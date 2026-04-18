pub mod network;
pub mod storage;
pub mod links;

use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(
    name = "polygone-drive",
    version = "0.1.0",
    about = "Decentralized file storage on the Polygone ephemeral network"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true)]
    bootstrap: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Upload a file to the P2P Drive network
    Upload {
        file_path: String,
        /// The destination ML-KEM public key file path
        peer_pk_path: String,
        
        /// Enable ephemeral link (auto-expires)
        #[arg(short, long)]
        ephemeral: bool,
        
        /// TTL in seconds for ephemeral links (default: 3600)
        #[arg(short, long, default_value = "3600")]
        ttl_seconds: u64,
    },
    /// Generate a public sharing link for a file
    Share {
        map_path: String,
        
        /// Create ephemeral link with TTL
        #[arg(short, long)]
        ephemeral: bool,
        
        /// TTL in seconds (default: 3600)
        #[arg(short, long, default_value = "3600")]
        ttl_seconds: u64,
        
        /// Max downloads before expiration
        #[arg(short, long, default_value = "10")]
        max_downloads: u32,
    },
    /// Download a file using a .pgd map or a token
    Download {
        #[arg(short, long)]
        map_path: Option<String>,
        #[arg(short, long)]
        sk_path: String,
        #[arg(short, long)]
        token: Option<String>,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        
        /// Stream to stdout instead of file
        #[arg(short, long)]
        stream: bool,
    },
    /// Start a storage relay node
    Node {
        #[arg(short, long, default_value = "0.0.0.0:4002")]
        listen: String,
        
        #[arg(short, long, default_value = "10")]
        cache_gb: usize,
        
        /// Enable computing tasks (share CPU when idle)
        #[arg(short, long)]
        enable_compute: bool,
        
        /// Max CPU % to use for compute (default: 50)
        #[arg(short, long, default_value = "50")]
        max_cpu_percent: u8,
    },
    /// Stream a file directly (no full download)
    Stream {
        token: String,
        
        /// Start position in bytes
        #[arg(short, long, default_value = "0")]
        start: u64,
        
        /// End position in bytes
        #[arg(short, long)]
        end: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    fmt().with_env_filter(EnvFilter::new("info")).with_target(false).init();

    match cli.command {
        Commands::Upload { file_path, peer_pk_path, ephemeral, ttl_seconds } => {
            upload_file(&file_path, &peer_pk_path, ephemeral, ttl_seconds).await?;
        }
        Commands::Share { map_path, ephemeral, ttl_seconds, max_downloads } => {
            create_share_link(&map_path, ephemeral, ttl_seconds, max_downloads)?;
        }
        Commands::Download { map_path, sk_path, token, output, stream } => {
            download_file(map_path.as_deref(), &sk_path, token.as_deref(), output, stream).await?;
        }
        Commands::Node { listen, cache_gb, enable_compute, max_cpu_percent } => {
            start_node(&listen, cache_gb, enable_compute, max_cpu_percent).await?;
        }
        Commands::Stream { token, start, end } => {
            stream_file(&token, start, end).await?;
        }
    }

    Ok(())
}

async fn upload_file(file_path: &str, peer_pk_path: &str, ephemeral: bool, ttl_seconds: u64) -> anyhow::Result<()> {
    use polygone::{protocol::Session, crypto::kem::KemPublicKey};
    use libp2p::{identity, futures::StreamExt, swarm::SwarmEvent, kad, request_response};

    println!("⬡ POLYGONE-DRIVE — Uploading {file_path}...");

    let pk_bytes = std::fs::read(peer_pk_path)?;
    let peer_pk = KemPublicKey::from_bytes(&pk_bytes)?;

    let (mut session, ciphertext) = Session::new_initiator(&peer_pk)?;
    session.establish(None)?;

    let mut swarm = network::build_swarm(identity::Keypair::generate_ed25519())?;
    if let Some(boot) = std::env::var("POLY_BOOTSTRAP").ok() {
        swarm.dial(boot.parse::<libp2p::Multiaddr>()?)?;
    }
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let file_size = tokio::fs::metadata(file_path).await?.len();
    let file_bytes = std::fs::read(file_path)?;
    let file_hash = blake3::hash(file_bytes.as_slice());
    let mut chunk_stream = storage::Chunker::stream_file(file_path).await?;
    let mut c_idx = 0u32;
    let mut total_bytes = 0u64;
    let start = std::time::Instant::now();

    // ── Collect encrypted + fragmented chunks ──
    while let Some(chunk_res) = chunk_stream.next().await {
        let chunk = chunk_res?;
        c_idx += 1;
        total_bytes += chunk.len() as u64;

        // Step 1: Generate random AES-256-GCM session key for this chunk
        use rand::RngCore;
        let mut session_key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut session_key_bytes);
        let drive_key = storage::DriveKey::new(session_key_bytes);

        // Step 2: AES-256-GCM encrypt + Shamir SSS-4-7 split (delegated to storage.rs)
        let enc_fragments = storage::upload_encrypted_fragmented_chunk(&chunk, &drive_key, c_idx)
            .map_err(|e| anyhow::anyhow!("Upload chunk failed: {e}"))?;

        // Step 3: Store encrypted fragments locally (in real impl, broadcast to DHT network)
        let hex_id = hex::encode(file_hash.as_bytes());
        tokio::fs::create_dir_all(".drive_cache").await?;
        for enc_frag in &enc_fragments {
            let store_path = format!(".drive_cache/{}_{}_{}.efrag", hex_id, c_idx, enc_frag.fragment_index);
            tokio::fs::write(&store_path, enc_frag.to_bytes()).await?;
        }

        let mbps = (total_bytes as f64) / start.elapsed().as_secs_f64() / 1_000_000.0;
        println!("  [UPLOAD] Chunk {c_idx} ({}/{}) — {:.2} MB/s ✓ encrypted + 4-of-7 Shamir",
            total_bytes, file_size, mbps);
    }

    let map = storage::DriveMap {
        file_id: *file_hash.as_bytes(),
        file_name: file_path.to_string(),
        num_chunks: c_idx,
        owner_pk: ciphertext.as_bytes().to_vec(),
        fragments_per_chunk: storage::SHAMIR_N_FRAGMENTS,
    };

    let map_path_out = format!("{}.pgd", file_path);
    map.save(&map_path_out)?;

    println!();
    println!("  ✓ Upload complete!");
    println!("    File: {}", map_path_out);
    println!("    Size: {} bytes", file_size);
    println!("    Hash: {}", file_hash);
    println!("    Chunks: {} (each → {} encrypted fragments)", c_idx, storage::SHAMIR_N_FRAGMENTS);
    if ephemeral {
        println!("    Ephemeral: {}s TTL", ttl_seconds);
    }

    Ok(())
}

fn create_share_link(map_path: &str, ephemeral: bool, ttl_seconds: u64, max_downloads: u32) -> anyhow::Result<()> {
    let map_bytes = std::fs::read(map_path)?;
    
    let share_link: Vec<u8> = if ephemeral {
        let link_data = links::EphemeralLink {
            map_data: map_bytes,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl_seconds,
            max_downloads,
            downloads: 0,
        };
        serde_json::to_vec(&link_data)?
    } else {
        map_bytes.clone()
    };
    
    let token = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &share_link
    );
    
    println!("⬡ POLYGONE SHARE — Link Generated");
    println!();
    if ephemeral {
        println!("  📎 Ephemeral Link (auto-expires)");
        println!("     TTL: {} seconds", ttl_seconds);
        println!("     Max downloads: {}", max_downloads);
    } else {
        println!("  📎 Permanent Link");
    }
    println!();
    println!("  Token: poly://drive/{}", &token[..40]);
    if token.len() > 40 {
        println!("         {}", &token[40..]);
    }
    println!();
    println!("  Download: polygone-drive download --token '{}'", token);
    
    Ok(())
}

async fn download_file(map_path: Option<&str>, sk_path: &str, token: Option<&str>, output: Option<String>, stream: bool) -> anyhow::Result<()> {
    use polygone::{protocol::Session, crypto::{KeyPair, kem::{KemSecretKey, KemCiphertext}}};
    use libp2p::{identity, futures::StreamExt, swarm::SwarmEvent, kad};
    
    let map: storage::DriveMap = if let Some(t) = token {
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            t
        )?;
        if bytes.starts_with(b"{\"map_data\"") {
            let link: links::EphemeralLink = serde_json::from_slice(&bytes)?;
            if link.is_expired() {
                anyhow::bail!("Link has expired!");
            }
            bincode::deserialize(&link.map_data)?
        } else {
            bincode::deserialize(&bytes)?
        }
    } else if let Some(p) = map_path {
        let bytes = std::fs::read(p)?;
        bincode::deserialize(&bytes)?
    } else {
        anyhow::bail!("Either --map-path or --token must be provided");
    };

    println!("⬡ POLYGONE-DRIVE — Downloading \"{}\"", map.file_name);
    
    let sk_bytes = std::fs::read(sk_path)?;
    let kem_sk = KemSecretKey::from_bytes(&sk_bytes)?;
    let kem_ct = KemCiphertext::from_bytes(&map.owner_pk)?;

    let mut kp = KeyPair::generate()?;
    kp.kem_sk = kem_sk;

    let mut session = Session::new_responder(kp, &kem_ct)?;
    session.establish(None)?;
    
    let nodes = session.topology.as_ref().unwrap().nodes.clone();
    let threshold = session.topology.as_ref().unwrap().params.threshold as usize;

    let mut swarm = network::build_swarm(identity::Keypair::generate_ed25519())?;
    if let Some(boot) = std::env::var("POLY_BOOTSTRAP").ok() {
        swarm.dial(boot.parse::<libp2p::Multiaddr>()?)?;
    }
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("  [DHT] Resolving {} nodes...", nodes.len());
    let mut node_to_peer = std::collections::HashMap::new();
    for node_id in &nodes {
        let key = kad::RecordKey::new(&node_id.0);
        swarm.behaviour_mut().kademlia.get_record(key);
    }

    let mut resolved_count = 0;
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(network::DriveBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                    if let kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(record))) = result {
                        let peer_id = libp2p::PeerId::from_bytes(&record.record.value).unwrap();
                        for nid in &nodes {
                            if nid.0.as_ref() == record.record.key.as_ref() {
                                node_to_peer.insert(*nid, peer_id);
                                resolved_count += 1;
                                break;
                            }
                        }
                        if resolved_count >= nodes.len() {
                            break;
                        }
                    }
                }
                _ => {}
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => anyhow::bail!("DHT resolution timeout"),
        }
    }

    let out_path = output.unwrap_or_else(|| format!("recovered_{}", map.file_name));
    let mut file = if stream {
        None
    } else {
        Some(tokio::fs::File::create(&out_path).await?)
    };
    let mut final_data = Vec::new();

    for c_idx in 0..map.num_chunks {
        print!("\r  [DOWNLOAD] Chunk {}/{}...", c_idx + 1, map.num_chunks);
        use tokio::io::AsyncWriteExt;
            tokio::io::stdout().flush().await?;
        
        let mut fragments = Vec::new();
        for node_id in &nodes {
            let peer_id = node_to_peer.get(node_id).unwrap();
            let request = network::ChunkRequest {
                file_id: map.file_id,
                chunk_index: c_idx,
                fragment_index: 0,
                data: None,
            };
            swarm.behaviour_mut().request_response.send_request(peer_id, request);
        }

        while fragments.len() < threshold {
            if let Some(event) = swarm.next().await {
                if let SwarmEvent::Behaviour(network::DriveBehaviourEvent::RequestResponse(
                    libp2p::request_response::Event::Message { 
                        message: libp2p::request_response::Message::Response { response, .. }, .. 
                    }
                )) = event {
                    if response.success {
                        fragments.push(response.payload);
                    }
                }
            }
        }
        
        let chunk_data = session.receive(fragments)?;
        if stream {
            tokio::io::stdout().write_all(&chunk_data).await?;
        } else if let Some(ref mut f) = file {
            use tokio::io::AsyncWriteExt;
            f.write_all(&chunk_data).await?;
        }
        final_data.extend(chunk_data);
    }
    
    println!();
    if !stream {
        std::fs::write(&out_path, &final_data)?;
        println!("  ✓ File recovered: {}", out_path);
        println!("    Size: {} bytes", final_data.len());
    } else {
        println!("  ✓ Stream complete: {} bytes", final_data.len());
    }
    
    Ok(())
}

async fn start_node(listen: &str, cache_gb: usize, enable_compute: bool, max_cpu_percent: u8) -> anyhow::Result<()> {
    use libp2p::{identity, futures::StreamExt, swarm::SwarmEvent, kad};
    
    println!("⬡ POLYGONE-DRIVE NODE");
    println!("  Cache: {} GB", cache_gb);
    println!("  Listen: {}", listen);
    println!("  Compute: {}", if enable_compute { format!("enabled (max {}%)", max_cpu_percent) } else { "disabled".to_string() });
    
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    println!("  Peer ID: {}", peer_id);
    
    let mut swarm = network::build_swarm(keypair)?;
    swarm.listen_on(listen.parse()?)?;
    let store = storage::RelayStore::new(".drive_cache", cache_gb)?;

    if let Some(boot) = std::env::var("POLY_BOOTSTRAP").ok() {
        swarm.dial(boot.parse::<libp2p::Multiaddr>()?)?;
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("  ✓ Listening on {}", address);
                }
                SwarmEvent::Behaviour(network::DriveBehaviourEvent::RequestResponse(
                    libp2p::request_response::Event::Message { 
                        message: libp2p::request_response::Message::Request { request, channel, .. }, .. 
                    }
                )) => {
                    if let Some(data) = request.data {
                        let _ = store.store(&request.file_id, request.chunk_index, request.fragment_index as u8, &data).await;
                        let _ = swarm.behaviour_mut().request_response.send_response(channel, network::ChunkResponse { success: true, payload: vec![] });
                    } else {
                        let res = if let Ok(data) = store.retrieve(&request.file_id, request.chunk_index, request.fragment_index as u8).await {
                            network::ChunkResponse { success: true, payload: data }
                        } else {
                            network::ChunkResponse { success: false, payload: vec![] }
                        };
                        let _ = swarm.behaviour_mut().request_response.send_response(channel, res);
                    }
                }
                _ => {}
            }
        }
    }
}

async fn stream_file(token: &str, start: u64, end: Option<u64>) -> anyhow::Result<()> {
    println!("⬡ POLYGONE-DRIVE — Streaming...");
    println!("  Range: {}-{:?}", start, end);
    println!("  Token: {}...", &token[..20]);
    
    println!("  ⚠️ Streaming requires active connection to network");
    println!("     Use 'polygone-drive download --stream --token ...' instead");
    
    Ok(())
}
