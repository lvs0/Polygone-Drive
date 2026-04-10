pub mod network;
pub mod storage;

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
    },
    /// Download a file using a .pgd map and your secret key
    Download {
        /// The map file (.pgd) describing the asset
        map_path: String,
        /// Your secret KEM key
        sk_path: String,
    },
    /// Start a storage relay node
    Node {
        #[arg(short, long, default_value = "0.0.0.0:4002")]
        listen: String,
        
        /// Maximum cache size allocated in Gigabytes
        #[arg(short, long, default_value = "10")]
        cache_gb: usize,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    fmt().with_env_filter(EnvFilter::new("info")).with_target(false).init();

    match cli.command {
        Commands::Upload { file_path, peer_pk_path } => {
            use polygone::{protocol::Session, crypto::kem::KemPublicKey};
            use libp2p::{identity, futures::StreamExt, swarm::SwarmEvent, kad, request_response};

            println!("⬡ POLYGONE-DRIVE — Uploading {file_path}...");

            // 1. Load recipient public key
            let pk_bytes = std::fs::read(&peer_pk_path)?;
            let peer_pk = KemPublicKey::from_bytes(&pk_bytes)?;

            // 2. Initialize Session
            let (mut session, ciphertext) = Session::new_initiator(&peer_pk)?;
            session.establish(None)?;
            println!("  [ALICE] Session established. Ephemeral topology derived.");

            // 3. Setup P2P
            let mut swarm = network::build_swarm(identity::Keypair::generate_ed25519())?;
            if let Some(boot) = cli.bootstrap {
                swarm.dial(boot.parse::<libp2p::Multiaddr>()?)?;
            }
            swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

            // 4. Discover peers and assign to NodeIds
            println!("  [ALICE] Discovering storage relays...");
            let mut discovery_query = None;
            let relay_key = kad::RecordKey::new(b"pg-drive-relays");
            
            // Wait for some peers (simplified: wait 5s or until some connection)
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            
            let nodes = session.topology.as_ref().unwrap().nodes.clone();
            let mut node_to_peer = std::collections::HashMap::new();
            
            // For this demo/v1, we pick peers from the routing table
            let mut available_peers: Vec<_> = swarm.behaviour().kademlia.kbuckets()
                .flat_map(|k| k.iter())
                .map(|e| e.node.key.preimage().clone())
                .collect();
            
            if available_peers.len() < nodes.len() {
                println!("  [WARNING] Not enough unique relays found ({}/{}). Reusing peers.", available_peers.len(), nodes.len());
                if available_peers.is_empty() {
                    anyhow::bail!("No peers found in network. Cannot upload.");
                }
                while available_peers.len() < nodes.len() {
                    let p = available_peers[0];
                    available_peers.push(p);
                }
            }

            for (i, node_id) in nodes.iter().enumerate() {
                let peer_id = available_peers[i];
                node_to_peer.insert(*node_id, peer_id);
                // Announce mapping in DHT (NodeId -> PeerId)
                let key = kad::RecordKey::new(node_id.as_bytes());
                swarm.behaviour_mut().kademlia.put_record(
                    kad::Record { key, value: peer_id.to_bytes(), publisher: None, expires: None },
                    kad::Quorum::One
                )?;
            }

            // 5. Encrypt, Fragment, and Upload Chunks
            let file_data = std::fs::read(&file_path)?;
            let chunks = storage::Chunker::chunk_file(&file_path)?;
            let mut file_id = [0u8; 32];
            blake3::Hasher::new().update(&file_data).finalize().as_bytes().copy_from_slice(&file_id);

            for (c_idx, chunk) in chunks.iter().enumerate() {
                println!("  [ALICE] Processing chunk {}/{}...", c_idx + 1, chunks.len());
                let assignments = session.send(chunk)?;
                
                for (node_id, frag_bytes) in assignments {
                    let peer_id = node_to_peer.get(&node_id).unwrap();
                    let request = network::ChunkRequest {
                        file_id,
                        chunk_index: c_idx as u32,
                        fragment_index: 0, // In this simplified split, assignment handles it
                        data: Some(frag_bytes),
                    };
                    swarm.behaviour_mut().request_response.send_request(peer_id, request);
                }
            }

            // 6. Save Map
            let map = storage::DriveMap {
                file_id,
                file_name: file_path.clone(),
                num_chunks: chunks.len() as u32,
                owner_pk: ciphertext.as_bytes().to_vec(),
            };
            let map_path = format!("{}{}", file_path, storage::DriveMap::EXTENSION);
            std::fs::write(&map_path, bincode::serialize(&map)?)?;
            println!("  ✓ Upload complete! Map saved to: {}", map_path);
            
            // Give some time for DHT propagation
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        Commands::Download { map_path, sk_path } => {
            use polygone::{protocol::Session, crypto::{KeyPair, kem::{KemSecretKey, KemCiphertext}}};
            use libp2p::{identity, futures::StreamExt, swarm::SwarmEvent, kad};

            println!("⬡ POLYGONE-DRIVE — Downloading from {map_path}...");
            
            let map_bytes = std::fs::read(&map_path)?;
            let map: storage::DriveMap = bincode::deserialize(&map_bytes)?;
            
            let sk_bytes = std::fs::read(&sk_path)?;
            let kem_sk = KemSecretKey::from_bytes(&sk_bytes)?;
            let kem_ct = KemCiphertext::from_bytes(&map.owner_pk)?;

            let mut kp = KeyPair::generate()?;
            kp.kem_sk = kem_sk;

            let mut session = Session::new_responder(kp, &kem_ct)?;
            session.establish(None)?;
            
            let nodes = session.topology.as_ref().unwrap().nodes.clone();
            let threshold = session.topology.as_ref().unwrap().params.threshold as usize;

            let mut swarm = network::build_swarm(identity::Keypair::generate_ed25519())?;
            if let Some(boot) = cli.bootstrap {
                swarm.dial(boot.parse::<libp2p::Multiaddr>()?)?;
            }
            swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

            // 1. Resolve NodeIds -> PeerIds via DHT
            println!("  [BOB] Resolving topology via DHT...");
            let mut node_to_peer = std::collections::HashMap::new();
            for node_id in &nodes {
                let key = kad::RecordKey::new(node_id.as_bytes());
                swarm.behaviour_mut().kademlia.get_record(key);
            }

            let mut resolved_count = 0;
            let mut final_data = Vec::new();

            loop {
                tokio::select! {
                    event = swarm.select_next_some() => match event {
                        SwarmEvent::Behaviour(network::DriveBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                            if let kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(record))) = result {
                                let peer_id = libp2p::PeerId::from_bytes(&record.record.value).unwrap();
                                let node_id = polygone::NodeId::derive(&[0;32], 0); // Fake derived to get type right for lookup
                                // We find which NodeId this record corresponds to by checking key
                                for nid in &nodes {
                                    if nid.as_bytes() == record.record.key.as_ref() {
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

            // 2. Download chunks
            for c_idx in 0..map.num_chunks {
                println!("  [BOB] Downloading chunk {}/{}...", c_idx + 1, map.num_chunks);
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
                        if let SwarmEvent::Behaviour(network::DriveBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { message: libp2p::request_response::Message::Response { response, .. }, .. })) = event {
                            if response.success {
                                fragments.push(response.payload);
                            }
                        }
                    }
                }
                
                let chunk_data = session.receive(fragments)?;
                final_data.extend(chunk_data);
            }

            let out_path = format!("recovered_{}", map.file_name);
            std::fs::write(&out_path, final_data)?;
            println!("  ✓ File recovered: {}", out_path);
        }
        Commands::Node { listen, cache_gb } => {
            use libp2p::{identity, futures::StreamExt, swarm::SwarmEvent, kad};
            
            println!("⬡ POLYGONE-DRIVE NODE");
            println!("  Allocated Cache : {cache_gb} GB");
            println!("  Listening on    : {listen}");
            
            let keypair = identity::Keypair::generate_ed25519();
            let mut swarm = network::build_swarm(keypair)?;
            swarm.listen_on(listen.parse()?)?;
            let store = storage::RelayStore::new(".drive_cache", cache_gb)?;

            if let Some(boot) = cli.bootstrap {
                swarm.dial(boot.parse::<libp2p::Multiaddr>()?)?;
            }

            loop {
                tokio::select! {
                    event = swarm.select_next_some() => match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("  ✓ Node participating on {address}");
                        }
                        SwarmEvent::Behaviour(network::DriveBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { message: libp2p::request_response::Message::Request { request, channel, .. }, .. })) => {
                            if let Some(data) = request.data {
                                // Upload/Store request
                                let _ = store.store(&request.file_id, request.chunk_index, request.fragment_index, &data).await;
                                let _ = swarm.behaviour_mut().request_response.send_response(channel, network::ChunkResponse { success: true, payload: vec![] });
                            } else {
                                // Download/Retrieve request
                                let res = if let Ok(data) = store.retrieve(&request.file_id, request.chunk_index, request.fragment_index).await {
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
    }

    Ok(())
}
