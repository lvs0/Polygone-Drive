//! Polygone-Drive network layer using unified P2P infrastructure.
//!
//! This module provides Drive-specific networking on top of the shared
//! Polygone P2P layer, handling chunk storage and retrieval.

use polygone::{
    network::{
        P2pNode, P2pConfig, NetworkEvent, PolygoneRequest, PolygoneResponse,
        Capability, Multiaddr, PeerId,
    },
    protocol::SessionId,
    NodeId, Topology,
};
use libp2p::{kad, identify, request_response, SwarmBuilder, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use libp2p_swarm::NetworkBehaviour;

/// Drive-specific chunk request (legacy format for compatibility)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub file_id: [u8; 32],
    pub chunk_index: u32,
    pub fragment_index: u64,
    pub data: Option<Vec<u8>>, // If Some, it's an upload/store request
}

/// Drive-specific chunk response (legacy format)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkResponse {
    pub success: bool,
    pub payload: Vec<u8>,
}

/// Drive network node wrapping the unified P2P layer
pub struct DriveNetwork {
    /// The underlying P2P node
    p2p_node: P2pNode,
    /// Event receiver for network events
    event_rx: mpsc::Receiver<NetworkEvent>,
    /// Pending chunk requests
    pending_chunks: HashMap<ChunkKey, oneshot::Sender<ChunkResponse>>,
    /// Local storage reference (set externally)
    storage_path: std::path::PathBuf,
    /// Maximum cache size in GB
    max_cache_gb: usize,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ChunkKey {
    file_id: [u8; 32],
    chunk_index: u32,
    fragment_index: u64,
}

impl DriveNetwork {
    /// Create a new Drive network node
    pub async fn new(
        config: P2pConfig,
        storage_path: std::path::PathBuf,
        max_cache_gb: usize,
    ) -> anyhow::Result<Self> {
        let (p2p_node, event_rx) = P2pNode::new(config).await?;
        
        Ok(Self {
            p2p_node,
            event_rx,
            pending_chunks: HashMap::new(),
            storage_path,
            max_cache_gb,
        })
    }

    /// Get the local PeerId
    pub fn peer_id(&self) -> PeerId {
        self.p2p_node.peer_id()
    }

    /// Start listening and bootstrap to the network
    pub async fn start(&mut self, bootstrap_addrs: Vec<Multiaddr>) -> anyhow::Result<()> {
        // Start listening
        let addrs = self.p2p_node.start_listening().await?;
        info!("Drive node listening on: {:?}", addrs);

        // Subscribe to drive-specific topics
        self.p2p_node.subscribe_topic("polygone-drive")?;

        // Bootstrap to the network
        for addr in bootstrap_addrs {
            info!("Bootstrapping to: {}", addr);
        }
        self.p2p_node.bootstrap().await?;

        // Announce storage capability
        self.announce_capability().await?;

        Ok(())
    }

    /// Announce storage capability to the network
    async fn announce_capability(&mut self) -> anyhow::Result<()> {
        use polygone::network::GossipMessage;
        
        let message = GossipMessage::CapabilitiesAnnounce {
            peer_id: self.peer_id().to_bytes(),
            capabilities: vec![Capability::DriveStorage {
                max_gb: self.max_cache_gb as u32,
            }],
            ttl_seconds: 3600,
        };
        
        self.p2p_node.publish_gossip("polygone-drive", message)?;
        info!("Announced storage capability: {} GB", self.max_cache_gb);
        
        Ok(())
    }

    /// Request a chunk from the network
    pub async fn request_chunk(
        &mut self,
        file_id: [u8; 32],
        chunk_index: u32,
        fragment_index: u64,
        peer_id: PeerId,
    ) -> anyhow::Result<Vec<u8>> {
        let request = PolygoneRequest::DriveChunk {
            file_id,
            chunk_index,
            fragment_index: fragment_index as u8,
        };

        // Send request via P2P
        let response_rx = self.p2p_node.send_request(peer_id, request);
        
        // Wait for response
        match response_rx.await {
            Ok(PolygoneResponse::DriveChunk { success: true, data }) => Ok(data),
            Ok(PolygoneResponse::DriveChunk { success: false, .. }) => {
                Err(anyhow::anyhow!("Chunk not found on peer"))
            }
            Ok(_) => Err(anyhow::anyhow!("Unexpected response type")),
            Err(_) => Err(anyhow::anyhow!("Request timeout")),
        }
    }

    /// Store a chunk on a specific peer
    pub async fn store_chunk(
        &mut self,
        file_id: [u8; 32],
        chunk_index: u32,
        fragment_index: u64,
        data: Vec<u8>,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let request = PolygoneRequest::DriveStore {
            file_id,
            chunk_index,
            fragment_index: fragment_index as u8,
            data,
        };

        let response_rx = self.p2p_node.send_request(peer_id, request);
        
        match response_rx.await {
            Ok(PolygoneResponse::DriveStore { success: true }) => Ok(()),
            Ok(PolygoneResponse::DriveStore { success: false }) => {
                Err(anyhow::anyhow!("Store failed on peer"))
            }
            Ok(_) => Err(anyhow::anyhow!("Unexpected response type")),
            Err(_) => Err(anyhow::anyhow!("Request timeout")),
        }
    }

    /// Handle incoming network events
    pub async fn handle_events(&mut self) -> anyhow::Result<()> {
        while let Some(event) = self.event_rx.recv().await {
            match event {
                NetworkEvent::IncomingRequest { peer_id, request, channel } => {
                    self.handle_incoming_request(peer_id, request, channel).await?;
                }
                NetworkEvent::PeerConnected { peer_id } => {
                    info!("Peer connected: {}", peer_id);
                }
                NetworkEvent::PeerDisconnected { peer_id } => {
                    info!("Peer disconnected: {}", peer_id);
                }
                NetworkEvent::GossipReceived { topic, message, source } => {
                    debug!("Gossip on {} from {:?}: {:?}", topic, source, message);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Handle an incoming request from a peer
    async fn handle_incoming_request(
        &mut self,
        peer_id: PeerId,
        request: PolygoneRequest,
        channel: libp2p::request_response::ResponseChannel<PolygoneResponse>,
    ) -> anyhow::Result<()> {
        match request {
            PolygoneRequest::DriveChunk { file_id, chunk_index, fragment_index } => {
                // Try to read from local storage
                let fragment_path = self.storage_path.join(format!(
                    "{}_{}_{}.frag",
                    hex::encode(file_id),
                    chunk_index,
                    fragment_index
                ));
                
                let response = match tokio::fs::read(&fragment_path).await {
                    Ok(data) => PolygoneResponse::DriveChunk {
                        success: true,
                        data,
                    },
                    Err(_) => PolygoneResponse::DriveChunk {
                        success: false,
                        data: vec![],
                    },
                };
                
                self.p2p_node.send_response(channel, response)?;
                info!("Served chunk request from {}: {:?}", peer_id, fragment_path);
            }
            PolygoneRequest::DriveStore { file_id, chunk_index, fragment_index, data } => {
                // Store the chunk locally
                let fragment_path = self.storage_path.join(format!(
                    "{}_{}_{}.frag",
                    hex::encode(file_id),
                    chunk_index,
                    fragment_index
                ));
                
                let response = match tokio::fs::write(&fragment_path, &data).await {
                    Ok(_) => PolygoneResponse::DriveStore { success: true },
                    Err(e) => {
                        error!("Failed to store chunk: {}", e);
                        PolygoneResponse::DriveStore { success: false }
                    }
                };
                
                self.p2p_node.send_response(channel, response)?;
                info!("Stored chunk from {}: {:?}", peer_id, fragment_path);
            }
            _ => {
                // Not a Drive request
                warn!("Received non-Drive request from {}", peer_id);
            }
        }
        Ok(())
    }

    /// Run the network event loop
    pub async fn run(mut self) -> anyhow::Result<()> {
        info!("Drive network event loop started");
        
        // Spawn event handler
        let event_handler = tokio::spawn(async move {
            if let Err(e) = self.handle_events().await {
                error!("Event handler error: {}", e);
            }
        });

        // Run the underlying P2P node
        // Note: In a real implementation, we'd need to coordinate this better
        // For now, just keep the event handler running
        event_handler.await?;
        
        Ok(())
    }
}

/// Legacy compatibility: Build a standalone swarm (for migration period)
/// 
/// This function is deprecated. Use `DriveNetwork` instead.
pub fn build_swarm(keypair: libp2p::identity::Keypair) -> anyhow::Result<libp2p::Swarm<DriveBehaviour>> {
    use libp2p::kad::{Behaviour as Kademlia, Config as KademliaConfig, store::MemoryStore, Mode};
    use libp2p::swarm::NetworkBehaviour;
    
    let local_peer_id = libp2p::PeerId::from(keypair.public());
    
    let store = MemoryStore::new(local_peer_id);
    let mut kad_config = KademliaConfig::default();
    kad_config.set_protocol_names(vec![StreamProtocol::new("/pg-drive/kad/1.0.0")]);
    let mut kademlia = Kademlia::with_config(local_peer_id, store, kad_config);
    kademlia.set_mode(Some(Mode::Server));

    let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
        "/pg-drive/id/1.0.0".into(),
        keypair.public(),
    ));

    let protocols = [(libp2p::StreamProtocol::new("/pg-drive/rr/1.0.0"), request_response::ProtocolSupport::Full)];
    let request_response = request_response::cbor::Behaviour::new(protocols, request_response::Config::default());

    let behaviour = DriveBehaviour {
        kademlia,
        identify,
        request_response,
    };

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

/// Legacy Drive behaviour (for migration compatibility)
#[derive(NetworkBehaviour)]
pub struct DriveBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub request_response: request_response::cbor::Behaviour<ChunkRequest, ChunkResponse>,
}
