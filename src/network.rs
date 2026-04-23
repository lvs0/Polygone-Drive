//! Polygone-Drive network layer.
//!
//! Provides Drive-specific networking using Kademlia DHT + request-response
//! for chunk storage and retrieval, with Shamir SSS-4-7 + AES-256-GCM encryption.

use libp2p::{
    identify, kad::{self, Behaviour as Kademlia, store::MemoryStore, Mode},
    request_response, SwarmBuilder, StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};
use libp2p_swarm::NetworkBehaviour;

// ── Drive request/response types ───────────────────────────────────────────────

/// Request sent to retrieve or store a specific fragment of a chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub file_id: [u8; 32],
    pub chunk_index: u32,
    pub fragment_index: u64,
    pub data: Option<Vec<u8>>, // If Some, it's a store request
}

/// Response containing the raw encrypted payload fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkResponse {
    pub success: bool,
    pub payload: Vec<u8>,
}

// ── Swarm builder ─────────────────────────────────────────────────────────────

/// Build a Drive swarm (Kademlia DHT + request-response).
pub fn build_swarm(
    keypair: libp2p::identity::Keypair,
) -> anyhow::Result<libp2p::Swarm<DriveBehaviour>> {
    use libp2p::kad::Config as KademliaConfig;
    use libp2p::SwarmBuilder;

    let local_peer_id = libp2p::PeerId::from(keypair.public());

    let store = MemoryStore::new(local_peer_id);
    let mut kad_config = KademliaConfig::default();
    kad_config.set_protocol_names(vec![StreamProtocol::new("/pg-drive/kad/1.0.0")]);
    let mut kademlia = Kademlia::with_config(local_peer_id, store, kad_config);
    kademlia.set_mode(Some(Mode::Server));

    let identify = libp2p::identify::Behaviour::new(
        libp2p::identify::Config::new("/pg-drive/id/1.0.0".into(), keypair.public()),
    );

    let protocols = [(
        libp2p::StreamProtocol::new("/pg-drive/rr/1.0.0"),
        request_response::ProtocolSupport::Full,
    )];
    let request_response =
        request_response::cbor::Behaviour::new(protocols, request_response::Config::default());

    let behaviour = DriveBehaviour {
        kademlia,
        identify,
        request_response,
    };

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(std::time::Duration::from_secs(60))
        })
        .build();

    Ok(swarm)
}

// ── Drive behaviour ───────────────────────────────────────────────────────────

/// Drive network behaviour: Kademlia DHT + request-response for chunks.
#[derive(NetworkBehaviour)]
pub struct DriveBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub request_response:
        request_response::cbor::Behaviour<ChunkRequest, ChunkResponse>,
}