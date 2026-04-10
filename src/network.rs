use libp2p::{
    identify, kad::{self, Behaviour as Kademlia, Config as KademliaConfig}, request_response, swarm::NetworkBehaviour, StreamProtocol
};
use serde::{Deserialize, Serialize};

/// Request sent to retrieve a specific fragment of a chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub file_id: [u8; 32],
    pub chunk_index: u32,
    pub fragment_index: u64,
    pub data: Option<Vec<u8>>, // If Some, it's an upload/store request
}

/// Response containing the raw encrypted payload fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkResponse {
    pub success: bool,
    pub payload: Vec<u8>,
}

#[derive(NetworkBehaviour)]
pub struct DriveBehaviour {
    pub kademlia: Kademlia<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub request_response: request_response::cbor::Behaviour<ChunkRequest, ChunkResponse>,
}

pub fn build_swarm(keypair: libp2p::identity::Keypair) -> anyhow::Result<libp2p::Swarm<DriveBehaviour>> {
    let local_peer_id = libp2p::PeerId::from(keypair.public());
    
    let store = kad::store::MemoryStore::new(local_peer_id);
    let mut kad_config = KademliaConfig::default();
    kad_config.set_protocol_names(vec![StreamProtocol::new("/pg-drive/kad/1.0.0")]);
    let mut kademlia = Kademlia::with_config(local_peer_id, store, kad_config);
    kademlia.set_mode(Some(kad::Mode::Server));

    let identify = identify::Behaviour::new(identify::Config::new(
        "/pg-drive/id/1.0.0".into(),
        keypair.public(),
    ));

    let protocols = [(StreamProtocol::new("/pg-drive/rr/1.0.0"), request_response::ProtocolSupport::Full)];
    let cfg = request_response::Config::default();
    let request_response = request_response::cbor::Behaviour::new(protocols, cfg);

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
