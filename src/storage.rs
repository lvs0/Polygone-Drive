use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// The "Treasure Map" file (.pgd) describing a stored file on the Polygone-Drive network.
#[derive(Debug, Serialize, Deserialize)]
pub struct DriveMap {
    /// Deterministic BLAKE3 hash of the original file
    pub file_id: [u8; 32],
    /// Original file name
    pub file_name: String,
    /// Total number of 1MB chunks
    pub num_chunks: u32,
    /// Bytes of the KemPublicKey identifying the owner
    pub owner_pk: Vec<u8>,
}

impl DriveMap {
    pub const EXTENSION: &'static str = ".pgd";
}

pub struct Chunker;

impl Chunker {
    pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB chunks
    
    /// Reads a file from disk asynchronously and chunks it.
    pub async fn stream_file<P: AsRef<Path>>(path: P) -> std::io::Result<impl tokio_stream::Stream<Item = std::io::Result<Vec<u8>>>> {
        let file = tokio::fs::File::open(path).await?;
        let stream = tokio_util::io::ReaderStream::with_capacity(file, Self::CHUNK_SIZE);
        Ok(stream.map(|res| res.map(|bytes| bytes.to_vec())))
    }
}

/// The local storage manager for a Relay Node.
pub struct RelayStore {
    cache_dir: PathBuf,
    pub max_size_bytes: u64,
}

impl RelayStore {
    pub fn new<P: AsRef<Path>>(dir: P, max_gb: usize) -> std::io::Result<Self> {
        let path = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            cache_dir: path,
            max_size_bytes: (max_gb as u64) * 1024 * 1024 * 1024,
        })
    }
    
    fn fragment_path(&self, file_id: &[u8; 32], chunk_idx: u32, fragment_idx: u64) -> PathBuf {
        let hex_id = hex::encode(file_id);
        self.cache_dir.join(format!("{}_{}_{}.frag", hex_id, chunk_idx, fragment_idx))
    }

    pub async fn store(&self, file_id: &[u8; 32], chunk_idx: u32, fragment_idx: u64, data: &[u8]) -> std::io::Result<()> {
        let path = self.fragment_path(file_id, chunk_idx, fragment_idx);
        tokio::fs::write(path, data).await
    }
    
    pub async fn retrieve(&self, file_id: &[u8; 32], chunk_idx: u32, fragment_idx: u64) -> std::io::Result<Vec<u8>> {
        let path = self.fragment_path(file_id, chunk_idx, fragment_idx);
        tokio::fs::read(path).await
    }
}
