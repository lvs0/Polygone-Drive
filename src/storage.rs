use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The "Treasure Map" file (.pgd) describing a stored file on the Polygone-Drive network.
#[derive(Debug, Serialize, Deserialize)]
pub struct DriveMap {
    /// Deterministic BLAKE3 hash of the original file
    pub file_id: [u8; 32],
    /// Original file name
    pub file_name: String,
    /// Total number of 1MB chunks
    pub num_chunks: u32,
    /// Owner public key bytes
    pub owner_pk: Vec<u8>,
    /// Number of fragments per chunk (for verification)
    pub fragments_per_chunk: u8,
}

/// Encrypted fragment stored on the network.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedFragment {
    pub chunk_index: u32,
    pub fragment_index: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Threshold parameters for Shamir SSS.
pub const SHAMIR_THRESHOLD: u8 = 4;
pub const SHAMIR_N_FRAGMENTS: u8 = 7;

/// AES-256-GCM key with zeroization on drop.
#[derive(ZeroizeOnDrop, Zeroize)]
pub struct DriveKey([u8; 32]);

impl DriveKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        use aes_gcm::{
            Aes256Gcm, Key, Nonce,
            aead::{Aead, AeadCore, KeyInit, OsRng},
        };
        let key = Key::<Aes256Gcm>::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext).expect("AES-GCM encrypt");
        (ciphertext, nonce.into())
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, ()> {
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
        let key = Key::<Aes256Gcm>::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).map_err(|_| ())
    }
}

// ── Chunker ───────────────────────────────────────────────────────────────────

pub struct Chunker;

impl Chunker {
    pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

    pub async fn stream_file<P: AsRef<Path>>(
        path: P,
    ) -> std::io::Result<impl tokio_stream::Stream<Item = std::io::Result<Vec<u8>>>> {
        let file = tokio::fs::File::open(path).await?;
        let stream =
            tokio_util::io::ReaderStream::with_capacity(file, Self::CHUNK_SIZE);
        use tokio_stream::StreamExt;
        Ok(stream.map(|res| res.map(|bytes| bytes.to_vec())))
    }
}

// ── Storage ───────────────────────────────────────────────────────────────────

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

    fn fragment_path(
        &self,
        file_id: &[u8; 32],
        chunk_idx: u32,
        frag_idx: u8,
    ) -> PathBuf {
        let hex_id = hex::encode(file_id);
        self.cache_dir
            .join(format!("{}_{}_{}.efrag", hex_id, chunk_idx, frag_idx))
    }

    pub async fn store(
        &self,
        file_id: &[u8; 32],
        chunk_idx: u32,
        frag_idx: u8,
        data: &[u8],
    ) -> std::io::Result<()> {
        let path = self.fragment_path(file_id, chunk_idx, frag_idx);
        tokio::fs::write(path, data).await
    }

    pub async fn retrieve(
        &self,
        file_id: &[u8; 32],
        chunk_idx: u32,
        frag_idx: u8,
    ) -> std::io::Result<Vec<u8>> {
        let path = self.fragment_path(file_id, chunk_idx, frag_idx);
        tokio::fs::read(path).await
    }
}

// ── DriveMap I/O ─────────────────────────────────────────────────────────────

impl DriveMap {
    pub const EXTENSION: &'static str = ".pgd";

    /// Save the DriveMap to disk.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let bytes =
            bincode::serialize(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, bytes)
    }

    /// Load a DriveMap from disk.
    pub fn load<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        bincode::deserialize(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

// ── EncryptedFragment I/O ───────────────────────────────────────────────────

impl EncryptedFragment {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serializable")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}