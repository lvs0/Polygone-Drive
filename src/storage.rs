use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Shamir SSS-4-7 + AES encrypt on upload chunks ────────────────────────────

use sharks::{Sharks, Share};
use rand::rngs::OsRng;

/// A unique fragment identifier [1..=n].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FragmentId(pub u8);

/// A single Shamir fragment wrapping a share.
#[derive(Clone, Serialize, Deserialize)]
pub struct ShamirFragment {
    pub id: FragmentId,
    pub data: Vec<u8>,
}

/// Split `secret` into 7 fragments (threshold 4) using Shamir SSS.
/// Any 4 fragments reconstruct the secret; fewer reveal nothing.
pub fn shamir_split(secret: &[u8]) -> Result<Vec<ShamirFragment>, String> {
    const THRESHOLD: u8 = 4;
    const N: u8 = 7;
    if secret.is_empty() {
        return Err("Cannot split empty secret".into());
    }
    let sharks = Sharks(THRESHOLD);
    let dealer = sharks.dealer_rng(secret, &mut OsRng);
    let fragments: Vec<ShamirFragment> = dealer
        .take(N as usize)
        .enumerate()
        .map(|(i, share)| ShamirFragment {
            id: FragmentId(i as u8 + 1),
            data: Vec::from(&share),
        })
        .collect();
    Ok(fragments)
}

/// Reconstruct a secret from at least 4 Shamir fragments.
pub fn shamir_reconstruct(fragments: &[ShamirFragment], threshold: u8) -> Result<Vec<u8>, String> {
    if fragments.len() < threshold as usize {
        return Err(format!("need {} fragments, got {}", threshold, fragments.len()));
    }
    let sharks = Sharks(threshold);
    let shares: Result<Vec<Share>, _> = fragments
        .iter()
        .map(|f| Share::try_from(f.data.as_slice()).map_err(|e| e.to_string()))
        .collect();
    let secret = sharks
        .recover(shares?.iter())
        .map_err(|e| e.to_string())?;
    Ok(secret)
}

/// Upload a single chunk: AES-256-GCM encrypt, then Shamir SSS-4-7 split.
///
/// Returns one `EncryptedFragment` per Shamir share (7 total).
///
/// # Arguments
/// * `chunk`        – raw 1 MB chunk bytes
/// * `drive_key`    – AES-256-GCM session key for this chunk
/// * `chunk_index`  – ordinal index of this chunk in the file
///
/// # Example
/// ```ignore
/// let frags = upload_encrypted_fragmented_chunk(&chunk, &drive_key, 0)?;
/// // → 7 EncryptedFragments ready to broadcast to DHT nodes
/// ```
pub fn upload_encrypted_fragmented_chunk(
    chunk: &[u8],
    drive_key: &DriveKey,
    chunk_index: u32,
) -> Result<Vec<EncryptedFragment>, String> {
    // Step 1: AES-256-GCM encrypt
    let (ciphertext, nonce) = drive_key.encrypt(chunk);

    // Step 2: Shamir SSS-4-7 split the encrypted payload
    let fragments = shamir_split(&ciphertext)?;

    // Step 3: Wrap as EncryptedFragments
    let enc_fragments: Vec<EncryptedFragment> = fragments
        .into_iter()
        .map(|frag| EncryptedFragment {
            chunk_index,
            fragment_index: frag.id.0,
            nonce,
            ciphertext: frag.data,
        })
        .collect();

    Ok(enc_fragments)
}

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