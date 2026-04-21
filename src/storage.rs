use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use polygone::crypto::shamir::{self, Fragment};
use polygone::Result as PolygoneResult;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::RngCore;

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

/// Encrypted chunk with its encryption nonce and fragment metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Number of fragments generated
    pub num_fragments: u8,
    /// Threshold needed for reconstruction
    pub threshold: u8,
    /// Fragment IDs for this chunk (to locate them on the network)
    pub fragment_ids: Vec<u8>,
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

/// AES-256-GCM encryption wrapper.
pub struct AesEncryption;

impl AesEncryption {
    /// Generate a random 256-bit key.
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt data using AES-256-GCM.
    /// Returns (ciphertext, nonce).
    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 12]) {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_bytes: [u8; 12] = nonce.into();
        let ciphertext = cipher.encrypt(&nonce, data).expect("AES-GCM encryption failed");
        (ciphertext, nonce_bytes)
    }

    /// Decrypt data using AES-256-GCM.
    pub fn decrypt(ciphertext: &[u8], nonce: &[u8; 12], key: &[u8; 32]) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_slice = Nonce::from_slice(nonce);
        cipher.decrypt(nonce_slice, ciphertext).ok()
    }
}

/// Shamir Secret Sharing configuration for Polygone-Drive.
/// SSS-4-7: 7 fragments total, any 4 can reconstruct.
pub const SHAMIR_THRESHOLD: u8 = 4;
pub const SHAMIR_TOTAL: u8 = 7;

/// Split a chunk into Shamir fragments after AES encryption.
/// 
/// Flow: chunk → AES-256-GCM encrypt → Shamir SSS-4-7 split
/// Returns the fragments and metadata needed for reconstruction.
pub fn encrypt_and_fragment(
    chunk: &[u8],
    encryption_key: &[u8; 32],
) -> PolygoneResult<(Vec<Fragment>, [u8; 12])> {
    // Step 1: AES-256-GCM encrypt the chunk
    let (ciphertext, nonce) = AesEncryption::encrypt(chunk, encryption_key);
    
    // Step 2: Shamir SSS-4-7 split the ciphertext
    let fragments = shamir::split(&ciphertext, SHAMIR_THRESHOLD, SHAMIR_TOTAL)?;
    
    Ok((fragments, nonce))
}

/// Reconstruct a chunk from Shamir fragments and decrypt.
/// 
/// Flow: fragments → Shamir reconstruct → AES-256-GCM decrypt
pub fn reconstruct_and_decrypt(
    fragments: &[Fragment],
    nonce: &[u8; 12],
    encryption_key: &[u8; 32],
) -> PolygoneResult<Option<Vec<u8>>> {
    // Step 1: Shamir reconstruct the ciphertext (need at least threshold fragments)
    let ciphertext = shamir::reconstruct(fragments, SHAMIR_THRESHOLD)?;
    
    // Step 2: AES-256-GCM decrypt
    Ok(AesEncryption::decrypt(&ciphertext, nonce, encryption_key))
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

    /// Store encrypted and fragmented chunk.
    /// 
    /// Encrypts the chunk with AES-256-GCM, splits into Shamir SSS-4-7 fragments,
    /// and stores each fragment locally.
    pub async fn store_encrypted_chunk(
        &self,
        file_id: &[u8; 32],
        chunk_idx: u32,
        chunk_data: &[u8],
        encryption_key: &[u8; 32],
    ) -> PolygoneResult<EncryptedChunk> {
        // Encrypt and fragment
        let (fragments, nonce) = encrypt_and_fragment(chunk_data, encryption_key)?;
        
        // Store each fragment
        for fragment in &fragments {
            let fragment_data = bincode::serialize(fragment)
                .map_err(|e| polygone::PolygoneError::Serialization(e.to_string()))?;
            self.store(file_id, chunk_idx, fragment.id.0 as u64, &fragment_data).await
                .map_err(|e| polygone::PolygoneError::Io(e))?;
        }

        Ok(EncryptedChunk {
            nonce,
            num_fragments: fragments.len() as u8,
            threshold: SHAMIR_THRESHOLD,
            fragment_ids: fragments.iter().map(|f| f.id.0).collect(),
        })
    }

    /// Retrieve and reconstruct an encrypted chunk.
    /// 
    /// Fetches at least `threshold` fragments, reconstructs the ciphertext,
    /// and decrypts with AES-256-GCM.
    pub async fn retrieve_encrypted_chunk(
        &self,
        file_id: &[u8; 32],
        chunk_idx: u32,
        encrypted_chunk: &EncryptedChunk,
        encryption_key: &[u8; 32],
    ) -> PolygoneResult<Option<Vec<u8>>> {
        // Collect available fragments
        let mut fragments = Vec::new();
        
        for fragment_id in &encrypted_chunk.fragment_ids {
            if let Ok(data) = self.retrieve(file_id, chunk_idx, *fragment_id as u64).await {
                if let Ok(fragment) = bincode::deserialize::<Fragment>(&data) {
                    fragments.push(fragment);
                    // Stop once we have enough fragments
                    if fragments.len() >= encrypted_chunk.threshold as usize {
                        break;
                    }
                }
            }
        }

        // Check if we have enough fragments
        if fragments.len() < encrypted_chunk.threshold as usize {
            return Err(polygone::PolygoneError::ShamirError(
                format!("Only {} of {} fragments available", fragments.len(), encrypted_chunk.threshold)
            ));
        }

        // Reconstruct and decrypt
        reconstruct_and_decrypt(&fragments, &encrypted_chunk.nonce, encryption_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = AesEncryption::generate_key();
        let plaintext = b"Hello, Polygone!";
        
        let (ciphertext, nonce) = AesEncryption::encrypt(plaintext, &key);
        let decrypted = AesEncryption::decrypt(&ciphertext, &nonce, &key).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_and_fragment_roundtrip() {
        let key = AesEncryption::generate_key();
        let chunk = b"This is a test chunk for Polygone-Drive with Shamir SSS-4-7!";
        
        // Encrypt and fragment
        let (fragments, nonce) = encrypt_and_fragment(chunk, &key).unwrap();
        
        // Verify we got 7 fragments
        assert_eq!(fragments.len(), 7);
        
        // Test reconstruction with exactly 4 fragments (threshold)
        let subset: Vec<Fragment> = fragments.iter().take(4).cloned().collect();
        let decrypted = reconstruct_and_decrypt(&subset, &nonce, &key).unwrap().unwrap();
        
        assert_eq!(chunk.to_vec(), decrypted);
    }

    #[test]
    fn test_shamir_3_fragments_fails() {
        let key = AesEncryption::generate_key();
        let chunk = b"Test data for Shamir";
        
        let (fragments, nonce) = encrypt_and_fragment(chunk, &key).unwrap();
        
        // Try with only 3 fragments (should fail - below threshold)
        let subset: Vec<Fragment> = fragments.iter().take(3).cloned().collect();
        let result = reconstruct_and_decrypt(&subset, &nonce, &key);
        
        assert!(result.is_err() || result.unwrap().is_none());
    }
}
