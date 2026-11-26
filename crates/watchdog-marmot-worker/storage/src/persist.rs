//! Sealed account document.
//!
//! Plaintext is the MDK provider, including OpenMLS private state. ChaCha20-Poly1305
//! seals it before Durable Object storage. A wrong key or a truncated blob fails closed.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::state::SavedState;

pub const FORMAT_VERSION: u32 = 1;
const MAGIC: &[u8] = b"MWDO";
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("storage document is corrupt")]
    Corrupt,
    #[error("storage format {found} is not supported (latest {latest})")]
    Unsupported { found: u32, latest: u32 },
    #[error("storage capacity exhausted")]
    Capacity,
    #[error("storage export is not at a transaction boundary")]
    Busy,
    #[error("randomness failed")]
    Random,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Document {
    pub format: u32,
    pub state: SavedState,
}

pub fn seal(key: &[u8; 32], document: &Document) -> Result<Vec<u8>, PersistError> {
    let mut plain = serde_json::to_vec(document).map_err(|_| PersistError::Corrupt)?;
    if plain.len() > MAX_DOCUMENT_BYTES {
        plain.zeroize();
        return Err(PersistError::Capacity);
    }
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| PersistError::Random)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| PersistError::Corrupt)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: MAGIC,
            },
        )
        .map_err(|_| {
            plain.zeroize();
            PersistError::Corrupt
        })?;
    plain.zeroize();
    let mut out = Vec::with_capacity(4 + 1 + nonce.len() + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_sealed(key: &[u8; 32], bytes: &[u8]) -> Result<Document, PersistError> {
    if bytes.len() < 4 + 1 + 12 + 16 || &bytes[..4] != MAGIC {
        return Err(PersistError::Corrupt);
    }
    let version = u32::from(bytes[4]);
    if version != FORMAT_VERSION {
        return Err(PersistError::Unsupported {
            found: version,
            latest: FORMAT_VERSION,
        });
    }
    let nonce = &bytes[5..17];
    let ciphertext = &bytes[17..];
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| PersistError::Corrupt)?;
    let mut plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .map_err(|_| PersistError::Corrupt)?;
    let document = serde_json::from_slice::<Document>(&plain).map_err(|_| PersistError::Corrupt);
    plain.zeroize();
    let document = document?;
    if document.format != FORMAT_VERSION {
        return Err(PersistError::Unsupported {
            found: document.format,
            latest: FORMAT_VERSION,
        });
    }
    Ok(document)
}
