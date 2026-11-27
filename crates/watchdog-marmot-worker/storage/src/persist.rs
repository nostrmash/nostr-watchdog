//! Sealed account document.
//!
//! Plaintext is the MDK provider, including OpenMLS private state. ChaCha20-Poly1305
//! seals it before Durable Object storage. A wrong key or a truncated blob fails closed.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::state::SavedState;

pub const FORMAT_VERSION: u32 = 2;
pub const KEY_VERSION: u8 = 1;
const MAGIC: &[u8] = b"MWDO";
pub const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const HEADER: usize = 4 + 1 + 1 + 12;

/// Binds a snapshot to one project Durable Object and one account.
///
/// The associated data is authenticated by ChaCha20-Poly1305. A snapshot sealed
/// for another project or account does not decrypt. Restoring an older backup
/// of both the ciphertext and this binding together is still a rollback; the
/// Durable Object revision compare-and-swap is what rejects a losing writer.
#[derive(Clone, Copy)]
pub struct SealBinding<'a> {
    pub project_id: &'a str,
    pub account_hex: &'a str,
}

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
    pub(crate) state: SavedState,
}

pub fn seal(
    key: &[u8; 32],
    binding: SealBinding<'_>,
    document: &Document,
) -> Result<Vec<u8>, PersistError> {
    let aad = associated_data(binding, FORMAT_VERSION)?;
    let plain = Zeroizing::new(serde_json::to_vec(document).map_err(|_| PersistError::Corrupt)?);
    if plain.len() > MAX_DOCUMENT_BYTES {
        return Err(PersistError::Capacity);
    }
    // JSON contains repeated keys and byte arrays. Compress before sealing
    // so a full active journal fits within the Durable Object row limit.
    let compressed = Zeroizing::new(miniz_oxide::deflate::compress_to_vec_zlib(&plain, 3));
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| PersistError::Random)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| PersistError::Corrupt)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &compressed,
                aad: &aad,
            },
        )
        .map_err(|_| PersistError::Corrupt)?;
    let mut out = Vec::with_capacity(HEADER + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION as u8);
    out.push(KEY_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_sealed(
    key: &[u8; 32],
    binding: SealBinding<'_>,
    bytes: &[u8],
) -> Result<Document, PersistError> {
    open_sealed_with_size(key, binding, bytes).map(|(document, _)| document)
}

pub fn open_sealed_with_size(
    key: &[u8; 32],
    binding: SealBinding<'_>,
    bytes: &[u8],
) -> Result<(Document, usize), PersistError> {
    if bytes.len() < HEADER + 16 || bytes.len() > HEADER + MAX_DOCUMENT_BYTES + 16 {
        return Err(PersistError::Corrupt);
    }
    if &bytes[..4] != MAGIC {
        return Err(PersistError::Corrupt);
    }
    let version = u32::from(bytes[4]);
    if version != 1 && version != FORMAT_VERSION {
        return Err(PersistError::Unsupported {
            found: version,
            latest: FORMAT_VERSION,
        });
    }
    let key_version = bytes[5];
    if key_version != KEY_VERSION {
        return Err(PersistError::Unsupported {
            found: u32::from(key_version),
            latest: u32::from(KEY_VERSION),
        });
    }
    let aad = associated_data(binding, version)?;
    let nonce = &bytes[6..18];
    let ciphertext = &bytes[18..];
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| PersistError::Corrupt)?;
    let decoded = Zeroizing::new(cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| PersistError::Corrupt)?);
    let plain = if version == 1 {
        decoded
    } else {
        Zeroizing::new(miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
            &decoded, MAX_DOCUMENT_BYTES,
        ).map_err(|_| PersistError::Corrupt)?)
    };
    let document: Document = serde_json::from_slice(&plain).map_err(|_| PersistError::Corrupt)?;
    if document.format != version {
        return Err(PersistError::Unsupported {
            found: document.format,
            latest: FORMAT_VERSION,
        });
    }
    Ok((document, plain.len()))
}

fn associated_data(binding: SealBinding<'_>, version: u32) -> Result<Vec<u8>, PersistError> {
    if binding.project_id.is_empty()
        || binding.project_id.len() > 128
        || binding.account_hex.len() != 64
        || !binding.account_hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(PersistError::Corrupt);
    }
    let mut aad = Vec::with_capacity(8 + binding.project_id.len() + binding.account_hex.len());
    aad.extend_from_slice(MAGIC);
    aad.push(version as u8);
    aad.push(KEY_VERSION);
    aad.extend_from_slice(binding.project_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(binding.account_hex.as_bytes());
    Ok(aad)
}
