//! Marmot push triggers, adapted from official `marmot-app`.
//!
//! Source: `marmot-protocol/mdk` `crates/marmot-app/src/notifications.rs` at
//! `ca52a04718628f08ed76b777df9c444594074182`. That file is MIT, copyright
//! 2024-2026 Internet Privacy Foundation. `marmot-app` cannot be linked into
//! a Worker. The HKDF labels, plaintext layout, kind 451 owner proof, kind
//! 446 rumor, and signed-record bytes follow that revision.
//!
//! A sender stores the encrypted wake capability, not the recipient's
//! plaintext APNs or FCM token. The slot is group, member, leaf, platform,
//! and notification server. The token fingerprint is not part of the slot.

// The encoding above is adapted from MIT-licensed marmot-app. The rest of
// this crate is Unlicense, the same license as the watchdog.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use nostr::event::UnsignedEvent;
use nostr::key::{Keys, PublicKey, SecretKey as NostrSecret};
use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr::event::{FinalizeEventAsync, FinalizeUnsignedEvent};
use nostr::prelude::{EventBuilder, FinalizeEvent, Kind, Tag, Timestamp};
use secp256k1::{Parity, PublicKey as SecpPublicKey, Secp256k1, SecretKey, XOnlyPublicKey, ecdh};
use sha2::{Digest, Sha256};
use transport_nostr_peeler::NostrTransportEvent;

pub const PUSH_VERSION: &str = "marmot-push-v1";
pub const KIND_NOTIFICATION_RUMOR: u64 = 446;
pub const KIND_OWNER_PROOF: u16 = 451;
pub const ENCRYPTED_TOKEN_LEN: usize = 1084;
const PLAINTEXT_LEN: usize = 1024;
const CIPHERTEXT_LEN: usize = PLAINTEXT_LEN + 16;
const HKDF_SALT: &[u8] = b"marmot-push-token-v1";
const HKDF_INFO: &[u8] = b"marmot-push-token-encryption";
const RECORD_DOMAIN: &str = "marmot-push-token-record-v1";
const REMOVAL_DOMAIN: &str = "marmot-push-token-removal-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Apns,
    Fcm,
}

impl Platform {
    fn byte(self) -> u8 {
        match self {
            Self::Apns => 0x01,
            Self::Fcm => 0x02,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
        }
    }

    pub fn from_name(value: &str) -> Result<Self, String> {
        match value {
            "apns" => Ok(Self::Apns),
            "fcm" => Ok(Self::Fcm),
            _ => Err("unsupported push platform".into()),
        }
    }

    fn from_byte(value: u8) -> Result<Self, String> {
        match value {
            0x01 => Ok(Self::Apns),
            0x02 => Ok(Self::Fcm),
            _ => Err("unsupported push platform".into()),
        }
    }
}

/// Sender-side wake record. It does not contain the raw device token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecord {
    pub group_id_hex: String,
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: Platform,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub owner_ts: i64,
    pub encrypted_token: Vec<u8>,
    pub owner_sig: String,
    pub removed: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PushDirectory {
    records: Vec<TokenRecord>,
}

impl PushDirectory {
    /// Accept a record only after its owner proof checks and the leaf is active.
    /// A newer `(owner_ts, record_digest)` supersedes the previous token in the
    /// same slot. An older record does not resurrect a tombstone.
    pub fn admit(&mut self, record: TokenRecord, leaves: &[(String, u32)]) -> Result<(), String> {
        if record.owner_sig.len() != 128 || !verify_owner_proof(&record, record.removed) {
            return Err("owner proof rejected".into());
        }
        let active = leaves
            .iter()
            .any(|(member, leaf)| member == &record.member_id_hex && *leaf == record.leaf_index);
        if !record.removed && !active {
            return Err("token leaf is not an active member".into());
        }
        self.insert_ordered(record)
    }

    pub fn records(&self) -> &[TokenRecord] {
        &self.records
    }

    pub fn revoke(&mut self, mut tombstone: TokenRecord, leaves: &[(String, u32)]) -> Result<(), String> {
        tombstone.removed = true;
        tombstone.encrypted_token.clear();
        self.admit(tombstone, leaves)
    }

    fn insert_ordered(&mut self, record: TokenRecord) -> Result<(), String> {
        let digest = record_digest(&record)?;
        if let Some(existing) = self.records.iter_mut().find(|item| same_slot(item, &record)) {
            let existing_digest = record_digest(existing)?;
            let newer = if record.removed && !existing.removed {
                record.owner_ts >= existing.owner_ts
            } else if existing.removed && !record.removed {
                record.owner_ts > existing.owner_ts
            } else {
                record.owner_ts > existing.owner_ts
                    || (record.owner_ts == existing.owner_ts && digest > existing_digest)
            };
            if !newer {
                return Ok(());
            }
            *existing = record;
            return Ok(());
        }
        self.records.push(record);
        Ok(())
    }

    pub fn active_tokens(&self, members: &[String]) -> Vec<Vec<u8>> {
        let mut tokens = Vec::new();
        for record in &self.records {
            if record.removed || record.encrypted_token.len() != ENCRYPTED_TOKEN_LEN {
                continue;
            }
            if members.iter().any(|member| member == &record.member_id_hex) {
                tokens.push(record.encrypted_token.clone());
            }
        }
        tokens
    }
}

pub fn encrypt_token(
    platform: Platform,
    token: &[u8],
    server_pubkey_hex: &str,
) -> Result<Vec<u8>, String> {
    if token.is_empty() || token.len() > PLAINTEXT_LEN - 3 {
        return Err("push token length is outside marmot-push-v1".into());
    }
    let server_bytes = decode_hex_32(server_pubkey_hex)?;
    let server_xonly = XOnlyPublicKey::from_slice(&server_bytes)
        .map_err(|_| "server pubkey is not valid x-only secp256k1".to_owned())?;
    let server_pubkey = SecpPublicKey::from_x_only_public_key(server_xonly, Parity::Even);
    let ephemeral = random_secret()?;
    let secp = Secp256k1::new();
    let ephemeral_pubkey = SecpPublicKey::from_secret_key(&secp, &ephemeral);
    let (ephemeral_xonly, _) = ephemeral_pubkey.x_only_public_key();
    let shared = ecdh::shared_secret_point(&server_pubkey, &ephemeral);
    let mut shared_x = [0u8; 32];
    shared_x.copy_from_slice(&shared[..32]);
    let key = derive_key(&shared_x)?;
    let mut plaintext = vec![0u8; PLAINTEXT_LEN];
    plaintext[0] = platform.byte();
    let token_len = u16::try_from(token.len()).map_err(|_| "token too long".to_owned())?;
    plaintext[1..3].copy_from_slice(&token_len.to_be_bytes());
    plaintext[3..3 + token.len()].copy_from_slice(token);
    fill_random(&mut plaintext[3 + token.len()..])?;
    let mut nonce = [0u8; 12];
    fill_random(&mut nonce)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "push key setup failed".to_owned())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &[] })
        .map_err(|_| "push token encryption failed".to_owned())?;
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err("push ciphertext length mismatch".into());
    }
    let mut out = Vec::with_capacity(ENCRYPTED_TOKEN_LEN);
    out.extend_from_slice(&ephemeral_xonly.serialize());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_token(blob: &[u8], server_secret: &[u8; 32]) -> Result<(Platform, Vec<u8>), String> {
    if blob.len() != ENCRYPTED_TOKEN_LEN {
        return Err("encrypted push token length mismatch".into());
    }
    let ephemeral_xonly = XOnlyPublicKey::from_slice(&blob[..32])
        .map_err(|_| "ephemeral key is not x-only".to_owned())?;
    let ephemeral = SecpPublicKey::from_x_only_public_key(ephemeral_xonly, Parity::Even);
    let secret = SecretKey::from_slice(server_secret).map_err(|error| error.to_string())?;
    let shared = ecdh::shared_secret_point(&ephemeral, &secret);
    let mut shared_x = [0u8; 32];
    shared_x.copy_from_slice(&shared[..32]);
    let key = derive_key(&shared_x)?;
    let nonce = &blob[32..44];
    let ciphertext = &blob[44..];
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "push key setup failed".to_owned())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &[] })
        .map_err(|_| "push token decryption failed".to_owned())?;
    if plaintext.len() != PLAINTEXT_LEN {
        return Err("push plaintext length mismatch".into());
    }
    let platform = Platform::from_byte(plaintext[0])?;
    let token_len = u16::from_be_bytes([plaintext[1], plaintext[2]]) as usize;
    if token_len == 0 || token_len > PLAINTEXT_LEN - 3 {
        return Err("push token length is outside marmot-push-v1".into());
    }
    Ok((platform, plaintext[3..3 + token_len].to_vec()))
}

pub fn sign_owner_proof(
    keys: &Keys,
    record: &TokenRecord,
    removal: bool,
) -> Result<String, String> {
    let proof = owner_proof_event(record, removal)?;
    let signed = proof
        .clone()
        .finalize(keys)
        .map_err(|error| error.to_string())?;
    if Some(signed.id) != proof.id || signed.pubkey != proof.pubkey || signed.tags != proof.tags {
        return Err("owner proof did not bind the record".into());
    }
    signed.verify().map_err(|error| error.to_string())?;
    Ok(hex::encode(signed.sig.to_bytes()))
}

pub fn verify_owner_proof(record: &TokenRecord, removal: bool) -> bool {
    let Ok(proof) = owner_proof_event(record, removal) else {
        return false;
    };
    let Ok(bytes) = hex::decode(&record.owner_sig) else {
        return false;
    };
    let Ok(signature) = nostr::event::Signature::from_slice(&bytes) else {
        return false;
    };
    proof.add_signature(signature).is_ok()
}

pub async fn notification_gift_wrap(
    server_pubkey_hex: &str,
    tokens: &[Vec<u8>],
) -> Result<NostrTransportEvent, String> {
    if tokens.is_empty() || tokens.len() > 18 {
        return Err("a gift wrap holds 1 to 18 tokens plus one padding token".into());
    }
    if tokens.iter().any(|token| token.len() != ENCRYPTED_TOKEN_LEN) {
        return Err("notification tokens must be marmot-push-v1".into());
    }
    let mut padded = tokens.to_vec();
    padded.push(random_padding_token()?);
    let server = PublicKey::parse(server_pubkey_hex).map_err(|error| error.to_string())?;
    let content = BASE64.encode(padded.concat());
    let seal_keys = random_nostr_keys()?;
    let rumor = EventBuilder::new(Kind::Custom(KIND_NOTIFICATION_RUMOR as u16), content)
        .tags([Tag::custom(
            "v",
            [PUSH_VERSION.to_owned()],
        )])
        .finalize_unsigned(seal_keys.public_key());
    let gift = GiftWrapBuilder::new(server, rumor)
        .finalize_async(&seal_keys)
        .await
        .map_err(|error| error.to_string())?;
    NostrTransportEvent::from_nostr_event(&gift).map_err(|error| error.to_string())
}

/// Decode kind 447, 448, or 449 content into owner-signed wake records.
/// The caller still has to admit them against the current leaf set.
pub fn records_from_gossip(
    kind: u64,
    group_id_hex: &str,
    content: &str,
) -> Result<Vec<TokenRecord>, String> {
    if content.len() > 64 * 1024 {
        return Err("push gossip is too large".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|_| "push gossip is not json".to_owned())?;
    if value.get("v").and_then(|item| item.as_str()) != Some(PUSH_VERSION) {
        return Err("unsupported push token gossip version".into());
    }
    let (removed, entries) = match kind {
        447 | 448 => (false, value.get("tokens")),
        449 => (true, value.get("removals")),
        _ => return Err("unsupported push token gossip kind".into()),
    };
    let entries = entries.and_then(|item| item.as_array()).cloned().unwrap_or_default();
    if entries.len() > 32 {
        return Err("push gossip array is too large".into());
    }
    let mut records = Vec::new();
    for entry in entries {
        let member_id_hex = entry
            .get("member_id_hex")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        let server_pubkey_hex = entry
            .get("server_pubkey_hex")
            .and_then(|item| item.as_str())
            .unwrap_or("")
            .to_owned();
        if member_id_hex.len() != 64 || server_pubkey_hex.len() != 64 {
            continue;
        }
        let platform = match Platform::from_name(
            entry.get("platform").and_then(|item| item.as_str()).unwrap_or(""),
        ) {
            Ok(platform) => platform,
            Err(_) => continue,
        };
        let encrypted_token = if removed {
            Vec::new()
        } else {
            match BASE64.decode(
                entry
                    .get("encrypted_token")
                    .and_then(|item| item.as_str())
                    .unwrap_or(""),
            ) {
                Ok(bytes) if bytes.len() == ENCRYPTED_TOKEN_LEN => bytes,
                _ => continue,
            }
        };
        records.push(TokenRecord {
            group_id_hex: group_id_hex.to_owned(),
            member_id_hex,
            leaf_index: entry.get("leaf_index").and_then(|item| item.as_u64()).unwrap_or(0) as u32,
            platform,
            token_fingerprint: entry
                .get("token_fingerprint")
                .and_then(|item| item.as_str())
                .unwrap_or("")
                .to_owned(),
            server_pubkey_hex,
            relay_hint: entry
                .get("relay_hint")
                .and_then(|item| item.as_str())
                .map(str::to_owned),
            owner_ts: entry.get("owner_ts").and_then(|item| item.as_i64()).unwrap_or(0),
            encrypted_token,
            owner_sig: entry
                .get("owner_sig")
                .and_then(|item| item.as_str())
                .unwrap_or("")
                .to_owned(),
            removed,
        });
    }
    Ok(records)
}

pub fn unwrap_notification(
    server_keys: &Keys,
    event_json: &[u8],
) -> Result<String, String> {
    let event: nostr::event::Event = serde_json::from_slice(event_json).map_err(|error| error.to_string())?;
    let opened = UnwrappedGift::from_gift_wrap(server_keys, &event).map_err(|error| error.to_string())?;
    if opened.rumor.kind != Kind::Custom(KIND_NOTIFICATION_RUMOR as u16) {
        return Err("notification rumor kind mismatch".into());
    }
    Ok(opened.rumor.content)
}

fn owner_proof_event(record: &TokenRecord, removal: bool) -> Result<UnsignedEvent, String> {
    let member = PublicKey::parse(&record.member_id_hex).map_err(|error| error.to_string())?;
    let relay = record.relay_hint.as_deref().unwrap_or("").trim();
    let domain = if removal { REMOVAL_DOMAIN } else { RECORD_DOMAIN };
    let mut tags = vec![
        Tag::custom("d", [domain.to_owned()]),
        Tag::custom("group_id", [record.group_id_hex.clone()]),
        Tag::custom("member_id", [record.member_id_hex.clone()]),
        Tag::custom("leaf_index", [record.leaf_index.to_string()]),
        Tag::custom("platform", [record.platform.name().to_owned()]),
        Tag::custom("server_pubkey", [record.server_pubkey_hex.clone()]),
        Tag::custom("token_fingerprint", [record.token_fingerprint.clone()]),
        Tag::custom("owner_ts", [record.owner_ts.to_string()]),
        Tag::custom("relay_hint", [relay.to_owned()]),
    ];
    let content = if removal {
        String::new()
    } else {
        tags.push(Tag::custom(
            "encrypted_token_encoding",
            ["base64".to_owned()],
        ));
        BASE64.encode(&record.encrypted_token)
    };
    let mut event = EventBuilder::new(Kind::Custom(KIND_OWNER_PROOF), content)
        .tags(tags)
        .custom_created_at(Timestamp::zero())
        .finalize_unsigned(member);
    event.ensure_id();
    Ok(event)
}

pub fn token_fingerprint(platform: Platform, token: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([platform.byte()]);
    hasher.update(token);
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{}", &digest[..24])
}

fn same_slot(left: &TokenRecord, right: &TokenRecord) -> bool {
    left.group_id_hex == right.group_id_hex
        && left.member_id_hex == right.member_id_hex
        && left.leaf_index == right.leaf_index
        && left.platform == right.platform
        && left.server_pubkey_hex == right.server_pubkey_hex
}

fn record_digest(record: &TokenRecord) -> Result<String, String> {
    let bytes = signed_record_bytes(record)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn signed_record_bytes(record: &TokenRecord) -> Result<Vec<u8>, String> {
    let group_id = hex::decode(&record.group_id_hex).map_err(|_| "group id must be hex".to_owned())?;
    let member_id = decode_hex_32(&record.member_id_hex)?;
    let server = decode_hex_32(&record.server_pubkey_hex)?;
    let fingerprint = fingerprint_bytes(&record.token_fingerprint)?;
    let group_len = u16::try_from(group_id.len()).map_err(|_| "group id too long".to_owned())?;
    let relay = record.relay_hint.as_deref().unwrap_or("").trim();
    let relay_len = u16::try_from(relay.len()).map_err(|_| "relay hint too long".to_owned())?;
    let domain = if record.removed { REMOVAL_DOMAIN } else { RECORD_DOMAIN };
    let mut buf = Vec::new();
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&group_len.to_be_bytes());
    buf.extend_from_slice(&group_id);
    buf.extend_from_slice(&member_id);
    buf.extend_from_slice(&record.leaf_index.to_be_bytes());
    buf.push(record.platform.byte());
    buf.extend_from_slice(&server);
    buf.extend_from_slice(&fingerprint);
    buf.extend_from_slice(&record.owner_ts.to_be_bytes());
    buf.extend_from_slice(&relay_len.to_be_bytes());
    buf.extend_from_slice(relay.as_bytes());
    if !record.removed {
        buf.extend_from_slice(&record.encrypted_token);
    }
    Ok(buf)
}

fn fingerprint_bytes(token_fingerprint: &str) -> Result<[u8; 12], String> {
    let hex_part = token_fingerprint
        .strip_prefix("sha256:")
        .ok_or("token fingerprint must start with sha256:")?;
    let decoded = hex::decode(hex_part).map_err(|_| "token fingerprint must be hex".to_owned())?;
    decoded
        .try_into()
        .map_err(|_| "token fingerprint must be 12 bytes".to_owned())
}

fn derive_key(shared_x: &[u8; 32]) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_x);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key)
        .map_err(|_| "push key derivation failed".to_owned())?;
    Ok(key)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| "expected 32-byte hex".to_owned())?;
    bytes.try_into().map_err(|_| "expected 32-byte hex".to_owned())
}

fn random_secret() -> Result<SecretKey, String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes)?;
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
    Err("random secp256k1 secret failed".into())
}

fn random_nostr_keys() -> Result<Keys, String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes)?;
        if let Ok(secret) = NostrSecret::from_slice(&bytes) {
            return Ok(Keys::new(secret));
        }
    }
    Err("random Nostr key failed".into())
}

fn random_padding_token() -> Result<Vec<u8>, String> {
    let mut padding = vec![0u8; ENCRYPTED_TOKEN_LEN];
    fill_random(&mut padding)?;
    Ok(padding)
}

fn fill_random(bytes: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(bytes).map_err(|_| "randomness failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_server_decrypts_the_official_trigger_layout() {
        for parity in [Parity::Even, Parity::Odd] {
            let server_secret = secret_with_parity(parity);
            let secp = Secp256k1::new();
            let server_public = SecpPublicKey::from_secret_key(&secp, &server_secret);
            let (server_xonly, found) = server_public.x_only_public_key();
            assert_eq!(found, parity);
            let server_hex = hex::encode(server_xonly.serialize());
            let token = b"fcm-device-token".to_vec();
            let encrypted = encrypt_token(Platform::Fcm, &token, &server_hex).unwrap();
            let (platform, opened) = decrypt_token(&encrypted, server_secret.as_ref()).unwrap();
            assert_eq!(platform, Platform::Fcm);
            assert_eq!(opened, token);
        }

        let server_secret = secret_with_parity(Parity::Even);
        let secp = Secp256k1::new();
        let server_public = SecpPublicKey::from_secret_key(&secp, &server_secret);
        let (server_xonly, _) = server_public.x_only_public_key();
        let server_hex = hex::encode(server_xonly.serialize());
        let server_keys = random_nostr_keys_from(&server_secret);
        let owner = random_nostr_keys().unwrap();
        let token = b"fcm-device-token".to_vec();
        let encrypted = encrypt_token(Platform::Fcm, &token, &server_hex).unwrap();
        let replacement = encrypt_token(Platform::Fcm, b"fcm-replacement", &server_hex).unwrap();
        let group_id_hex = "ab".repeat(16);
        let leaves = [(hex::encode(owner.public_key().to_bytes()), 0u32)];

        let mut record = TokenRecord {
            group_id_hex: group_id_hex.clone(),
            member_id_hex: leaves[0].0.clone(),
            leaf_index: 0,
            platform: Platform::Fcm,
            token_fingerprint: token_fingerprint(Platform::Fcm, &token),
            server_pubkey_hex: server_hex.clone(),
            relay_hint: Some("wss://relay.example".into()),
            owner_ts: 1_700_000_000_000,
            encrypted_token: encrypted.clone(),
            owner_sig: String::new(),
            removed: false,
        };
        record.owner_sig = sign_owner_proof(&owner, &record, false).unwrap();
        assert!(verify_owner_proof(&record, false));

        let mut directory = PushDirectory::default();
        directory.admit(record.clone(), &leaves).unwrap();
        let mut unsigned = record.clone();
        unsigned.owner_sig.clear();
        assert!(directory.admit(unsigned, &leaves).is_err());
        let mut older = record.clone();
        older.owner_ts -= 1;
        older.encrypted_token = vec![0; ENCRYPTED_TOKEN_LEN];
        older.token_fingerprint = token_fingerprint(Platform::Fcm, b"old");
        older.owner_sig = sign_owner_proof(&owner, &older, false).unwrap();
        directory.admit(older, &leaves).unwrap();
        assert_eq!(directory.records[0].encrypted_token, encrypted);

        let mut newer = record.clone();
        newer.owner_ts += 1;
        newer.encrypted_token = replacement.clone();
        newer.token_fingerprint = token_fingerprint(Platform::Fcm, b"fcm-replacement");
        newer.owner_sig = sign_owner_proof(&owner, &newer, false).unwrap();
        directory.admit(newer, &leaves).unwrap();
        assert_eq!(directory.records[0].encrypted_token, replacement);

        let mut tombstone = record.clone();
        tombstone.owner_ts += 2;
        tombstone.removed = true;
        tombstone.encrypted_token.clear();
        tombstone.owner_sig = sign_owner_proof(&owner, &tombstone, true).unwrap();
        directory.revoke(tombstone, &leaves).unwrap();
        assert!(directory.active_tokens(&[record.member_id_hex.clone()]).is_empty());
        directory.admit(record.clone(), &leaves).unwrap();
        assert!(directory.active_tokens(&[record.member_id_hex.clone()]).is_empty());

        let trigger = notification_gift_wrap(&server_hex, &[encrypted.clone()]).await.unwrap();
        assert_eq!(trigger.kind, 1059);
        let content = unwrap_notification(&server_keys, &serde_json::to_vec(&trigger).unwrap()).unwrap();
        let raw = BASE64.decode(content).unwrap();
        assert!(raw.windows(encrypted.len()).any(|window| window == encrypted));
    }

    fn secret_with_parity(want: Parity) -> SecretKey {
        for _ in 0..64 {
            let secret = random_secret().unwrap();
            let public = SecpPublicKey::from_secret_key(&Secp256k1::new(), &secret);
            if public.x_only_public_key().1 == want {
                return secret;
            }
        }
        panic!("no secp256k1 key with parity {want:?}");
    }

    fn random_nostr_keys_from(secret: &SecretKey) -> Keys {
        Keys::new(NostrSecret::from_slice(&secret.secret_bytes()).unwrap())
    }
}
