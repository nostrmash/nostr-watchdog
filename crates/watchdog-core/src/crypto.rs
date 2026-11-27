use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn hmac_sha256_hex(secret: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_hmac_sha256(secret: &str, message: &str, signature_hex: &str) -> bool {
    if secret.is_empty()
        || signature_hex.len() != 64
        || !signature_hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return false;
    }
    let Ok(expected) = hex::decode(signature_hex) else {
        return false;
    };
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(message.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Compare two secrets without revealing which one was longer.
/// Both values are hashed first, matching the previous Worker.
pub fn secrets_equal(left: &str, right: &str) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let a = Sha256::digest(left.as_bytes());
    let b = Sha256::digest(right.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn canonical_heartbeat(
    timestamp: &str,
    nonce: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    format!(
        "{timestamp}\n{nonce}\n{}\n{path}\n{}",
        method.to_ascii_uppercase(),
        sha256_hex(body)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_round_trip_and_constant_secret_compare() {
        let sig = hmac_sha256_hex("key", "message");
        assert!(verify_hmac_sha256("key", "message", &sig));
        assert!(!verify_hmac_sha256("key", "other", &sig));
        assert!(secrets_equal("same", "same"));
        assert!(!secrets_equal("same", "different"));
        assert!(!secrets_equal("", "same"));
    }
}
