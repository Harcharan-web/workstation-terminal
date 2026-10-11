//! Security primitives: randomness, permission checks, origin validation, rate limiting.

pub mod origin;
pub mod perms;
pub mod rate_limit;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// `n` bytes from the OS CSPRNG, base64url encoded.
pub fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    URL_SAFE_NO_PAD.encode(buf)
}

/// Short random identifier (128 bits, hex) for sessions shown to users and admins.
pub fn random_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    hex::encode(buf)
}

/// SHA-256 of a secret, used as a map key so raw tokens are never stored.
pub fn hash_secret(s: &str) -> [u8; 32] {
    let out = Sha256::digest(s.as_bytes());
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_long() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert_eq!(random_id().len(), 32);
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
