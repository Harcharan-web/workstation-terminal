//! Short-lived, single-use login challenges and SSHSIG verification.
//!
//! The browser asks for a challenge for a user name. The server returns a one-line message
//! containing the origin, user, a random nonce, a challenge id and the expiry. The user signs
//! it locally with `ssh-keygen -Y sign -n sshweb-auth` (key file, encrypted key or agent) and
//! pastes the armored signature back. The server rebuilds the message from its own stored
//! state (never from client input), checks the namespace and that the signing key is one of
//! the user's authorised keys, and verifies the signature. Challenges are removed on the
//! first verification attempt, so they cannot be replayed even after a failure.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ssh_key::SshSig;

use super::keys::{AuthorizedKey, AuthorizedKeys};
use crate::security;

/// SSHSIG namespace; signatures for other purposes (e.g. git commits) are rejected.
pub const NAMESPACE: &str = "sshweb-auth";
pub const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_OUTSTANDING: usize = 10_000;

#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: String,
    pub user: String,
    pub origin: String,
    /// Hash of the secret that binds the challenge to the requesting browser/socket.
    binding: [u8; 32],
    pub message: String,
    pub expires_at: Instant,
    pub expires_unix: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChallengeError {
    #[error("unknown or already used challenge")]
    Unknown,
    #[error("challenge expired")]
    Expired,
    #[error("challenge was issued to a different client")]
    BindingMismatch,
    #[error("too many outstanding challenges")]
    Capacity,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("signature is too large")]
    TooLarge,
    #[error("signature is not a valid SSH signature")]
    Malformed,
    #[error("signature namespace must be {NAMESPACE:?}")]
    Namespace,
    #[error("signing key is not authorised for this user")]
    KeyNotAuthorized,
    #[error("signature verification failed")]
    BadSignature,
}

pub struct ChallengeStore {
    ttl: Duration,
    map: Mutex<HashMap<String, Challenge>>,
}

impl ChallengeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(
        &self,
        user: &str,
        origin: &str,
        binding_secret: &str,
    ) -> Result<Challenge, ChallengeError> {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap();
        if map.len() >= MAX_OUTSTANDING {
            map.retain(|_, c| c.expires_at > now);
            if map.len() >= MAX_OUTSTANDING {
                return Err(ChallengeError::Capacity);
            }
        }
        let id = security::random_token(18);
        let nonce = security::random_token(32);
        let expires_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + self.ttl.as_secs();
        let message = format!(
            "sshweb-auth-v1 origin={origin} user={user} challenge={id} nonce={nonce} expires={expires_unix}"
        );
        let ch = Challenge {
            id: id.clone(),
            user: user.to_string(),
            origin: origin.to_string(),
            binding: security::hash_secret(binding_secret),
            message,
            expires_at: now + self.ttl,
            expires_unix,
        };
        map.insert(id, ch.clone());
        Ok(ch)
    }

    /// Remove and return the challenge (single use), checking expiry and binding.
    pub fn take(&self, id: &str, binding_secret: &str) -> Result<Challenge, ChallengeError> {
        self.take_at(id, binding_secret, Instant::now())
    }

    pub fn take_at(
        &self,
        id: &str,
        binding_secret: &str,
        now: Instant,
    ) -> Result<Challenge, ChallengeError> {
        let ch = self
            .map
            .lock()
            .unwrap()
            .remove(id)
            .ok_or(ChallengeError::Unknown)?;
        if now >= ch.expires_at {
            return Err(ChallengeError::Expired);
        }
        if !security::ct_eq(&ch.binding, &security::hash_secret(binding_secret)) {
            return Err(ChallengeError::BindingMismatch);
        }
        Ok(ch)
    }

    pub fn purge(&self) {
        let now = Instant::now();
        self.map.lock().unwrap().retain(|_, c| c.expires_at > now);
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Verify an armored SSHSIG over `message` against the user's authorised keys.
pub fn verify_signature<'a>(
    keys: &'a AuthorizedKeys,
    user: &str,
    message: &str,
    armored: &str,
) -> Result<&'a AuthorizedKey, VerifyError> {
    if armored.len() > MAX_SIGNATURE_BYTES {
        return Err(VerifyError::TooLarge);
    }
    let armored = armored.trim().replace("\r\n", "\n");
    let sig = SshSig::from_pem(armored.as_bytes()).map_err(|_| VerifyError::Malformed)?;
    if sig.namespace() != NAMESPACE {
        return Err(VerifyError::Namespace);
    }
    let key = keys
        .keys
        .iter()
        .find(|k| k.user == user && k.key.key_data() == sig.public_key())
        .ok_or(VerifyError::KeyNotAuthorized)?;
    key.key
        .verify(NAMESPACE, message.as_bytes(), &sig)
        .map_err(|_| VerifyError::BadSignature)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    fn keys_for(user: &str, k: &PrivateKey) -> AuthorizedKeys {
        let line = format!(
            "user=\"{user}\",access=\"local\" {}",
            k.public_key().to_openssh().unwrap()
        );
        AuthorizedKeys::parse(&line, 2048).unwrap()
    }

    fn sign(k: &PrivateKey, ns: &str, msg: &str) -> String {
        k.sign(ns, HashAlg::Sha512, msg.as_bytes())
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap()
    }

    #[test]
    fn verifies_ed25519_signature() {
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ak = keys_for("alice", &k);
        let sig = sign(&k, NAMESPACE, "hello");
        assert_eq!(
            verify_signature(&ak, "alice", "hello", &sig).unwrap().user,
            "alice"
        );
        // Windows line endings and surrounding whitespace from copy/paste are tolerated.
        let crlf = format!("\n  {}  \n", sig.replace('\n', "\r\n"));
        assert!(verify_signature(&ak, "alice", "hello", &crlf).is_ok());
    }

    #[test]
    fn verifies_ecdsa_signature() {
        let k = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        let ak = keys_for("alice", &k);
        let sig = sign(&k, NAMESPACE, "m");
        assert!(verify_signature(&ak, "alice", "m", &sig).is_ok());
    }

    #[test]
    fn rejects_wrong_message_namespace_key_and_user() {
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ak = keys_for("alice", &k);
        let sig = sign(&k, NAMESPACE, "hello");
        assert_eq!(
            verify_signature(&ak, "alice", "hellO", &sig).unwrap_err(),
            VerifyError::BadSignature
        );
        assert_eq!(
            verify_signature(&ak, "bob", "hello", &sig).unwrap_err(),
            VerifyError::KeyNotAuthorized
        );
        let wrong_ns = sign(&k, "git", "hello");
        assert_eq!(
            verify_signature(&ak, "alice", "hello", &wrong_ns).unwrap_err(),
            VerifyError::Namespace
        );
        let other_sig = sign(&other, NAMESPACE, "hello");
        assert_eq!(
            verify_signature(&ak, "alice", "hello", &other_sig).unwrap_err(),
            VerifyError::KeyNotAuthorized
        );
        assert_eq!(
            verify_signature(&ak, "alice", "hello", "not a signature").unwrap_err(),
            VerifyError::Malformed
        );
        let huge = "A".repeat(MAX_SIGNATURE_BYTES + 1);
        assert_eq!(
            verify_signature(&ak, "alice", "hello", &huge).unwrap_err(),
            VerifyError::TooLarge
        );
    }

    #[test]
    fn a_bare_public_key_is_not_proof() {
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ak = keys_for("alice", &k);
        let pubkey = k.public_key().to_openssh().unwrap();
        assert!(verify_signature(&ak, "alice", "hello", &pubkey).is_err());
    }

    #[test]
    fn challenge_single_use() {
        let s = ChallengeStore::new(Duration::from_secs(60));
        let c = s.issue("alice", "http://127.0.0.1:7681", "bind").unwrap();
        assert!(c.message.contains("user=alice"));
        assert!(c.message.contains("origin=http://127.0.0.1:7681"));
        assert_eq!(s.take(&c.id, "bind").unwrap().id, c.id);
        assert_eq!(s.take(&c.id, "bind").unwrap_err(), ChallengeError::Unknown);
    }

    #[test]
    fn challenge_expiry() {
        let s = ChallengeStore::new(Duration::from_secs(60));
        let c = s.issue("alice", "o", "bind").unwrap();
        let later = Instant::now() + Duration::from_secs(61);
        assert_eq!(
            s.take_at(&c.id, "bind", later).unwrap_err(),
            ChallengeError::Expired
        );
        // Expired challenge is consumed too.
        assert_eq!(s.take(&c.id, "bind").unwrap_err(), ChallengeError::Unknown);
    }

    #[test]
    fn challenge_binding() {
        let s = ChallengeStore::new(Duration::from_secs(60));
        let c = s.issue("alice", "o", "bind").unwrap();
        assert_eq!(
            s.take(&c.id, "other").unwrap_err(),
            ChallengeError::BindingMismatch
        );
        // A failed attempt still burns the challenge.
        assert_eq!(s.take(&c.id, "bind").unwrap_err(), ChallengeError::Unknown);
    }

    #[test]
    fn challenges_are_unique() {
        let s = ChallengeStore::new(Duration::from_secs(60));
        let a = s.issue("alice", "o", "b").unwrap();
        let b = s.issue("alice", "o", "b").unwrap();
        assert_ne!(a.id, b.id);
        assert_ne!(a.message, b.message);
        assert_eq!(s.len(), 2);
    }
}
