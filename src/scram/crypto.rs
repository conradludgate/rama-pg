//! SCRAM-SHA-256 cryptographic primitives (RFC 5802 / RFC 7677).
//!
//! HMAC-SHA256 and PBKDF2 are implemented directly on `sha2` to avoid pinning a
//! separate `hmac`/`pbkdf2` release against the bleeding-edge `sha2`. Correctness
//! is pinned by the RFC 7677 / RFC 4231 test vectors below.

use sha2::{Digest, Sha256};

/// The key material derived from a SCRAM password (or recovered during a
/// handshake). `client_key` is the piece a SCRAM *client* needs to produce a
/// proof; `stored_key`/`server_key` are the verifier a SCRAM *server* holds.
#[derive(Debug, Clone, Copy)]
pub struct ScramKeys {
    pub client_key: [u8; 32],
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl ScramKeys {
    /// Derive all keys from a salted password.
    pub fn from_salted_password(salted: &[u8; 32]) -> Self {
        let client_key = hmac_sha256(salted, b"Client Key");
        Self {
            client_key,
            stored_key: sha256(&client_key),
            server_key: hmac_sha256(salted, b"Server Key"),
        }
    }

    /// Derive all keys from a plaintext password, salt and iteration count.
    pub fn from_password(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        Self::from_salted_password(&pbkdf2_hmac_sha256(password, salt, iterations))
    }
}

/// `ClientProof XOR ClientSignature`, recovering the `ClientKey` a SCRAM server
/// can then validate against the `StoredKey` (and reuse to reauthenticate
/// upstream).
pub fn recover_client_key(proof: &[u8; 32], client_signature: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = proof[i] ^ client_signature[i];
    }
    key
}

/// `ClientProof = ClientKey XOR ClientSignature`.
pub fn client_proof(client_key: &[u8; 32], client_signature: &[u8; 32]) -> [u8; 32] {
    let mut proof = [0u8; 32];
    for i in 0..32 {
        proof[i] = client_key[i] ^ client_signature[i];
    }
    proof
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        block_key[..32].copy_from_slice(&sha256(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA256 for the SCRAM case `dkLen == hLen == 32`, so only the
/// first (and only) block is needed: `U1 ^ U2 ^ ... ^ Ui`.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes()); // INT(1)

    let mut u = hmac_sha256(password, &block);
    let mut result = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for i in 0..32 {
            result[i] ^= u[i];
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;

    // RFC 7677 §3 worked example for SCRAM-SHA-256.
    const PASSWORD: &str = "pencil";
    const SALT_B64: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const ITERATIONS: u32 = 4096;
    const CLIENT_FIRST_BARE: &str = "n=user,r=rOprNGfwEbeRWgbNEkqO";
    const SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const CLIENT_FINAL_WITHOUT_PROOF: &str =
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const EXPECTED_PROOF_B64: &str = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const EXPECTED_SERVER_SIG_B64: &str = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn auth_message() -> String {
        format!("{CLIENT_FIRST_BARE},{SERVER_FIRST},{CLIENT_FINAL_WITHOUT_PROOF}")
    }

    #[test]
    fn rfc7677_proof_and_server_signature() {
        let salt = BASE64_STANDARD.decode(SALT_B64).unwrap();
        let keys = ScramKeys::from_password(PASSWORD.as_bytes(), &salt, ITERATIONS);

        let client_signature = hmac_sha256(&keys.stored_key, auth_message().as_bytes());
        let proof = client_proof(&keys.client_key, &client_signature);
        assert_eq!(BASE64_STANDARD.encode(proof), EXPECTED_PROOF_B64);

        // The server recovers ClientKey from the proof and confirms it.
        let recovered = recover_client_key(&proof, &client_signature);
        assert_eq!(recovered, keys.client_key);
        assert_eq!(sha256(&recovered), keys.stored_key);

        let server_signature = hmac_sha256(&keys.server_key, auth_message().as_bytes());
        assert_eq!(
            BASE64_STANDARD.encode(server_signature),
            EXPECTED_SERVER_SIG_B64
        );
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
