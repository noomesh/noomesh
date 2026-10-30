// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use super::Error;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const KEY_NAME: &str = "NOO_INTEGRATIONS_KEY";

pub struct Vault(Zeroizing<[u8; 32]>);

#[derive(Serialize, Deserialize)]
pub struct Sealed {
    v: u8,
    nonce: String,
    ciphertext: String,
}

impl Vault {
    pub fn from_secret(secret: &str) -> Result<Self, Error> {
        if secret.len() < 32 {
            return Err(Error::Unavailable(
                "The integration encryption key is missing or too short".into(),
            ));
        }
        let mut h = Sha256::new();
        h.update(b"noomesh/integration-vault/v1\0");
        h.update(secret.as_bytes());
        Ok(Self(Zeroizing::new(h.finalize().into())))
    }
    pub fn configured() -> Result<Self, Error> {
        let secret = crate::config::secret_env::secret(KEY_NAME)
            .map_err(|_| Error::Unavailable("The integration encryption key could not be read".into()))?
            .map(Zeroizing::new).ok_or_else(|| Error::Unavailable("Installer setup required: create NOO_INTEGRATIONS_KEY in the encrypted secret store".into()))?;
        Self::from_secret(&secret)
    }
    pub fn seal<T: Serialize>(&self, value: &T, context: &str) -> Result<serde_json::Value, Error> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|_| Error::Invalid("Invalid credential data".into()))?,
        );
        let nonce = rand::random::<[u8; 12]>();
        let cipher = ChaCha20Poly1305::new_from_slice(self.0.as_ref()).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(
                &Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Reauth)?,
                Payload {
                    msg: &plaintext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| Error::Unavailable("Credential encryption failed".into()))?;
        Ok(serde_json::to_value(Sealed {
            v: 1,
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        })
        .expect("serializable envelope"))
    }
    pub fn open<T: serde::de::DeserializeOwned>(
        &self,
        value: &serde_json::Value,
        context: &str,
    ) -> Result<T, Error> {
        let s: Sealed = serde_json::from_value(value.clone()).map_err(|_| Error::Reauth)?;
        let nonce = B64.decode(&s.nonce).map_err(|_| Error::Reauth)?;
        if s.v != 1 || nonce.len() != 12 {
            return Err(Error::Reauth);
        }
        let bytes = B64.decode(&s.ciphertext).map_err(|_| Error::Reauth)?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.0.as_ref()).expect("32-byte key");
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Reauth)?,
                    Payload {
                        msg: &bytes,
                        aad: context.as_bytes(),
                    },
                )
                .map_err(|_| Error::Reauth)?,
        );
        serde_json::from_slice(&plain).map_err(|_| Error::Reauth)
    }
}

pub fn random_token() -> String {
    B64.encode(rand::random::<[u8; 32]>())
}
pub fn hash(value: &str) -> String {
    B64.encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ciphertext_is_bound_to_owner_account_and_purpose() {
        let v = Vault::from_secret(&"a".repeat(32)).unwrap();
        let sealed = v.seal(&"credential", "alice/google/account-a").unwrap();
        assert!(!sealed.to_string().contains("credential"));
        assert_eq!(
            v.open::<String>(&sealed, "alice/google/account-a").unwrap(),
            "credential"
        );
        for context in [
            "bob/google/account-a",
            "alice/google/account-b",
            "alice/google/session-a",
        ] {
            assert!(v.open::<String>(&sealed, context).is_err());
        }
        assert!(Vault::from_secret(&"b".repeat(32))
            .unwrap()
            .open::<String>(&sealed, "alice/google/account-a")
            .is_err());
    }
}
