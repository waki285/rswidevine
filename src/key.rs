//! Key module for handling decrypted content keys.
//!
//! Keys are parsed from License messages and decrypted using AES-128-CBC.

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::license_protocol::license::key_container::KeyType;
use crate::license_protocol::license::KeyContainer;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// A decrypted content key.
///
/// Key type names use the license protocol enum string values (e.g. CONTENT).
#[derive(Debug, Clone)]
pub struct Key {
    /// Key type (e.g., CONTENT, SIGNING, etc.).
    pub key_type: String,
    /// Key ID as UUID.
    pub kid: Uuid,
    /// Decrypted key bytes.
    pub key: Vec<u8>,
    /// Permissions for OPERATOR_SESSION keys.
    pub permissions: Vec<String>,
}

impl Key {
    /// Create a new Key.
    pub fn new(key_type: String, kid: Uuid, key: Vec<u8>, permissions: Vec<String>) -> Self {
        Self {
            key_type,
            kid,
            key,
            permissions,
        }
    }

    /// Load a Key from a KeyContainer.
    ///
    /// For OPERATOR_SESSION keys, permissions are extracted from the
    /// operator_session_key_permissions field.
    pub fn from_key_container(container: &KeyContainer, enc_key: &[u8]) -> Result<Self> {
        let mut permissions = Vec::new();

        // Extract permissions for OPERATOR_SESSION keys
        if container.r#type() == KeyType::OperatorSession {
            if let Some(ref perms) = container.operator_session_key_permissions {
                if perms.allow_encrypt.unwrap_or(false) { permissions.push("allow_encrypt".to_string()); }
                if perms.allow_decrypt.unwrap_or(false) { permissions.push("allow_decrypt".to_string()); }
                if perms.allow_sign.unwrap_or(false) { permissions.push("allow_sign".to_string()); }
                if perms.allow_signature_verify.unwrap_or(false) { permissions.push("allow_signature_verify".to_string()); }
            }
        }

        let key_type = container
            .r#type
            .and_then(|v| KeyType::try_from(v).ok())
            .map(|t| t.as_str_name().to_string())
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing key type".to_string()))?;

        let kid_bytes = container
            .id
            .as_ref()
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing key ID".to_string()))?;
        let kid = Self::kid_to_uuid(kid_bytes)?;

        let key_bytes = container
            .key
            .as_ref()
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing key bytes".to_string()))?;
        let iv_bytes = container
            .iv
            .as_ref()
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing IV bytes".to_string()))?;

        // Decrypt the key using AES-CBC
        let decrypted_key = Self::decrypt_key(key_bytes, iv_bytes, enc_key)?;

        Ok(Self::new(key_type, kid, decrypted_key, permissions))
    }

    /// Decrypt a key using AES-128-CBC.
    fn decrypt_key(encrypted_key: &[u8], iv: &[u8], enc_key: &[u8]) -> Result<Vec<u8>> {
        if enc_key.len() != 16 {
            return Err(Error::Other(format!(
                "Invalid encryption key length: expected 16, got {}",
                enc_key.len()
            )));
        }

        if iv.len() != 16 {
            return Err(Error::Other(format!(
                "Invalid IV length: expected 16, got {}",
                iv.len()
            )));
        }

        let enc_key_arr: [u8; 16] = enc_key.try_into().unwrap();
        let iv_arr: [u8; 16] = iv.try_into().unwrap();

        let mut buffer = encrypted_key.to_vec();
        let decryptor = Aes128CbcDec::new(&enc_key_arr.into(), &iv_arr.into());

        let decrypted = decryptor
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buffer)
            .map_err(|e| Error::Other(format!("Failed to decrypt key: {}", e)))?;

        Ok(decrypted.to_vec())
    }

    /// Convert a Key ID to a UUID.
    ///
    /// Handles various formats:
    /// - 16 bytes: direct UUID bytes
    /// - 32 bytes: hex-encoded UUID string
    /// - Decimal ASCII bytes: parsed as integer
    /// - Other lengths: padded or truncated to 16 bytes
    pub fn kid_to_uuid(kid: &[u8]) -> Result<Uuid> {
        if kid.is_empty() {
            // Return a nil UUID for empty key IDs
            return Ok(Uuid::nil());
        }

        // Check if the bytes represent a decimal number string
        if let Ok(s) = std::str::from_utf8(kid) {
            if s.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = s.parse::<u128>() {
                    return Ok(Uuid::from_u128(n));
                }
            }
        }

        // 16 bytes - direct UUID bytes
        if kid.len() == 16 {
            return Ok(Uuid::from_slice(kid).unwrap_or_else(|_| Uuid::nil()));
        }

        // 32 bytes - hex encoded
        if kid.len() == 32 {
            if let Ok(s) = std::str::from_utf8(kid) {
                if let Ok(uuid) = Uuid::parse_str(s) {
                    return Ok(uuid);
                }
            }
        }

        // Shorter than 16 bytes - pad with zeros
        if kid.len() < 16 {
            let mut padded = vec![0u8; 16];
            padded[..kid.len()].copy_from_slice(kid);
            return Ok(Uuid::from_slice(&padded).unwrap_or_else(|_| Uuid::nil()));
        }

        // Longer than expected - try to use first 16 bytes
        Ok(Uuid::from_slice(&kid[..16]).unwrap_or_else(|_| Uuid::nil()))
    }
}
