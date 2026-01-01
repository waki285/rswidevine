//! Core Widevine CDM implementation.
//!
//! This module handles session lifecycle, license request/response parsing,
//! privacy certificate handling, and key derivation.
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use aes::Aes128;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use cmac::Cmac;
use hmac::{Hmac, Mac};
use prost::Message;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::rand_core::{OsRng, RngCore};
use rsa::{Oaep, Pss, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::device::{Device, DeviceType};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::license_protocol::license_request::content_identification::ContentIdVariant;
use crate::license_protocol::license_request::content_identification::WidevinePsshData as WidevinePsshDataRequest;
use crate::license_protocol::license_request::RequestType;
use crate::license_protocol::{
    ClientIdentification, DrmCertificate, EncryptedClientIdentification, License, LicenseRequest,
    LicenseType, ProtocolVersion, SignedDrmCertificate, SignedMessage,
};
use crate::pssh::Pssh;
use crate::session::Session;
use crate::utils::get_binary_path;

type HmacSha256 = Hmac<Sha256>;
type CmacAes128 = Cmac<Aes128>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

/// Widevine system UUID.
pub const WIDEVINE_UUID: Uuid = Uuid::from_u128(0xedef8ba979d64acea3c827dcd51d21ed);
/// Widevine URN string.
pub const WIDEVINE_URN: &str = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed";
/// Service certificate challenge payload.
pub const SERVICE_CERTIFICATE_CHALLENGE: &[u8] = b"\x08\x04";

pub const COMMON_PRIVACY_CERT: &str = concat!(
    "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsy",
    "fateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5Up",
    "HVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioY",
    "Hrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+",
    "2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7",
    "c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MI",
    "tHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuNHMUtag1",
    "KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2",
    "oQQ4RgpQO8GVK5uk5M4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2z",
    "NMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnS",
    "q8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3Cq",
    "CLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOdd",
    "eOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMm",
    "MzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWY",
    "YQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="
);

pub const STAGING_PRIVACY_CERT: &str = concat!(
    "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhEr",
    "jQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8MYK3mUbVX9wI3+lUB4Femm",
    "J0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPk",
    "xgJxiJf14e+baq9a1Nuip+FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7t",
    "zY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2",
    "fzPvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5",
    "SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUuY29tEoADmD4wNSZ19A",
    "unFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeE",
    "jMdT/0l7ARp9qXeIoA4qprhM19ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7",
    "jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lex",
    "jOY9Dv1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s",
    "+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocLsjA89wxul4TJPS",
    "3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/L",
    "fGcF96njtvOUA4P5xRFtICogySKe6WnCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8AB",
    "Hg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU"
);

const ROOT_SIGNED_CERT_B64: &str = concat!(
    "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8ud",
    "NI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9",
    "GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SI",
    "QqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG",
    "0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDT",
    "KjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9I",
    "Zbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec",
    "86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufj",
    "UUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI",
    "5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+X",
    "aE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9Td",
    "pvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8",
    "Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9",
    "yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUS",
    "IDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJs",
    "KlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7R",
    "C5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
);

static ROOT_SIGNED_CERT: LazyLock<SignedDrmCertificate> = LazyLock::new(|| {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ROOT_SIGNED_CERT_B64)
        .expect("Invalid root cert base64");
    SignedDrmCertificate::decode(bytes.as_slice()).expect("Invalid root SignedDrmCertificate")
});

static ROOT_CERT: LazyLock<DrmCertificate> = LazyLock::new(|| {
    let cert_bytes = ROOT_SIGNED_CERT
        .drm_certificate
        .as_ref()
        .expect("Missing DRM certificate");
    DrmCertificate::decode(cert_bytes.as_slice()).expect("Invalid root DrmCertificate")
});

static ROOT_PUBLIC_KEY: LazyLock<RsaPublicKey> = LazyLock::new(|| {
    let public_key_bytes = ROOT_CERT
        .public_key
        .as_ref()
        .expect("Missing root public key");
    RsaPublicKey::from_pkcs1_der(public_key_bytes.as_slice()).expect("Invalid root public key")
});

/// Widevine Content Decryption Module (CDM).
#[derive(Debug, Clone)]
pub struct Cdm {
    pub device_type: DeviceType,
    pub system_id: u32,
    pub security_level: u8,
    client_id: ClientIdentification,
    private_key: RsaPrivateKey,
    sessions: HashMap<Vec<u8>, Session>,
}

impl Cdm {
    /// Maximum number of concurrently opened sessions.
    pub const MAX_NUM_OF_SESSIONS: usize = 16;

    /// Create a CDM instance from raw components.
    ///
    /// This is equivalent to constructing a pywidevine `Cdm` with a device type,
    /// system id, security level, client id, and RSA private key.
    pub fn new(
        device_type: DeviceType,
        system_id: u32,
        security_level: u8,
        client_id: ClientIdentification,
        private_key: RsaPrivateKey,
    ) -> Result<Self> {
        Ok(Self {
            device_type,
            system_id,
            security_level,
            client_id,
            private_key,
            sessions: HashMap::new(),
        })
    }

    /// Create a CDM instance from a parsed device.
    pub fn from_device(device: Device) -> Result<Self> {
        Self::new(
            device.device_type,
            device.system_id,
            device.security_level,
            device.client_id,
            device.private_key,
        )
    }

    /// Open a new session and return its session id.
    ///
    /// Returns an error if the maximum number of sessions has been reached.
    pub fn open(&mut self) -> Result<Vec<u8>> {
        if self.sessions.len() > Self::MAX_NUM_OF_SESSIONS {
            return Err(Error::TooManySessions {
                max: Self::MAX_NUM_OF_SESSIONS,
            });
        }

        let session = Session::new(self.sessions.len() as u32 + 1);
        let session_id = session.id.clone();
        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Close a session by id.
    pub fn close(&mut self, session_id: &[u8]) -> Result<()> {
        if self.sessions.remove(session_id).is_none() {
            return Err(Error::InvalidSession(session_id.to_vec()));
        }
        Ok(())
    }

    /// Set or unset the service certificate for a session.
    ///
    /// The certificate must be either:
    /// - A serialized `SignedDrmCertificate`, or
    /// - A serialized `SignedMessage` containing a `SignedDrmCertificate`.
    ///
    /// Unsigned `DrmCertificate` values are rejected. When `certificate` is
    /// `None`, this unsets the current certificate and returns the previous
    /// provider id (if any).
    pub fn set_service_certificate(
        &mut self,
        session_id: &[u8],
        certificate: Option<&[u8]>,
    ) -> Result<Option<String>> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::InvalidSession(session_id.to_vec()))?;

        if certificate.is_none() {
            let provider_id = if let Some(ref signed) = session.service_certificate {
                let cert_bytes = signed
                    .drm_certificate
                    .as_ref()
                    .ok_or_else(|| Error::DecodeError("Missing DRM certificate".to_string()))?;
                let drm_cert = DrmCertificate::decode(cert_bytes.as_slice()).map_err(|e| {
                    Error::DecodeError(format!("Failed to parse DrmCertificate: {}", e))
                })?;
                drm_cert.provider_id.clone()
            } else {
                None
            };
            session.service_certificate = None;
            return Ok(provider_id);
        }

        let certificate = certificate.unwrap();
        let signed_drm_certificate = decode_signed_drm_certificate(certificate)?;

        let drm_certificate_bytes = signed_drm_certificate
            .drm_certificate
            .as_ref()
            .ok_or_else(|| Error::DecodeError("Missing DRM certificate".to_string()))?;
        let drm_certificate = DrmCertificate::decode(drm_certificate_bytes.as_slice())
            .map_err(|e| Error::DecodeError(format!("Failed to parse DrmCertificate: {}", e)))?;

        verify_signed_certificate(&signed_drm_certificate)?;

        session.service_certificate = Some(signed_drm_certificate);
        Ok(drm_certificate.provider_id.clone())
    }

    /// Get the service certificate for a session.
    pub fn get_service_certificate(
        &self,
        session_id: &[u8],
    ) -> Result<Option<SignedDrmCertificate>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| Error::InvalidSession(session_id.to_vec()))?;
        Ok(session.service_certificate.clone())
    }

    /// Build a signed license request for the given PSSH.
    ///
    /// `license_type` must be one of: STREAMING, OFFLINE, AUTOMATIC.
    /// When `privacy_mode` is enabled and a service certificate is set, the
    /// client id is encrypted.
    ///
    /// For Android devices, the request_id is generated in a counter-like form
    /// to match OEMCrypto behavior.
    pub fn get_license_challenge(
        &mut self,
        session_id: &[u8],
        pssh: &Pssh,
        license_type: &str,
        privacy_mode: bool,
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::InvalidSession(session_id.to_vec()))?;

        let license_type_enum = LicenseType::from_str_name(&license_type.to_uppercase())
            .ok_or_else(|| Error::InvalidLicenseType(license_type.to_string()))?;

        let request_id = if self.device_type == DeviceType::Android {
            let mut req = [0u8; 16];
            let mut rng = OsRng;
            rng.fill_bytes(&mut req[..4]);
            // bytes 4..8 remain 0
            let counter = session.number.to_le_bytes();
            req[8..].copy_from_slice(&counter);
            req.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>()
                .into_bytes()
        } else {
            let mut req = vec![0u8; 16];
            let mut rng = OsRng;
            rng.fill_bytes(&mut req);
            req
        };

        let encrypted_client_id = if session.service_certificate.is_some() && privacy_mode {
            Some(Self::encrypt_client_id(
                &self.client_id,
                session.service_certificate.as_ref().expect("checked above"),
                None,
                None,
            )?)
        } else {
            None
        };

        let client_id = if encrypted_client_id.is_some() {
            None
        } else {
            Some(self.client_id.clone())
        };

        let content_id = crate::license_protocol::license_request::ContentIdentification {
            content_id_variant: Some(ContentIdVariant::WidevinePsshData(
                WidevinePsshDataRequest {
                    pssh_data: vec![pssh.init_data.clone()],
                    license_type: Some(license_type_enum as i32),
                    request_id: Some(request_id.clone()),
                },
            )),
        };

        let request_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();

        let license_request = LicenseRequest {
            client_id,
            content_id: Some(content_id),
            r#type: Some(RequestType::New as i32),
            request_time: Some(request_time),
            key_control_nonce_deprecated: None,
            protocol_version: Some(ProtocolVersion::Version21 as i32),
            key_control_nonce: Some(random_u32()),
            encrypted_client_id,
        };

        let license_request_bytes = license_request.encode_to_vec();
        let signature = sign_pss_sha1(&self.private_key, &license_request_bytes)?;

        let signed_message = SignedMessage {
            r#type: Some(
                crate::license_protocol::signed_message::MessageType::LicenseRequest as i32,
            ),
            msg: Some(license_request_bytes.clone()),
            signature: Some(signature),
            session_key: None,
            remote_attestation: None,
            metric_data: Vec::new(),
            service_version_info: None,
            session_key_type: None,
            oemcrypto_core_message: None,
        };

        session
            .context
            .insert(request_id, Self::derive_context(&license_request_bytes));

        Ok(signed_message.encode_to_vec())
    }

    /// Parse a license response and load keys into the session.
    ///
    /// This validates the HMAC signature (including oemcrypto_core_message if
    /// present), derives session keys, and decrypts content keys. Context is
    /// removed after successful parsing. If the session has no context, the
    /// license likely did not originate from this CDM instance.
    pub fn parse_license(&mut self, session_id: &[u8], license_message: &[u8]) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::InvalidSession(session_id.to_vec()))?;

        let signed_message = SignedMessage::decode(license_message).map_err(|e| {
            Error::InvalidLicenseMessage(format!("Failed to parse SignedMessage: {}", e))
        })?;

        if signed_message.r#type
            != Some(crate::license_protocol::signed_message::MessageType::License as i32)
        {
            return Err(Error::InvalidLicenseMessage(
                "Expected LICENSE message".to_string(),
            ));
        }

        let msg_bytes = signed_message
            .msg
            .as_ref()
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing license message".to_string()))?;

        let license = License::decode(msg_bytes.as_slice())
            .map_err(|e| Error::InvalidLicenseMessage(format!("Failed to parse License: {}", e)))?;

        let request_id = license
            .id
            .as_ref()
            .and_then(|id| id.request_id.clone())
            .ok_or_else(|| Error::InvalidContext("Missing request_id".to_string()))?;

        let context = session
            .context
            .get(&request_id)
            .ok_or_else(|| Error::InvalidContext("Missing context".to_string()))?
            .clone();

        let session_key = signed_message
            .session_key
            .as_ref()
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing session_key".to_string()))?;

        let decrypted_session_key = self
            .private_key
            .decrypt(Oaep::new::<Sha1>(), session_key)
            .map_err(Error::RsaError)?;

        let (enc_key, mac_key_server, _) =
            Self::derive_keys(&context.0, &context.1, &decrypted_session_key);

        let mut mac = HmacSha256::new_from_slice(&mac_key_server)
            .map_err(|e| Error::Other(format!("Invalid HMAC key: {}", e)))?;
        if let Some(ref core) = signed_message.oemcrypto_core_message {
            mac.update(core);
        }
        mac.update(msg_bytes);
        let computed = mac.finalize().into_bytes().to_vec();

        let signature = signed_message
            .signature
            .as_ref()
            .ok_or_else(|| Error::InvalidLicenseMessage("Missing signature".to_string()))?;
        if computed != *signature {
            return Err(Error::SignatureMismatch(
                "Signature mismatch on license message".to_string(),
            ));
        }

        let mut keys = Vec::new();
        for key_container in license.key.iter() {
            keys.push(Key::from_key_container(key_container, &enc_key)?);
        }

        session.keys = keys;
        session.context.remove(&request_id);
        Ok(())
    }

    /// Return decrypted keys from a session, optionally filtered by key type.
    ///
    /// When `key_type` is `None` or "ALL", all keys are returned.
    pub fn get_keys(&self, session_id: &[u8], key_type: Option<&str>) -> Result<Vec<Key>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| Error::InvalidSession(session_id.to_vec()))?;

        let filter = if let Some(value) = key_type {
            let normalized = value.to_uppercase();
            if normalized == "ALL" {
                None
            } else {
                Some(normalized)
            }
        } else {
            None
        };

        Ok(session
            .keys
            .iter()
            .filter(|&k| match &filter {
                Some(f) => &k.key_type == f,
                None => true,
            })
            .cloned()
            .collect())
    }

    /// Decrypt a media file using shaka-packager and loaded keys.
    ///
    /// This uses raw key decryption and will include a blank KID variant for
    /// compatibility with some services. Returns the process exit code.
    ///
    /// Errors if input is missing, output exists (unless `exists_ok`), keys are
    /// not loaded, or shaka-packager is not available in PATH.
    pub fn decrypt(
        &self,
        session_id: &[u8],
        input_file: impl AsRef<Path>,
        output_file: impl AsRef<Path>,
        temp_dir: Option<impl AsRef<Path>>,
        exists_ok: bool,
    ) -> Result<i32> {
        let input_file = input_file.as_ref();
        let output_file = output_file.as_ref();
        let temp_dir = temp_dir.as_ref().map(|p| p.as_ref());

        if !input_file.is_file() {
            return Err(Error::Other(format!(
                "Input file does not exist: {}",
                input_file.display()
            )));
        }
        if output_file.exists() && !exists_ok {
            return Err(Error::Other(format!(
                "Output file already exists: {}",
                output_file.display()
            )));
        }

        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| Error::InvalidSession(session_id.to_vec()))?;

        if session.keys.is_empty() {
            return Err(Error::NoKeysLoaded);
        }

        let platform = match std::env::consts::OS {
            "windows" => "win",
            "macos" => "osx",
            other => other,
        };
        let executable = get_binary_path(&[
            "shaka-packager",
            &format!("packager-{}", platform),
            &format!("packager-{}-x64", platform),
        ])
        .ok_or_else(|| Error::Other("Shaka Packager executable not found".to_string()))?;

        let mut key_labels = Vec::new();
        for (i, key) in session.keys.iter().enumerate() {
            if key.key_type == "CONTENT" {
                let kid_hex = key.kid.as_simple().to_string();
                let key_hex = hex::encode(&key.key);
                key_labels.push(format!("label=1_{}:key_id={}:key={}", i, kid_hex, key_hex));
                key_labels.push(format!(
                    "label=2_{}:key_id={}:key={}",
                    i,
                    "0".repeat(32),
                    key_hex
                ));
            }
        }

        let mut args = vec![
            format!(
                "input={},stream=0,output={}",
                input_file.display(),
                output_file.display()
            ),
            "--enable_raw_key_decryption".to_string(),
            "--keys".to_string(),
            key_labels.join(","),
        ];

        if let Some(temp_dir) = temp_dir {
            std::fs::create_dir_all(temp_dir)?;
            args.push("--temp_dir".to_string());
            args.push(temp_dir.display().to_string());
        }

        let status = Command::new(executable)
            .args(args)
            .status()
            .map_err(|e| Error::Other(format!("Failed to run shaka-packager: {}", e)))?;

        Ok(status.code().unwrap_or(1))
    }

    /// Encrypt the client id using a service certificate (privacy mode).
    ///
    /// Uses AES-128-CBC with PKCS#5/7 padding and wraps the privacy key using
    /// RSA-OAEP with the service certificate public key. `key` and `iv` are
    /// optional and default to random 16-byte values.
    pub fn encrypt_client_id(
        client_id: &ClientIdentification,
        service_certificate: &SignedDrmCertificate,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
    ) -> Result<EncryptedClientIdentification> {
        let mut privacy_key = [0u8; 16];
        if let Some(key) = key {
            if key.len() != 16 {
                return Err(Error::Other("Privacy key must be 16 bytes".to_string()));
            }
            privacy_key.copy_from_slice(key);
        } else {
            let mut rng = OsRng;
            rng.fill_bytes(&mut privacy_key);
        }

        let mut privacy_iv = [0u8; 16];
        if let Some(iv) = iv {
            if iv.len() != 16 {
                return Err(Error::Other("Privacy IV must be 16 bytes".to_string()));
            }
            privacy_iv.copy_from_slice(iv);
        } else {
            let mut rng = OsRng;
            rng.fill_bytes(&mut privacy_iv);
        }

        let drm_certificate = DrmCertificate::decode(
            service_certificate
                .drm_certificate
                .as_ref()
                .ok_or_else(|| Error::DecodeError("Missing DRM certificate".to_string()))?
                .as_slice(),
        )
        .map_err(|e| Error::DecodeError(format!("Failed to parse DrmCertificate: {}", e)))?;

        let public_key_bytes = drm_certificate
            .public_key
            .as_ref()
            .ok_or_else(|| Error::DecodeError("Missing public key".to_string()))?;
        let public_key = RsaPublicKey::from_pkcs1_der(public_key_bytes.as_slice())
            .map_err(|e| Error::Other(format!("Failed to parse public key: {}", e)))?;

        let mut buffer = client_id.encode_to_vec();
        let buffer_len = buffer.len();
        let encrypted_client_id = Aes128CbcEnc::new(&privacy_key.into(), &privacy_iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, buffer_len)
            .map_err(|e| Error::Other(format!("Failed to encrypt client_id: {}", e)))?
            .to_vec();

        let mut rng = OsRng;
        let encrypted_privacy_key = public_key
            .encrypt(&mut rng, Oaep::new::<Sha1>(), &privacy_key)
            .map_err(Error::RsaError)?;

        Ok(EncryptedClientIdentification {
            provider_id: drm_certificate.provider_id.clone(),
            service_certificate_serial_number: drm_certificate.serial_number.clone(),
            encrypted_client_id: Some(encrypted_client_id),
            encrypted_client_id_iv: Some(privacy_iv.to_vec()),
            encrypted_privacy_key: Some(encrypted_privacy_key),
        })
    }

    /// Derive encryption and MAC context from a message.
    ///
    /// Context format follows Widevine's ENCRYPTION/AUTHENTICATION labels.
    #[must_use]
    pub fn derive_context(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn enc_context(msg: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(11 + msg.len() + 4);
            out.extend_from_slice(b"ENCRYPTION");
            out.push(0);
            out.extend_from_slice(msg);
            out.extend_from_slice(&(16u32 * 8).to_be_bytes());
            out
        }

        fn mac_context(msg: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(14 + msg.len() + 4);
            out.extend_from_slice(b"AUTHENTICATION");
            out.push(0);
            out.extend_from_slice(msg);
            out.extend_from_slice(&(32u32 * 8 * 2).to_be_bytes());
            out
        }

        (enc_context(message), mac_context(message))
    }

    /// Derive encryption and MAC keys from context and base key.
    ///
    /// Returns (enc_key, mac_key_server, mac_key_client) using AES-CMAC over
    /// the context data.
    #[must_use]
    pub fn derive_keys(
        enc_context: &[u8],
        mac_context: &[u8],
        key: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        fn derive(session_key: &[u8], context: &[u8], counter: u8) -> Vec<u8> {
            let mut mac = CmacAes128::new_from_slice(session_key).expect("CMAC key length invalid");
            mac.update(&[counter]);
            mac.update(context);
            mac.finalize().into_bytes().to_vec()
        }

        let enc_key = derive(key, enc_context, 1);
        let mut mac_key_server = derive(key, mac_context, 1);
        mac_key_server.extend_from_slice(&derive(key, mac_context, 2));
        let mut mac_key_client = derive(key, mac_context, 3);
        mac_key_client.extend_from_slice(&derive(key, mac_context, 4));
        (enc_key, mac_key_server, mac_key_client)
    }
}

fn sign_pss_sha1(private_key: &RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    let hash = Sha1::digest(message);
    let mut rng = OsRng;
    let signature = private_key
        .sign_with_rng(&mut rng, Pss::new::<Sha1>(), &hash)
        .map_err(Error::RsaError)?;
    Ok(signature)
}

#[must_use]
fn random_u32() -> u32 {
    let mut rng = OsRng;
    let mut buf = [0u8; 4];
    rng.fill_bytes(&mut buf);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::Cdm;

    #[test]
    fn derive_context_contains_labels() {
        let message = b"test-message";
        let (enc, mac) = Cdm::derive_context(message);

        assert!(enc.starts_with(b"ENCRYPTION"));
        assert!(mac.starts_with(b"AUTHENTICATION"));
        assert!(enc.windows(message.len()).any(|w| w == message));
        assert!(mac.windows(message.len()).any(|w| w == message));
    }

    #[test]
    fn derive_keys_lengths() {
        let message = b"context";
        let (enc_ctx, mac_ctx) = Cdm::derive_context(message);
        let key = [0u8; 16];
        let (enc_key, mac_server, mac_client) = Cdm::derive_keys(&enc_ctx, &mac_ctx, &key);

        assert_eq!(enc_key.len(), 16);
        assert_eq!(mac_server.len(), 32);
        assert_eq!(mac_client.len(), 32);
    }
}

fn decode_signed_drm_certificate(data: &[u8]) -> Result<SignedDrmCertificate> {
    let signed_message = SignedMessage::decode(data);
    if let Ok(signed_message) = signed_message {
        let signed_message_bytes = signed_message.encode_to_vec();
        if !signed_message_bytes.is_empty()
            && data.len().is_multiple_of(signed_message_bytes.len())
            && data
                .chunks(signed_message_bytes.len())
                .all(|c| c == signed_message_bytes)
        {
            let msg_bytes = signed_message
                .msg
                .ok_or_else(|| Error::DecodeError("SignedMessage missing msg".to_string()))?;
            return SignedDrmCertificate::decode(msg_bytes.as_slice()).map_err(|e| {
                Error::DecodeError(format!("Failed to parse SignedDrmCertificate: {}", e))
            });
        }
    }

    SignedDrmCertificate::decode(data)
        .map_err(|e| Error::DecodeError(format!("Failed to parse SignedDrmCertificate: {}", e)))
}

fn verify_signed_certificate(cert: &SignedDrmCertificate) -> Result<()> {
    let cert_bytes = cert
        .drm_certificate
        .as_ref()
        .ok_or_else(|| Error::DecodeError("Missing DRM certificate".to_string()))?;
    let signature = cert
        .signature
        .as_ref()
        .ok_or_else(|| Error::DecodeError("Missing certificate signature".to_string()))?;

    let hash = Sha1::digest(cert_bytes);
    ROOT_PUBLIC_KEY
        .verify(Pss::new::<Sha1>(), &hash, signature)
        .map_err(|_| Error::SignatureMismatch("Signature mismatch on certificate".to_string()))
}
