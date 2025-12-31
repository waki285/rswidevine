//! Remote CDM client for pywidevine serve-compatible APIs.
use base64::Engine;
use prost::Message;
use reqwest::blocking::Client;
use serde::Deserialize;
use uuid::Uuid;

use crate::device::{Device, DeviceType};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::license_protocol::SignedDrmCertificate;
use crate::pssh::Pssh;

/// Remote-accessible CDM wrapper.
#[derive(Debug)]
pub struct RemoteCdm {
    /// Device type the remote server should match.
    pub device_type: DeviceType,
    /// Expected Widevine system id.
    pub system_id: u32,
    /// Expected security level.
    pub security_level: u8,
    host: String,
    device_name: String,
    client: Client,
}

impl RemoteCdm {
    /// Create a new RemoteCdm client and verify server version.
    ///
    /// The server must advertise a `pywidevine serve vX.Y.Z` header and the
    /// version must be >= 1.4.3.
    pub fn new(
        device_type: DeviceType,
        system_id: u32,
        security_level: u8,
        host: impl Into<String>,
        secret: impl AsRef<str>,
        device_name: impl Into<String>,
    ) -> Result<Self> {
        let host = host.into();
        let device_name = device_name.into();

        let client = Client::builder()
            .user_agent("rswidevine")
            .build()
            .map_err(|e| Error::Other(format!("Failed to build HTTP client: {}", e)))?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-Secret-Key",
            reqwest::header::HeaderValue::from_str(secret.as_ref())
                .map_err(|e| Error::Other(format!("Invalid secret key: {}", e)))?,
        );

        let response = client
            .head(&host)
            .headers(headers.clone())
            .send()
            .map_err(|e| Error::Other(format!("Failed to contact server: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Server did not respond successfully: {}",
                response.status()
            )));
        }

        if let Some(server_header) = response.headers().get("Server") {
            if let Ok(server_str) = server_header.to_str() {
                let server_lower = server_str.to_lowercase();
                let marker = "pywidevine serve v";
                if !server_lower.contains(marker) {
                    return Err(Error::Other(format!(
                        "Remote API does not appear to be pywidevine serve ({})",
                        server_str
                    )));
                }
                if let Some(version) = extract_version(&server_lower, marker) {
                    if !version_at_least(&version, "1.4.3") {
                        return Err(Error::Other(format!(
                            "Remote API version {} is not supported",
                            version
                        )));
                    }
                }
            }
        }

        Ok(Self {
            device_type,
            system_id,
            security_level,
            host,
            device_name,
            client,
        })
    }

    /// Remote CDM cannot be created from a local device.
    pub fn from_device(_device: Device) -> Result<Self> {
        Err(Error::Other(
            "RemoteCdm cannot be created from a local Device".to_string(),
        ))
    }

    /// Open a remote session and return session id.
    pub fn open(&self, secret: &str) -> Result<Vec<u8>> {
        let response: ApiResponse<OpenResponse> = self
            .client
            .get(format!("{}/{}/open", self.host, self.device_name))
            .header("X-Secret-Key", secret)
            .send()
            .map_err(|e| Error::Other(format!("Failed to open session: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(format!(
                "Cannot open session: {}",
                response.message
            )));
        }

        let data = response
            .data
            .ok_or_else(|| Error::Other("Missing response data".to_string()))?;
        if data.device.system_id != self.system_id
            || data.device.security_level != self.security_level
        {
            return Err(Error::DeviceMismatch(
                "Device metadata mismatch".to_string(),
            ));
        }

        let session_id = hex::decode(data.session_id)
            .map_err(|e| Error::Other(format!("Invalid session id: {}", e)))?;
        Ok(session_id)
    }

    /// Close a remote session.
    pub fn close(&self, secret: &str, session_id: &[u8]) -> Result<()> {
        let response: ApiResponse<serde_json::Value> = self
            .client
            .get(format!(
                "{}/{}/close/{}",
                self.host,
                self.device_name,
                hex::encode(session_id)
            ))
            .header("X-Secret-Key", secret)
            .send()
            .map_err(|e| Error::Other(format!("Failed to close session: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(response.message));
        }
        Ok(())
    }

    /// Set or unset the service certificate for a remote session.
    pub fn set_service_certificate(
        &self,
        secret: &str,
        session_id: &[u8],
        certificate: Option<&[u8]>,
    ) -> Result<String> {
        let certificate_b64 =
            certificate.map(|c| base64::engine::general_purpose::STANDARD.encode(c));
        let response: ApiResponse<ProviderResponse> = self
            .client
            .post(format!(
                "{}/{}/set_service_certificate",
                self.host, self.device_name
            ))
            .header("X-Secret-Key", secret)
            .json(&serde_json::json!({
                "session_id": hex::encode(session_id),
                "certificate": certificate_b64,
            }))
            .send()
            .map_err(|e| Error::Other(format!("Failed to set service certificate: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(response.message));
        }
        let data = response
            .data
            .ok_or_else(|| Error::Other("Missing response data".to_string()))?;
        Ok(data.provider_id)
    }

    /// Get the current service certificate for a remote session.
    pub fn get_service_certificate(
        &self,
        secret: &str,
        session_id: &[u8],
    ) -> Result<Option<SignedDrmCertificate>> {
        let response: ApiResponse<ServiceCertResponse> = self
            .client
            .post(format!(
                "{}/{}/get_service_certificate",
                self.host, self.device_name
            ))
            .header("X-Secret-Key", secret)
            .json(&serde_json::json!({
                "session_id": hex::encode(session_id),
            }))
            .send()
            .map_err(|e| Error::Other(format!("Failed to get service certificate: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(response.message));
        }

        let data = response
            .data
            .ok_or_else(|| Error::Other("Missing response data".to_string()))?;
        if let Some(cert_b64) = data.service_certificate {
            let cert_bytes = base64::engine::general_purpose::STANDARD
                .decode(cert_b64)
                .map_err(Error::Base64DecodeError)?;
            let cert = SignedDrmCertificate::decode(cert_bytes.as_slice()).map_err(|e| {
                Error::DecodeError(format!("Failed to parse SignedDrmCertificate: {}", e))
            })?;
            Ok(Some(cert))
        } else {
            Ok(None)
        }
    }

    /// Request a license challenge from the remote server.
    ///
    /// `license_type` should match Widevine LicenseType strings.
    pub fn get_license_challenge(
        &self,
        secret: &str,
        session_id: &[u8],
        pssh: &Pssh,
        license_type: &str,
        privacy_mode: bool,
    ) -> Result<Vec<u8>> {
        let response: ApiResponse<ChallengeResponse> = self
            .client
            .post(format!(
                "{}/{}/get_license_challenge/{}",
                self.host, self.device_name, license_type
            ))
            .header("X-Secret-Key", secret)
            .json(&serde_json::json!({
                "session_id": hex::encode(session_id),
                "init_data": pssh.to_base64(),
                "privacy_mode": privacy_mode,
            }))
            .send()
            .map_err(|e| Error::Other(format!("Failed to get license challenge: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(response.message));
        }
        let data = response
            .data
            .ok_or_else(|| Error::Other("Missing response data".to_string()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data.challenge_b64)
            .map_err(Error::Base64DecodeError)?;
        Ok(bytes)
    }

    /// Submit a license response to the remote server.
    pub fn parse_license(
        &self,
        secret: &str,
        session_id: &[u8],
        license_message: &[u8],
    ) -> Result<()> {
        let response: ApiResponse<serde_json::Value> = self
            .client
            .post(format!("{}/{}/parse_license", self.host, self.device_name))
            .header("X-Secret-Key", secret)
            .json(&serde_json::json!({
                "session_id": hex::encode(session_id),
                "license_message": base64::engine::general_purpose::STANDARD.encode(license_message),
            }))
            .send()
            .map_err(|e| Error::Other(format!("Failed to parse license: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(response.message));
        }
        Ok(())
    }

    /// Fetch decrypted keys from the remote server.
    pub fn get_keys(
        &self,
        secret: &str,
        session_id: &[u8],
        key_type: Option<&str>,
    ) -> Result<Vec<Key>> {
        let key_type = key_type.unwrap_or("ALL");
        let response: ApiResponse<KeysResponse> = self
            .client
            .post(format!(
                "{}/{}/get_keys/{}",
                self.host, self.device_name, key_type
            ))
            .header("X-Secret-Key", secret)
            .json(&serde_json::json!({
                "session_id": hex::encode(session_id),
            }))
            .send()
            .map_err(|e| Error::Other(format!("Failed to get keys: {}", e)))?
            .json()
            .map_err(|e| Error::Other(format!("Invalid response: {}", e)))?;

        if response.status != 200 {
            return Err(Error::Other(response.message));
        }
        let data = response
            .data
            .ok_or_else(|| Error::Other("Missing response data".to_string()))?;

        let keys = data
            .keys
            .into_iter()
            .map(|k| Key {
                key_type: k.r#type,
                kid: Key::kid_to_uuid(&hex::decode(k.key_id).unwrap_or_default())
                    .unwrap_or_else(|_| Uuid::nil()),
                key: hex::decode(k.key).unwrap_or_default(),
                permissions: k.permissions,
            })
            .collect();

        Ok(keys)
    }
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    status: i32,
    message: String,
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct OpenResponse {
    session_id: String,
    device: DeviceInfo,
}

#[derive(Debug, Deserialize)]
struct DeviceInfo {
    system_id: u32,
    security_level: u8,
}

#[derive(Debug, Deserialize)]
struct ProviderResponse {
    provider_id: String,
}

#[derive(Debug, Deserialize)]
struct ServiceCertResponse {
    service_certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    challenge_b64: String,
}

#[derive(Debug, Deserialize)]
struct KeysResponse {
    keys: Vec<KeyResponse>,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    key_id: String,
    key: String,
    r#type: String,
    permissions: Vec<String>,
}

fn extract_version(server: &str, marker: &str) -> Option<String> {
    server
        .find(marker)
        .map(|idx| server[idx + marker.len()..].trim().to_string())
}

fn version_at_least(version: &str, minimum: &str) -> bool {
    let parse = |v: &str| {
        v.split('.')
            .filter_map(|s| s.parse::<u32>().ok())
            .collect::<Vec<_>>()
    };
    let v = parse(version);
    let m = parse(minimum);
    for i in 0..m.len().max(v.len()) {
        let a = *v.get(i).unwrap_or(&0);
        let b = *m.get(i).unwrap_or(&0);
        if a > b {
            return true;
        } else if a < b {
            return false;
        }
    }
    true
}
