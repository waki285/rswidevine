//! Device module for handling Widevine Device (.wvd) files.
//!
//! The device file contains the RSA private key and ClientIdentification blob
//! required to authenticate CDM sessions. v2 stores VMP data inside the
//! ClientIdentification message. v1 stored VMP data separately; when parsing
//! v1 the VMP is merged into the ClientIdentification if missing.

use std::io::Write;
use std::path::Path;

use prost::Message;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

use crate::error::{Error, Result};
use crate::license_protocol::{ClientIdentification, DrmCertificate, FileHashes, SignedDrmCertificate};

/// Magic bytes for WVD files.
const WVD_MAGIC: &[u8; 3] = b"WVD";

/// Current supported WVD version.
const WVD_VERSION: u8 = 2;

/// Device types supported by Widevine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceType {
    /// Chrome CDM device.
    Chrome = 1,
    /// Android CDM device.
    Android = 2,
}

impl TryFrom<u8> for DeviceType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(DeviceType::Chrome),
            2 => Ok(DeviceType::Android),
            _ => Err(Error::InvalidWvdFile(format!(
                "Invalid device type: {}",
                value
            ))),
        }
    }
}

impl From<DeviceType> for u8 {
    fn from(device_type: DeviceType) -> Self {
        device_type as u8
    }
}

/// Widevine Device containing key material and client identification.
///
/// This struct is the Rust equivalent of pywidevine's `Device` and is the
/// primary source of CDM credentials. The system id is extracted from the DRM
/// certificate embedded in the ClientIdentification token.
#[derive(Debug)]
pub struct Device {
    /// Device type (Chrome or Android).
    pub device_type: DeviceType,
    /// Security level (1-3, where 1 is highest).
    pub security_level: u8,
    /// Device flags (reserved for future use).
    pub flags: u8,
    /// RSA private key for signing.
    pub private_key: RsaPrivateKey,
    /// Client identification blob.
    pub client_id: ClientIdentification,
    /// Verified Media Path (VMP) data.
    pub vmp: Option<FileHashes>,
    /// System ID extracted from the DRM certificate.
    pub system_id: u32,
}

impl Device {
    /// Create a new Device from components.
    ///
    /// This validates the ClientIdentification, parses VMP data (if present),
    /// and extracts the system id from the signed DRM certificate.
    pub fn new(
        device_type: DeviceType,
        security_level: u8,
        flags: u8,
        private_key: RsaPrivateKey,
        client_id: ClientIdentification,
    ) -> Result<Self> {
        // Parse VMP from client_id if present
        let vmp = match client_id.vmp_data.as_ref() {
            Some(data) if !data.is_empty() => {
                let vmp = FileHashes::decode(data.as_slice())?;
                Some(vmp)
            }
            _ => None,
        };

        // Extract system_id from DRM certificate
        let token = client_id
            .token
            .as_ref()
            .ok_or_else(|| Error::InvalidWvdFile("Client ID token missing".to_string()))?;

        let signed_drm_cert = SignedDrmCertificate::decode(token.as_slice())
            .map_err(|e| Error::DecodeError(format!("Failed to parse SignedDrmCertificate: {}", e)))?;

        let drm_cert_bytes = signed_drm_cert
            .drm_certificate
            .as_ref()
            .ok_or_else(|| Error::InvalidWvdFile("DRM certificate missing".to_string()))?;

        let drm_cert = DrmCertificate::decode(drm_cert_bytes.as_slice())
            .map_err(|e| Error::DecodeError(format!("Failed to parse DrmCertificate: {}", e)))?;

        let system_id = drm_cert
            .system_id
            .ok_or_else(|| Error::InvalidWvdFile("System ID missing".to_string()))?;

        Ok(Self {
            device_type,
            security_level,
            flags,
            private_key,
            client_id,
            vmp,
            system_id,
        })
    }

    /// Load a Device from a WVD file path.
    ///
    /// This supports v1 and v2 WVD formats. v1 VMP data will be merged into the
    /// ClientIdentification if it was not already present.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Load a Device from WVD bytes.
    ///
    /// Input must be the raw WVD binary data. If you have base64, decode it
    /// before calling this method.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::parse_v2(data)
    }


    /// Parse a v2 WVD file.
    ///
    /// v2 stores VMP data inside the ClientIdentification blob.
    fn parse_v2(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::InvalidWvdFile("Data too short".to_string()));
        }

        // Check magic
        if &data[0..3] != WVD_MAGIC {
            return Err(Error::InvalidWvdFile("Invalid magic bytes".to_string()));
        }

        // Check version
        let version = data[3];
        if version != WVD_VERSION {
            if version == 1 {
                return Self::parse_v1(data);
            }
            return Err(Error::InvalidWvdFile(format!(
                "Unsupported version: {}",
                version
            )));
        }

        let mut offset = 4;

        // Device type
        let device_type = DeviceType::try_from(data[offset])?;
        offset += 1;

        // Security level
        let security_level = data[offset];
        offset += 1;

        // Flags (1 byte, padded)
        let flags = data[offset];
        offset += 1;

        // Private key length (2 bytes, big endian)
        if offset + 2 > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for private key length".to_string()));
        }
        let private_key_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Private key
        if offset + private_key_len > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for private key".to_string()));
        }
        let private_key_der = &data[offset..offset + private_key_len];
        offset += private_key_len;

        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(private_key_der))
            .map_err(|e| Error::InvalidWvdFile(format!("Failed to parse RSA key: {}", e)))?;

        // Client ID length (2 bytes, big endian)
        if offset + 2 > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for client ID length".to_string()));
        }
        let client_id_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Client ID
        if offset + client_id_len > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for client ID".to_string()));
        }
        let client_id_bytes = &data[offset..offset + client_id_len];

        let client_id = ClientIdentification::decode(client_id_bytes)
            .map_err(|e| Error::DecodeError(format!("Failed to parse ClientIdentification: {}", e)))?;

        Self::new(device_type, security_level, flags, private_key, client_id)
    }

    /// Parse a v1 WVD file and migrate to v2.
    ///
    /// v1 stored VMP data separately; this method merges it into the
    /// ClientIdentification if missing.
    fn parse_v1(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::InvalidWvdFile("Data too short".to_string()));
        }

        // Check magic and version
        if &data[0..3] != WVD_MAGIC || data[3] != 1 {
            return Err(Error::InvalidWvdFile("Invalid v1 format".to_string()));
        }

        let mut offset = 4;

        // Device type
        let device_type = DeviceType::try_from(data[offset])?;
        offset += 1;

        // Security level
        let security_level = data[offset];
        offset += 1;

        // Flags (1 byte, padded)
        let flags = data[offset];
        offset += 1;

        // Private key length (2 bytes, big endian)
        if offset + 2 > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for private key length".to_string()));
        }
        let private_key_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Private key
        if offset + private_key_len > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for private key".to_string()));
        }
        let private_key_der = &data[offset..offset + private_key_len];
        offset += private_key_len;

        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(private_key_der))
            .map_err(|e| Error::InvalidWvdFile(format!("Failed to parse RSA key: {}", e)))?;

        // Client ID length (2 bytes, big endian)
        if offset + 2 > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for client ID length".to_string()));
        }
        let client_id_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Client ID
        if offset + client_id_len > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for client ID".to_string()));
        }
        let client_id_bytes = &data[offset..offset + client_id_len];
        offset += client_id_len;

        // VMP length (2 bytes, big endian) - v1 specific
        if offset + 2 > data.len() {
            return Err(Error::InvalidWvdFile("Data too short for VMP length".to_string()));
        }
        let vmp_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // VMP data - v1 specific
        let mut client_id = ClientIdentification::decode(client_id_bytes)
            .map_err(|e| Error::DecodeError(format!("Failed to parse ClientIdentification: {}", e)))?;

        // If VMP data exists in v1, merge it into client_id
        if vmp_len > 0 && offset + vmp_len <= data.len() {
            let vmp_bytes = &data[offset..offset + vmp_len];
            let has_vmp = client_id.vmp_data.as_ref().map_or(false, |d| !d.is_empty());
            if !has_vmp {
                client_id.vmp_data = Some(vmp_bytes.to_vec());
            }
        }

        Self::new(device_type, security_level, flags, private_key, client_id)
    }

    /// Serialize the Device to WVD v2 bytes.
    ///
    /// v1 output is not supported; VMP data should already be stored inside
    /// the ClientIdentification.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let private_key_der = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&self.private_key)
            .map_err(|e| Error::Other(format!("Failed to encode RSA key: {}", e)))?;
        let private_key_bytes = private_key_der.as_bytes();

        let client_id_bytes = self.client_id.encode_to_vec();

        let mut buf = Vec::new();

        // Magic
        buf.write_all(WVD_MAGIC)?;

        // Version
        buf.write_all(&[WVD_VERSION])?;

        // Device type
        buf.write_all(&[self.device_type.into()])?;

        // Security level
        buf.write_all(&[self.security_level])?;

        // Flags
        buf.write_all(&[self.flags])?;

        // Private key length
        let private_key_len = private_key_bytes.len() as u16;
        buf.write_all(&private_key_len.to_be_bytes())?;

        // Private key
        buf.write_all(private_key_bytes)?;

        // Client ID length
        let client_id_len = client_id_bytes.len() as u16;
        buf.write_all(&client_id_len.to_be_bytes())?;

        // Client ID
        buf.write_all(&client_id_bytes)?;

        Ok(buf)
    }

    /// Save the Device to a WVD file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let data = self.to_bytes()?;
        std::fs::write(path, data)?;
        Ok(())
    }
}
