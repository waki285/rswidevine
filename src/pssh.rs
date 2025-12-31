//! PSSH parsing and conversion utilities.
//!
//! Supports Widevine PSSH and optional PlayReady conversion via feature flag.
use std::str::FromStr;

use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
#[cfg(feature = "playready")]
use byteorder::LittleEndian;
use prost::Message;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::license_protocol::WidevinePsshData;

/// Known DRM system IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemId {
    Widevine,
    PlayReady,
}

impl SystemId {
    pub fn to_uuid(self) -> Uuid {
        match self {
            SystemId::Widevine => Uuid::from_u128(0xedef8ba979d64acea3c827dcd51d21ed),
            SystemId::PlayReady => Uuid::from_u128(0x9a04f07998404286ab92e65be0885f95),
        }
    }
}

/// Parsed PSSH box or DRM init data wrapper.
#[derive(Debug, Clone)]
pub struct Pssh {
    pub version: u8,
    pub flags: u32,
    pub system_id: Uuid,
    key_ids: Vec<Uuid>,
    pub init_data: Vec<u8>,
}

impl Pssh {
    /// Parse from bytes in lenient mode (strict = false).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::parse_bytes(data, false)
    }

    /// Parse from bytes in strict mode.
    pub fn from_bytes_strict(data: &[u8]) -> Result<Self> {
        Self::parse_bytes(data, true)
    }

    /// Parse from base64 in lenient mode (strict = false).
    pub fn from_base64(data_b64: &str) -> Result<Self> {
        Self::parse_base64(data_b64, false)
    }

    /// Parse from base64 in strict mode.
    pub fn from_base64_strict(data_b64: &str) -> Result<Self> {
        Self::parse_base64(data_b64, true)
    }

    /// Parse a PSSH box or init data from raw bytes.
    ///
    /// Strict mode supports:
    /// - Full PSSH boxes.
    /// - Widevine CencHeader (WidevinePsshData).
    /// - PlayReady headers (detected by UTF-16 `</WRMHEADER>`).
    ///
    /// Lenient mode (strict = false) wraps unknown input as a v0 Widevine PSSH
    /// with init_data set to the provided bytes.
    pub fn parse_bytes(data: &[u8], strict: bool) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidInitData("Data must not be empty".to_string()));
        }

        if let Ok(pssh) = parse_pssh_box(data) {
            return Ok(pssh);
        }

        if let Ok(pssh) = parse_widevine_pssh_data(data) {
            return Ok(pssh);
        }

        if contains_playready_header(data) {
            return Ok(Pssh::new(
                SystemId::PlayReady.to_uuid(),
                None,
                Some(data.to_vec()),
                0,
                0,
            )?);
        }

        if strict {
            return Err(Error::InvalidInitData(
                "Could not parse data as PSSH or Widevine PSSH Data".to_string(),
            ));
        }

        Pssh::new(SystemId::Widevine.to_uuid(), None, Some(data.to_vec()), 0, 0)
    }

    /// Parse a PSSH box or init data from base64.
    ///
    /// See [`Pssh::parse_bytes`] for strict/lenient behavior.
    pub fn parse_base64(data_b64: &str, strict: bool) -> Result<Self> {
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(Error::Base64DecodeError)?;
        Self::parse_bytes(&data, strict)
    }

    /// Create a new PSSH box wrapper.
    ///
    /// Version 0 uses only init_data. Version 1 requires init_data or key_ids.
    pub fn new(
        system_id: Uuid,
        key_ids: Option<Vec<Uuid>>,
        init_data: Option<Vec<u8>>,
        version: u8,
        flags: u32,
    ) -> Result<Self> {
        if version != 0 && version != 1 {
            return Err(Error::InvalidInitData(format!(
                "Invalid version: {}",
                version
            )));
        }

        if version == 0 && key_ids.is_some() && init_data.is_some() {
            return Err(Error::InvalidInitData(
                "Version 0 PSSH boxes must use only init_data".to_string(),
            ));
        }

        if version == 1 && key_ids.is_none() && init_data.is_none() {
            return Err(Error::InvalidInitData(
                "Version 1 PSSH boxes must use init_data or key_ids".to_string(),
            ));
        }

        Ok(Self {
            version,
            flags,
            system_id,
            key_ids: key_ids.unwrap_or_default(),
            init_data: init_data.unwrap_or_default(),
        })
    }

    /// Serialize as a full PSSH box.
    pub fn to_bytes(&self) -> Vec<u8> {
        build_pssh_box(self)
    }

    /// Serialize as a base64 PSSH box.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.to_bytes())
    }

    /// Extract KIDs from box/init data where possible.
    ///
    /// Supports:
    /// - v1 PSSH boxes (key_IDs field).
    /// - Widevine CencHeader (WidevinePsshData).
    /// - PlayReady headers (versions 4.0.0.0 - 4.3.0.0).
    pub fn key_ids(&self) -> Result<Vec<Uuid>> {
        if self.version == 1 && !self.key_ids.is_empty() {
            return Ok(self.key_ids.clone());
        }

        if self.system_id == SystemId::Widevine.to_uuid() {
            let pssh_data = WidevinePsshData::decode(self.init_data.as_slice())
                .map_err(|e| Error::DecodeError(format!("Failed to parse WidevinePsshData: {}", e)))?;

            let mut ids = Vec::new();
            for key_id in pssh_data.key_ids.iter() {
                ids.push(parse_key_id_bytes(key_id));
            }
            return Ok(ids);
        }

        if self.system_id == SystemId::PlayReady.to_uuid() {
            return parse_playready_key_ids(&self.init_data);
        }

        Err(Error::InvalidInitData(
            "Unsupported system ID for key_ids".to_string(),
        ))
    }

    /// Convert PlayReady init data to Widevine PSSH.
    pub fn to_widevine(&mut self) -> Result<()> {
        if self.system_id == SystemId::Widevine.to_uuid() {
            return Err(Error::InvalidInitData("Already Widevine".to_string()));
        }

        let key_ids = self.key_ids()?;
        let pssh_data = WidevinePsshData {
            key_ids: key_ids.iter().map(|id| id.as_bytes().to_vec()).collect(),
            ..Default::default()
        };

        if self.version == 1 {
            self.key_ids = key_ids;
        }

        self.init_data = pssh_data.encode_to_vec();
        self.system_id = SystemId::Widevine.to_uuid();
        Ok(())
    }

    #[cfg(feature = "playready")]
    /// Convert Widevine init data to PlayReady v4.3.0.0 format.
    ///
    /// Note: PlayReady CHECKSUM values cannot be generated without the content
    /// keys, so the output may be incompatible with some clients.
    pub fn to_playready(
        &mut self,
        la_url: Option<&str>,
        lui_url: Option<&str>,
        ds_id: Option<&[u8]>,
        decryptor_setup: Option<&str>,
        custom_data: Option<&str>,
    ) -> Result<()> {
        if self.system_id == SystemId::PlayReady.to_uuid() {
            return Err(Error::InvalidInitData("Already PlayReady".to_string()));
        }

        let key_ids = self.key_ids()?;
        let mut key_ids_xml = String::new();
        for key_id in key_ids.iter() {
            key_ids_xml.push_str(&format!(
                r#"<KID ALGID="AESCTR" VALUE="{}"></KID>"#,
                base64::engine::general_purpose::STANDARD.encode(key_id.as_bytes())
            ));
        }

        let prr_value = format!(
            r#"<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.3.0.0"><DATA><PROTECTINFO><KIDS>{}</KIDS></PROTECTINFO>{}{}{}</DATA></WRMHEADER>"#,
            key_ids_xml,
            la_url.map(|v| format!("<LA_URL>{}</LA_URL>", v)).unwrap_or_default(),
            lui_url.map(|v| format!("<LUI_URL>{}</LUI_URL>", v)).unwrap_or_default(),
            {
                let mut extra = String::new();
                if let Some(ds_id) = ds_id {
                    extra.push_str(&format!(
                        "<DS_ID>{}</DS_ID>",
                        base64::engine::general_purpose::STANDARD.encode(ds_id)
                    ));
                }
                if let Some(decryptor_setup) = decryptor_setup {
                    extra.push_str(&format!("<DECRYPTORSETUP>{}</DECRYPTORSETUP>", decryptor_setup));
                }
                if let Some(custom_data) = custom_data {
                    extra.push_str(&format!(r#"<CUSTOMATTRIBUTES xmlns="">{}</CUSTOMATTRIBUTES>"#, custom_data));
                }
                extra
            }
        )
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect::<Vec<u8>>();

        let prr_length = (prr_value.len() as u16).to_le_bytes();
        let prr_type = (1u16).to_le_bytes();
        let pro_record_count = (1u16).to_le_bytes();
        let mut pro = Vec::new();
        pro.extend_from_slice(&pro_record_count);
        pro.extend_from_slice(&prr_type);
        pro.extend_from_slice(&prr_length);
        pro.extend_from_slice(&prr_value);
        let total_length = (pro.len() as u32 + 4).to_le_bytes();
        let mut pro_full = Vec::new();
        pro_full.extend_from_slice(&total_length);
        pro_full.extend_from_slice(&pro);

        self.init_data = pro_full;
        self.system_id = SystemId::PlayReady.to_uuid();
        Ok(())
    }

    #[cfg(not(feature = "playready"))]
    pub fn to_playready(
        &mut self,
        _la_url: Option<&str>,
        _lui_url: Option<&str>,
        _ds_id: Option<&[u8]>,
        _decryptor_setup: Option<&str>,
        _custom_data: Option<&str>,
    ) -> Result<()> {
        Err(Error::InvalidInitData(
            "playready feature is disabled".to_string(),
        ))
    }

    /// Replace KIDs in the init data and box (Widevine only).
    pub fn set_key_ids(&mut self, key_ids: &[Uuid]) -> Result<()> {
        if self.system_id != SystemId::Widevine.to_uuid() {
            return Err(Error::InvalidInitData(
                "Only Widevine PSSH boxes support key id updates".to_string(),
            ));
        }

        if self.version == 1 || !self.key_ids.is_empty() {
            self.key_ids = key_ids.to_vec();
        }

        let mut pssh_data = WidevinePsshData::decode(self.init_data.as_slice())
            .map_err(|e| Error::DecodeError(format!("Failed to parse WidevinePsshData: {}", e)))?;
        pssh_data.key_ids = key_ids.iter().map(|id| id.as_bytes().to_vec()).collect();
        self.init_data = pssh_data.encode_to_vec();
        Ok(())
    }
}

impl FromStr for Pssh {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Pssh::parse_base64(s, false)
    }
}

fn parse_pssh_box(data: &[u8]) -> Result<Pssh> {
    if data.len() < 8 {
        return Err(Error::InvalidInitData("Data too short".to_string()));
    }

    let mut offset = 0;
    let size = BigEndian::read_u32(&data[offset..offset + 4]) as usize;
    offset += 4;
    let box_type = &data[offset..offset + 4];
    offset += 4;

    if box_type != b"pssh" {
        return Err(Error::InvalidInitData("Not a PSSH box".to_string()));
    }

    let mut actual_size = size;
    if size == 1 {
        if data.len() < 16 {
            return Err(Error::InvalidInitData("Data too short".to_string()));
        }
        actual_size = BigEndian::read_u64(&data[offset..offset + 8]) as usize;
        offset += 8;
    } else if size == 0 {
        actual_size = data.len();
    }

    if actual_size > data.len() {
        return Err(Error::InvalidInitData("PSSH size exceeds data length".to_string()));
    }

    if data.len() < offset + 4 + 16 {
        return Err(Error::InvalidInitData("PSSH header incomplete".to_string()));
    }

    let version = data[offset];
    let flags = ((data[offset + 1] as u32) << 16)
        | ((data[offset + 2] as u32) << 8)
        | (data[offset + 3] as u32);
    offset += 4;

    let system_id = Uuid::from_slice(&data[offset..offset + 16])
        .map_err(|_| Error::InvalidInitData("Invalid system ID".to_string()))?;
    offset += 16;

    let mut key_ids = Vec::new();
    if version == 1 {
        if data.len() < offset + 4 {
            return Err(Error::InvalidInitData("Missing KID count".to_string()));
        }
        let kid_count = BigEndian::read_u32(&data[offset..offset + 4]) as usize;
        offset += 4;

        let required = offset + kid_count * 16;
        if data.len() < required {
            return Err(Error::InvalidInitData("Missing KIDs".to_string()));
        }
        for i in 0..kid_count {
            let start = offset + i * 16;
            let end = start + 16;
            key_ids.push(Uuid::from_slice(&data[start..end]).unwrap_or_else(|_| Uuid::nil()));
        }
        offset = required;
    }

    if data.len() < offset + 4 {
        return Err(Error::InvalidInitData("Missing init data length".to_string()));
    }
    let data_size = BigEndian::read_u32(&data[offset..offset + 4]) as usize;
    offset += 4;
    if data.len() < offset + data_size {
        return Err(Error::InvalidInitData("Missing init data".to_string()));
    }
    let init_data = data[offset..offset + data_size].to_vec();

    Ok(Pssh {
        version,
        flags,
        system_id,
        key_ids,
        init_data,
    })
}

fn build_pssh_box(pssh: &Pssh) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(pssh.version);
    body.extend_from_slice(&[
        ((pssh.flags >> 16) & 0xFF) as u8,
        ((pssh.flags >> 8) & 0xFF) as u8,
        (pssh.flags & 0xFF) as u8,
    ]);
    body.extend_from_slice(pssh.system_id.as_bytes());

    if pssh.version == 1 {
        body.extend_from_slice(&(pssh.key_ids.len() as u32).to_be_bytes());
        for kid in pssh.key_ids.iter() {
            body.extend_from_slice(kid.as_bytes());
        }
    }

    body.extend_from_slice(&(pssh.init_data.len() as u32).to_be_bytes());
    body.extend_from_slice(&pssh.init_data);

    let size = (body.len() + 8) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(b"pssh");
    out.extend_from_slice(&body);
    out
}

fn parse_widevine_pssh_data(data: &[u8]) -> Result<Pssh> {
    let pssh_data = WidevinePsshData::decode(data)
        .map_err(|e| Error::DecodeError(format!("Failed to parse WidevinePsshData: {}", e)))?;
    let encoded = pssh_data.encode_to_vec();
    if encoded != data {
        return Err(Error::InvalidInitData("Partial WidevinePsshData parse".to_string()));
    }

    Pssh::new(
        SystemId::Widevine.to_uuid(),
        None,
        Some(encoded),
        0,
        0,
    )
}

fn contains_playready_header(data: &[u8]) -> bool {
    let marker = "</WRMHEADER>".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
    data.windows(marker.len()).any(|window| window == marker)
}

fn parse_key_id_bytes(key_id: &[u8]) -> Uuid {
    if key_id.len() == 16 {
        return Uuid::from_slice(key_id).unwrap_or_else(|_| Uuid::nil());
    }

    if key_id.len() == 32 {
        if let Ok(s) = std::str::from_utf8(key_id) {
            if let Ok(uuid) = Uuid::parse_str(s) {
                return uuid;
            }
        }
    }

    let mut buf = [0u8; 16];
    if key_id.len() >= 16 {
        buf.copy_from_slice(&key_id[key_id.len() - 16..]);
    } else {
        buf[16 - key_id.len()..].copy_from_slice(key_id);
    }
    Uuid::from_bytes(buf)
}

#[cfg(feature = "playready")]
fn parse_playready_key_ids(data: &[u8]) -> Result<Vec<Uuid>> {
    if data.len() < 6 {
        return Err(Error::InvalidInitData("PlayReady data too short".to_string()));
    }

    let total_length = LittleEndian::read_u32(&data[0..4]) as usize;
    if total_length != data.len() {
        return Err(Error::InvalidInitData(
            "PlayReady object length mismatch".to_string(),
        ));
    }

    let record_count = LittleEndian::read_u16(&data[4..6]) as usize;
    let mut offset = 6;

    for _ in 0..record_count {
        if data.len() < offset + 4 {
            return Err(Error::InvalidInitData("PlayReady record truncated".to_string()));
        }
        let record_type = LittleEndian::read_u16(&data[offset..offset + 2]);
        let record_length = LittleEndian::read_u16(&data[offset + 2..offset + 4]) as usize;
        offset += 4;

        if data.len() < offset + record_length {
            return Err(Error::InvalidInitData("PlayReady record truncated".to_string()));
        }
        let record_data = &data[offset..offset + record_length];
        offset += record_length;

        if record_type != 0x01 {
            continue;
        }

        let xml = String::from_utf16(
            &record_data
                .chunks_exact(2)
                .map(|c| LittleEndian::read_u16(c))
                .collect::<Vec<u16>>(),
        )
        .map_err(|_| Error::InvalidInitData("Invalid PlayReady XML".to_string()))?;

        let doc = roxmltree::Document::parse(&xml)
            .map_err(|e| Error::InvalidInitData(format!("PlayReady XML parse error: {}", e)))?;

        let root = doc.root_element();
        let version = root
            .attribute("version")
            .ok_or_else(|| Error::InvalidInitData("Missing PlayReady version".to_string()))?;

        let mut key_ids = Vec::new();
        match version {
            "4.0.0.0" => {
                for node in root
                    .descendants()
                    .filter(|n| n.tag_name().name() == "KID" && n.text().is_some())
                {
                    let text = node.text().unwrap();
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(text)
                        .map_err(Error::Base64DecodeError)?;
                    key_ids.push(Uuid::from_slice(&bytes).unwrap_or_else(|_| Uuid::nil()));
                }
            }
            "4.1.0.0" => {
                for node in root.descendants().filter(|n| n.tag_name().name() == "KID") {
                    if let Some(value) = node.attribute("VALUE") {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .map_err(Error::Base64DecodeError)?;
                        key_ids.push(Uuid::from_slice(&bytes).unwrap_or_else(|_| Uuid::nil()));
                    }
                }
            }
            "4.2.0.0" | "4.3.0.0" => {
                for node in root.descendants().filter(|n| n.tag_name().name() == "KID") {
                    if let Some(value) = node.attribute("VALUE") {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .map_err(Error::Base64DecodeError)?;
                        key_ids.push(Uuid::from_slice(&bytes).unwrap_or_else(|_| Uuid::nil()));
                    }
                }
            }
            _ => {
                return Err(Error::InvalidInitData(format!(
                    "Unsupported PlayReady version {}",
                    version
                )));
            }
        }

        if key_ids.is_empty() {
            return Err(Error::InvalidInitData(
                "No PlayReady KIDs found".to_string(),
            ));
        }

        return Ok(key_ids);
    }

    Err(Error::InvalidInitData(
        "Unsupported PlayReady object".to_string(),
    ))
}

#[cfg(not(feature = "playready"))]
fn parse_playready_key_ids(_data: &[u8]) -> Result<Vec<Uuid>> {
    Err(Error::InvalidInitData(
        "playready feature is disabled".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{Pssh, SystemId};
    use prost::Message;
    use uuid::Uuid;

    use crate::license_protocol::WidevinePsshData;

    #[test]
    fn pssh_roundtrip_bytes_v0() {
        let init_data = b"example-init-data".to_vec();
        let pssh = Pssh::new(SystemId::Widevine.to_uuid(), None, Some(init_data.clone()), 0, 0)
            .expect("create pssh");

        let bytes = pssh.to_bytes();
        let parsed = Pssh::from_bytes(&bytes).expect("parse pssh");

        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.system_id, SystemId::Widevine.to_uuid());
        assert_eq!(parsed.init_data, init_data);
    }

    #[test]
    fn pssh_roundtrip_base64() {
        let init_data = b"base64-init".to_vec();
        let pssh = Pssh::new(SystemId::Widevine.to_uuid(), None, Some(init_data), 0, 0)
            .expect("create pssh");

        let b64 = pssh.to_base64();
        let parsed = Pssh::from_base64(&b64).expect("parse base64");
        assert_eq!(parsed.system_id, SystemId::Widevine.to_uuid());
    }

    #[test]
    fn pssh_key_ids_from_widevine_init_data() {
        let kid = Uuid::new_v4();
        let pssh_data = WidevinePsshData {
            key_ids: vec![kid.as_bytes().to_vec()],
            ..Default::default()
        };
        let init_data = pssh_data.encode_to_vec();
        let pssh = Pssh::new(SystemId::Widevine.to_uuid(), None, Some(init_data), 0, 0)
            .expect("create pssh");

        let ids = pssh.key_ids().expect("key ids");
        assert_eq!(ids, vec![kid]);
    }

    #[test]
    fn pssh_key_ids_from_v1_box() {
        let kid = Uuid::new_v4();
        let pssh = Pssh::new(SystemId::Widevine.to_uuid(), Some(vec![kid]), None, 1, 0)
            .expect("create pssh");

        let bytes = pssh.to_bytes();
        let parsed = Pssh::from_bytes(&bytes).expect("parse pssh");
        let ids = parsed.key_ids().expect("key ids");
        assert_eq!(ids, vec![kid]);
    }

    #[test]
    fn pssh_empty_base64_is_error() {
        let err = Pssh::from_base64("").expect_err("empty input should fail");
        let msg = format!("{}", err);
        assert!(msg.contains("empty"));
    }

    #[cfg(feature = "playready")]
    #[test]
    fn playready_roundtrip_key_ids() {
        let kid = Uuid::new_v4();
        let pssh_data = WidevinePsshData {
            key_ids: vec![kid.as_bytes().to_vec()],
            ..Default::default()
        };
        let init_data = pssh_data.encode_to_vec();
        let mut pssh = Pssh::new(SystemId::Widevine.to_uuid(), None, Some(init_data), 0, 0)
            .expect("create pssh");

        pssh.to_playready(None, None, None, None, None)
            .expect("to_playready");

        assert_eq!(pssh.system_id, SystemId::PlayReady.to_uuid());
        let ids = pssh.key_ids().expect("key ids");
        assert_eq!(ids, vec![kid]);
    }
}
