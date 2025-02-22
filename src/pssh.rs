use prost::Message;
use uuid::Uuid;

use crate::rswidevine_license_protocol::WidevinePsshData;

enum SystemId {
    Widevine,
    PlayReady,
}

impl SystemId {
    pub fn to_uuid(&self) -> Uuid {
        match self {
            SystemId::Widevine => Uuid::from_u128(0xedef8ba979d64acea3c827dcd51d21ed),
            SystemId::PlayReady => Uuid::from_u128(0x9a04f07998404286ab92e65be0885f95),
        }
    }
}

/// MP4 PSSH Box-related utilities.
/// Allows you to load, create, and modify various kinds of DRM system headers.
pub struct PSSH {
    
}

impl PSSH {
    /// Load a PSSH box, WidevineCencHeader, or PlayReadyHeader.
    ///
    /// When loading a WidevineCencHeader or PlayReadyHeader, a new v0 PSSH box will be
    /// created and the header will be parsed and stored in the init_data field. However,
    /// PlayReadyHeaders (and PlayReadyObjects) are not yet currently parsed and are
    /// stored as bytes.
    ///
    /// # Strict mode (strict=True)
    ///
    /// Supports the following forms of input data in either Base64 or Bytes form:
    /// - Full PSSH mp4 boxes (as defined by pymp4 Box).
    /// - Full Widevine Cenc Headers (as defined by WidevinePsshData proto).
    /// - Full PlayReady Objects and Headers (as defined by Microsoft Docs).
    ///
    /// # Lenient mode (strict=False, default)
    ///
    /// If the data is not supported in Strict mode, and is assumed not to be corrupt or
    /// parsed incorrectly, the License Server likely accepts a custom init_data value
    /// during a License Request call. This is uncommon behavior but not out of realm of
    /// possibilities. For example, Netflix does this with its MSL WidevineExchange
    /// scheme.
    ///
    /// Lenient mode will craft a new v0 PSSH box with the init_data field set to
    /// the provided data as-is. The data will first be base64 decoded. This behavior
    /// may not work in your scenario and if that's the case please manually craft
    /// your own PSSH box with the init_data field to be used in License Requests.
    ///
    /// # Raises
    ///
    /// - `ValueError`: If the data is empty.
    /// - `TypeError`: If the data is an unexpected type.
    /// - `binascii.Error`: If the data could not be decoded as Base64 if provided as a
    ///   string.
    /// - `DecodeError`: If the data could not be parsed as a PSSH mp4 box nor a Widevine
    ///   Cenc Header and strict mode is enabled.
    fn inner_new() -> Self {
        Self {
            
        }
    }

    /// Craft a new version 0 or 1 PSSH Box.
    pub fn new(
        system_id: Uuid,
        key_ids: Option<Vec<Uuid>>,
        init_data: Option<WidevinePsshData>,
        version: Option<u8>,
        flags: Option<u32>,
    ) -> anyhow::Result<Self> {
        let version = version.unwrap_or(0);
        let flags = flags.unwrap_or(0);

        if version != 0 && version != 1 {
            return Err(anyhow::anyhow!("Invalid version, must be either 0 or 1, got {}", version));
        }

        if version == 0 && !key_ids.is_none() && !init_data.is_none() {
            // v0 boxes use only init_data in the pssh field, but we can use the key_ids within the init_data
            return Err(anyhow::anyhow!("Version 0 PSSH boxes must use only init_data, not init_data and key_ids."));
        } else if version == 1 {
            // TODO: I cannot tell if they need either init_data or key_ids exclusively, or both is fine
            // So for now I will just make sure at least one is supplied
            if init_data.is_none() && key_ids.is_none() {
                return Err(anyhow::anyhow!("Version 1 PSSH boxes must use either init_data or key_ids but neither were provided"));
            }
        }

        let mut buf = None;
        if let Some(init_data) = init_data {
            buf = Some(init_data.encode_to_vec());
        }

        Ok(PSSH::inner_new())
    }
}