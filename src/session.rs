//! Session module for managing Widevine CDM sessions.
//!
//! Each session stores request context and decrypted keys loaded from a license.

use std::collections::HashMap;

use rsa::rand_core::{OsRng, RngCore};

use crate::key::Key;
use crate::license_protocol::SignedDrmCertificate;

/// A Widevine CDM session.
///
/// Session ids are randomly generated 16-byte values. The `context` map
/// associates request_id to the derived encryption and MAC contexts.
#[derive(Debug)]
pub struct Session {
    /// Session number (1-indexed).
    pub number: u32,
    /// Unique session identifier (16 random bytes).
    pub id: Vec<u8>,
    /// Service certificate for privacy mode.
    pub service_certificate: Option<SignedDrmCertificate>,
    /// Context data: maps request_id to (enc_context, mac_context).
    pub context: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,
    /// Decrypted keys from the license.
    pub keys: Vec<Key>,
}

impl Session {
    /// Create a new session with the given session number.
    pub fn new(number: u32) -> Self {
        let mut id = vec![0u8; 16];
        let mut rng = OsRng;
        rng.fill_bytes(&mut id);

        Self {
            number,
            id,
            service_certificate: None,
            context: HashMap::new(),
            keys: Vec::new(),
        }
    }
}
