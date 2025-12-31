//! HTTP serve API compatible with pywidevine's serve schema.
//!
//! Endpoints:
//! - `GET /` ping.
//! - `GET /{device}/open`
//! - `GET /{device}/close/{session_id}`
//! - `POST /{device}/set_service_certificate`
//! - `POST /{device}/get_service_certificate`
//! - `POST /{device}/get_license_challenge/{license_type}`
//! - `POST /{device}/parse_license`
//! - `POST /{device}/get_keys/{key_type}`
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use base64::Engine;
use prost::Message;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::cdm::Cdm;
use crate::device::Device;
use crate::error::{Error, Result};
use crate::pssh::Pssh;

/// Server configuration loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct ServeConfig {
    /// List of device file paths available to the server.
    pub devices: Vec<String>,
    /// Map of secret key to user access configuration.
    pub users: HashMap<String, ServeUser>,
    /// Enforce privacy mode (requires service certificate).
    #[serde(default)]
    pub force_privacy_mode: bool,
}

/// Per-user access configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServeUser {
    /// Optional display name used in logs.
    pub username: Option<String>,
    /// Device names the user is allowed to access (by file stem).
    pub devices: Vec<String>,
}

#[derive(Clone)]
struct ServeState {
    config: ServeConfig,
    devices: HashMap<String, PathBuf>,
    cdms: Arc<Mutex<HashMap<(String, String), Cdm>>>,
}

/// Start the serve HTTP API.
///
/// The API surface matches pywidevine's serve schema and is intended to be
/// consumed by RemoteCdm clients.
pub async fn run(config: ServeConfig, host: &str, port: u16) -> Result<()> {
    let devices = build_device_map(&config.devices)?;
    let state = ServeState {
        config,
        devices,
        cdms: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = axum::Router::new()
        .route("/", get(ping))
        .route("/:device/open", get(open))
        .route("/:device/close/:session_id", get(close))
        .route("/:device/set_service_certificate", post(set_service_certificate))
        .route("/:device/get_service_certificate", post(get_service_certificate))
        .route("/:device/get_license_challenge/:license_type", post(get_license_challenge))
        .route("/:device/parse_license", post(parse_license))
        .route("/:device/get_keys/:key_type", post(get_keys))
        .with_state(state);

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| Error::Other(format!("Server bind error: {}", e)))?;
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| Error::Other(format!("Server error: {}", e)))?;
    Ok(())
}

async fn ping() -> Response {
    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": "Pong!"
        })),
    )
}

async fn open(
    AxumPath(device): AxumPath<String>,
    State(state): State<ServeState>,
    headers: HeaderMap,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    let device_path = match state.devices.get(&device) {
        Some(path) => path.clone(),
        None => {
            return json_response(
                StatusCode::FORBIDDEN,
                Json(json!({
                    "status": 403,
                    "message": format!("Device '{}' is not found or you are not authorized to use it.", device)
                })),
            )
        }
    };

    let mut cdms = state.cdms.lock().await;
    if !cdms.contains_key(&(secret.clone(), device.clone())) {
        match Device::from_path(device_path) {
            Ok(device_data) => match Cdm::from_device(device_data) {
                Ok(cdm) => {
                    cdms.insert((secret.clone(), device.clone()), cdm);
                }
                Err(e) => {
                    return json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "status": 500,
                            "message": e.to_string()
                        })),
                    )
                }
            },
            Err(e) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "status": 500,
                        "message": e.to_string()
                    })),
                )
            }
        }
    }

    let cdm = cdms
        .get_mut(&(secret.clone(), device.clone()))
        .expect("CDM should exist");

    let session_id = match cdm.open() {
        Ok(id) => id,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": e.to_string()
                })),
            )
        }
    };

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": "Success",
            "data": {
                "session_id": hex::encode(session_id),
                "device": {
                    "system_id": cdm.system_id,
                    "security_level": cdm.security_level,
                }
            }
        })),
    )
}

async fn close(
    AxumPath((device, session_id)): AxumPath<(String, String)>,
    State(state): State<ServeState>,
    headers: HeaderMap,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    let session_id = match hex::decode(session_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid session id"
                })),
            )
        }
    };

    let mut cdms = state.cdms.lock().await;
    let cdm = match cdms.get_mut(&(secret, device.clone())) {
        Some(cdm) => cdm,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("No Cdm session for {} has been opened yet. No session to close.", device)
                })),
            )
        }
    };

    if let Err(_) = cdm.close(&session_id) {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": format!("Invalid Session ID '{}', it may have expired.", hex::encode(&session_id))
            })),
        );
    }

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": format!("Successfully closed Session '{}'.", hex::encode(&session_id))
        })),
    )
}

#[derive(Debug, Deserialize)]
struct ServiceCertRequest {
    session_id: String,
    certificate: Option<String>,
}

async fn set_service_certificate(
    AxumPath(device): AxumPath<String>,
    State(state): State<ServeState>,
    headers: HeaderMap,
    Json(body): Json<ServiceCertRequest>,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    if body.session_id.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": "Missing required field 'session_id' in JSON body."
            })),
        );
    }

    let session_id = match hex::decode(&body.session_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid session id"
                })),
            )
        }
    };

    let certificate_bytes = match body.certificate {
        Some(ref cert) => match base64::engine::general_purpose::STANDARD.decode(cert) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "status": 400,
                        "message": "Invalid certificate data"
                    })),
                )
            }
        },
        None => None,
    };

    let mut cdms = state.cdms.lock().await;
    let cdm = match cdms.get_mut(&(secret, device.clone())) {
        Some(cdm) => cdm,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("No Cdm session for {} has been opened yet. No session to use.", device)
                })),
            )
        }
    };

    let provider_id = match cdm.set_service_certificate(&session_id, certificate_bytes.as_deref()) {
        Ok(id) => id,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": e.to_string()
                })),
            )
        }
    };

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": format!("Successfully {} the Service Certificate.", if certificate_bytes.is_some() { "set" } else { "unset" }),
            "data": {
                "provider_id": provider_id
            }
        })),
    )
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    session_id: String,
}

async fn get_service_certificate(
    AxumPath(device): AxumPath<String>,
    State(state): State<ServeState>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    if body.session_id.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": "Missing required field 'session_id' in JSON body."
            })),
        );
    }

    let session_id = match hex::decode(&body.session_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid session id"
                })),
            )
        }
    };

    let cdms = state.cdms.lock().await;
    let cdm = match cdms.get(&(secret, device.clone())) {
        Some(cdm) => cdm,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("No Cdm session for {} has been opened yet. No session to use.", device)
                })),
            )
        }
    };

    let service_certificate = match cdm.get_service_certificate(&session_id) {
        Ok(cert) => cert,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("Invalid Session ID '{}', it may have expired.", body.session_id)
                })),
            )
        }
    };

    let service_certificate_b64 = service_certificate
        .map(|cert| base64::engine::general_purpose::STANDARD.encode(cert.encode_to_vec()));

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": "Successfully got the Service Certificate.",
            "data": {
                "service_certificate": service_certificate_b64
            }
        })),
    )
}

#[derive(Debug, Deserialize)]
struct LicenseChallengeRequest {
    session_id: String,
    init_data: String,
    privacy_mode: Option<bool>,
}

async fn get_license_challenge(
    AxumPath((device, license_type)): AxumPath<(String, String)>,
    State(state): State<ServeState>,
    headers: HeaderMap,
    Json(body): Json<LicenseChallengeRequest>,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    if body.session_id.is_empty() || body.init_data.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": "Missing required fields in JSON body."
            })),
        );
    }

    let session_id = match hex::decode(&body.session_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid session id"
                })),
            )
        }
    };

    let privacy_mode = body.privacy_mode.unwrap_or(true);

    let mut cdms = state.cdms.lock().await;
    let cdm = match cdms.get_mut(&(secret, device.clone())) {
        Some(cdm) => cdm,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("No Cdm session for {} has been opened yet. No session to use.", device)
                })),
            )
        }
    };

    if state.config.force_privacy_mode {
        if cdm.get_service_certificate(&session_id).ok().flatten().is_none() {
            return json_response(
                StatusCode::FORBIDDEN,
                Json(json!({
                    "status": 403,
                    "message": "No Service Certificate set but Privacy Mode is Enforced."
                })),
            );
        }
    }

    let pssh = match Pssh::from_base64(&body.init_data) {
        Ok(pssh) => pssh,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("Invalid Init Data, {}", e)
                })),
            )
        }
    };

    let challenge = match cdm.get_license_challenge(&session_id, &pssh, &license_type, privacy_mode) {
        Ok(challenge) => challenge,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": e.to_string()
                })),
            )
        }
    };

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": "Success",
            "data": {
                "challenge_b64": base64::engine::general_purpose::STANDARD.encode(challenge)
            }
        })),
    )
}

#[derive(Debug, Deserialize)]
struct ParseLicenseRequest {
    session_id: String,
    license_message: String,
}

async fn parse_license(
    AxumPath(device): AxumPath<String>,
    State(state): State<ServeState>,
    headers: HeaderMap,
    Json(body): Json<ParseLicenseRequest>,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    if body.session_id.is_empty() || body.license_message.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": "Missing required fields in JSON body."
            })),
        );
    }

    let session_id = match hex::decode(&body.session_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid session id"
                })),
            )
        }
    };

    let license_message = match base64::engine::general_purpose::STANDARD.decode(&body.license_message) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid license message"
                })),
            )
        }
    };

    let mut cdms = state.cdms.lock().await;
    let cdm = match cdms.get_mut(&(secret, device.clone())) {
        Some(cdm) => cdm,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("No Cdm session for {} has been opened yet. No session to use.", device)
                })),
            )
        }
    };

    if let Err(e) = cdm.parse_license(&session_id, &license_message) {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": format!("Invalid License Message, {}", e)
            })),
        );
    }

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": "Successfully parsed and loaded the Keys from the License message."
        })),
    )
}

async fn get_keys(
    AxumPath((device, key_type)): AxumPath<(String, String)>,
    State(state): State<ServeState>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> Response {
    let secret = match authorize(&state, &device, &headers) {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };

    if body.session_id.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "message": "Missing required field 'session_id' in JSON body."
            })),
        );
    }

    let session_id = match hex::decode(&body.session_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": "Invalid session id"
                })),
            )
        }
    };

    let mut cdms = state.cdms.lock().await;
    let cdm = match cdms.get_mut(&(secret, device.clone())) {
        Some(cdm) => cdm,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("No Cdm session for {} has been opened yet. No session to use.", device)
                })),
            )
        }
    };

    let key_type = if key_type == "ALL" { None } else { Some(key_type.as_str()) };
    let keys = match cdm.get_keys(&session_id, key_type) {
        Ok(keys) => keys,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": 400,
                    "message": format!("The Key Type value '{}' is invalid, {}", key_type.unwrap_or("ALL"), e)
                })),
            )
        }
    };

    let keys_json = keys
        .into_iter()
        .map(|key| {
            json!({
                "key_id": key.kid.as_simple().to_string(),
                "key": hex::encode(key.key),
                "type": key.key_type,
                "permissions": key.permissions,
            })
        })
        .collect::<Vec<_>>();

    json_response(
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "message": "Success",
            "data": {
                "keys": keys_json
            }
        })),
    )
}

fn authorize(state: &ServeState, device: &str, headers: &HeaderMap) -> std::result::Result<String, Response> {
    let secret = headers.get("X-Secret-Key").and_then(|v| v.to_str().ok());
    if secret.is_none() {
        return Err(json_response(
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "status": 401,
                "message": "Secret Key is Empty."
            })),
        ));
    }
    let secret = secret.unwrap().to_string();

    let user = match state.config.users.get(&secret) {
        Some(user) => user,
        None => {
            return Err(json_response(
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": 401,
                    "message": "Secret Key is Invalid, the Key is case-sensitive."
                })),
            ))
        }
    };

    if !user.devices.iter().any(|d| d == device) {
        return Err(json_response(
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": 403,
                "message": format!("Device '{}' is not found or you are not authorized to use it.", device)
            })),
        ));
    }

    Ok(secret)
}

fn json_response(status: StatusCode, body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    *response.status_mut() = status;
    response.headers_mut().insert(
        "Server",
        HeaderValue::from_static(concat!(
            "https://github.com/devine-dl/pywidevine serve v",
            env!("CARGO_PKG_VERSION")
        )),
    );
    response
}

fn build_device_map(devices: &[String]) -> Result<HashMap<String, PathBuf>> {
    let mut map = HashMap::new();
    for device in devices {
        let path = PathBuf::from(device);
        if !path.is_file() {
            return Err(Error::Other(format!("Device file does not exist: {}", device)));
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::Other("Invalid device filename".to_string()))?
            .to_string();
        map.insert(name, path);
    }
    Ok(map)
}
