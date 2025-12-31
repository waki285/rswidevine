#![cfg(feature = "cli")]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use clap::{ArgAction, Parser, Subcommand};
use prost::Message;
use serde::Serialize;

use rswidevine::cdm::Cdm;
use rswidevine::device::{Device, DeviceType};
use rswidevine::license_protocol::client_identification::client_capabilities::{
    AnalogOutputCapabilities, CertificateKeyType, HdcpVersion,
};
use rswidevine::license_protocol::client_identification::ClientCapabilities;
use rswidevine::license_protocol::ClientIdentification;
use rswidevine::pssh::Pssh;

#[cfg(feature = "chrono")]
use chrono::Datelike;

use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use tracing::{error, info, warn, Level};

#[derive(Parser)]
#[command(name = "rswidevine", version, disable_version_flag = true, about = "rswidevine CLI")]
struct Cli {
    #[arg(short = 'v', long = "version", action = ArgAction::SetTrue)]
    version: bool,

    #[arg(short = 'd', long = "debug", action = ArgAction::SetTrue)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// CLI subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Make a license request for a PSSH using a device.
    ///
    /// Expects a license server that accepts the raw challenge bytes and returns
    /// the raw license bytes. For service-specific workflows, implement your
    /// own request flow using the library API.
    License {
        device_path: PathBuf,
        pssh: String,
        server: String,
        #[arg(short = 't', long = "type", default_value = "STREAMING")]
        license_type: String,
        #[arg(short = 'p', long = "privacy", action = ArgAction::SetTrue)]
        privacy: bool,
    },
    /// Test the CDM against Bitmovin's public example.
    ///
    /// Uses a fixed PSSH and the cwip-shaka-proxy license server.
    Test {
        device: PathBuf,
        #[arg(short = 'p', long = "privacy", action = ArgAction::SetTrue)]
        privacy: bool,
    },
    /// Create a WVD device file from a private key and ClientIdentification.
    CreateDevice {
        #[arg(short = 't', long = "type")]
        type_: String,
        #[arg(short = 'l', long = "level")]
        level: u8,
        #[arg(short = 'k', long = "key")]
        key: PathBuf,
        #[arg(short = 'c', long = "client_id")]
        client_id: PathBuf,
        #[arg(short = 'v', long = "vmp")]
        vmp: Option<PathBuf>,
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
    /// Export a WVD file to PEM/DER key, client_id.bin, and optional vmp.bin.
    ExportDevice {
        wvd_path: PathBuf,
        #[arg(short = 'o', long = "out_dir")]
        out_dir: Option<PathBuf>,
    },
    /// Migrate older WVD files to the latest v2 format.
    Migrate {
        path: PathBuf,
    },
    #[cfg(feature = "serve")]
    /// Serve local devices and CDM sessions over HTTP.
    Serve {
        config_path: PathBuf,
        #[arg(short = 'h', long = "host", default_value = "127.0.0.1")]
        host: String,
        #[arg(short = 'p', long = "port", default_value = "8786")]
        port: u16,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level = if cli.debug {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    let current_year = current_year();
    let copyright_years = format!("2024-{}", current_year);
    let version = env!("CARGO_PKG_VERSION");

    info!(
        "rswidevine version {} Copyright (c) {} waki285 (Original: rlaphoenix)",
        version,
        copyright_years
    );
    info!("https://github.com/waki285/rswidevine");

    if cli.version {
        return Ok(());
    }

    match cli.command {
        Some(Commands::License {
            device_path,
            pssh,
            server,
            license_type,
            privacy,
        }) => run_license(&device_path, &pssh, &server, &license_type, privacy),
        Some(Commands::Test { device, privacy }) => run_test(&device, privacy),
        Some(Commands::CreateDevice {
            type_,
            level,
            key,
            client_id,
            vmp,
            output,
        }) => run_create_device(&type_, level, &key, &client_id, vmp.as_deref(), output.as_deref()),
        Some(Commands::ExportDevice { wvd_path, out_dir }) => {
            run_export_device(&wvd_path, out_dir.as_deref())
        }
        Some(Commands::Migrate { path }) => run_migrate(&path),
        #[cfg(feature = "serve")]
        Some(Commands::Serve {
            config_path,
            host,
            port,
        }) => run_serve(&config_path, &host, port),
        None => Ok(()),
    }
}

fn current_year() -> i64 {
    #[cfg(feature = "chrono")]
    {
        chrono::Local::now().year().into()
    }
    #[cfg(not(feature = "chrono"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 31_536_000 + 1970)
            .unwrap_or(2024) as i64
    }
}

fn run_license(
    device_path: &Path,
    pssh_str: &str,
    server: &str,
    license_type: &str,
    privacy: bool,
) -> anyhow::Result<()> {
    let device = Device::from_path(device_path).context("Failed to load device")?;
    info!("[+] Loaded Device ({} L{})", device.system_id, device.security_level);

    let mut cdm = Cdm::from_device(device)?;
    info!("[+] Loaded CDM");

    let session_id = cdm.open()?;
    info!("[+] Opened CDM Session: {}", hex::encode(&session_id));

    if privacy {
        let client = reqwest::blocking::Client::new();
        let response = client
            .post(server)
            .body(rswidevine::cdm::SERVICE_CERTIFICATE_CHALLENGE)
            .send()
            .context("Failed to request service certificate")?;
        if !response.status().is_success() {
            error!(
                "[-] Failed to get Service Privacy Certificate: [{}] {}",
                response.status(),
                response.text().unwrap_or_default()
            );
            return Ok(());
        }
        let cert_bytes = response.bytes().context("Failed to read certificate")?;
        let provider_id = cdm.set_service_certificate(&session_id, Some(&cert_bytes))?;
        info!(
            "[+] Set Service Privacy Certificate: {}",
            provider_id.unwrap_or_default()
        );
    }

    let pssh = Pssh::from_str(pssh_str)?;
    let challenge = cdm.get_license_challenge(&session_id, &pssh, license_type, true)?;
    info!("[+] Created License Request Message (Challenge)");

    let client = reqwest::blocking::Client::new();
    let license_res = client
        .post(server)
        .body(challenge)
        .send()
        .context("Failed to send challenge")?;
    if !license_res.status().is_success() {
        error!(
            "[-] Failed to send challenge: [{}] {}",
            license_res.status(),
            license_res.text().unwrap_or_default()
        );
        return Ok(());
    }
    let license_bytes = license_res.bytes().context("Failed to read license")?;
    info!("[+] Got License Message");

    cdm.parse_license(&session_id, &license_bytes)?;
    info!("[+] License Parsed Successfully");

    for key in cdm.get_keys(&session_id, None)? {
        info!("[{}] {}:{}", key.key_type, key.kid.as_simple(), hex::encode(key.key));
    }

    cdm.close(&session_id)?;
    Ok(())
}

fn run_test(device: &Path, privacy: bool) -> anyhow::Result<()> {
    let pssh = "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==";
    let license_server = "https://cwip-shaka-proxy.appspot.com/no_auth";
    run_license(device, pssh, license_server, "STREAMING", privacy)
}

fn run_create_device(
    type_: &str,
    level: u8,
    key: &Path,
    client_id_path: &Path,
    vmp: Option<&Path>,
    output: Option<&Path>,
) -> anyhow::Result<()> {
    let device_type = parse_device_type(type_)?;
    let private_key = load_private_key(key)?;

    let client_id_bytes = std::fs::read(client_id_path).context("Failed to read client_id")?;
    let client_id = ClientIdentification::decode(client_id_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse ClientIdentification: {}", e))?;

    let mut client_id = ensure_full_parse(client_id, &client_id_bytes)?;
    if let Some(vmp_path) = vmp {
        let vmp_bytes = std::fs::read(vmp_path).context("Failed to read vmp")?;
        if client_id.vmp_data.is_some() {
            warn!("Client ID already has Verified Media Path data");
        }
        client_id.vmp_data = Some(vmp_bytes);
    }

    let device = Device::new(device_type, level, 0, private_key, client_id)?;
    let wvd_bin = device.to_bytes()?;

    let client_info = client_info_map(&device.client_id);
    let company = client_info.get("company_name").cloned().unwrap_or_else(|| "widevine".to_string());
    let model = client_info.get("model_name").cloned().unwrap_or_else(|| "device".to_string());
    let mut name = format!("{} {}", company, model);
    if let Some(version) = client_info.get("widevine_cdm_version") {
        name.push(' ');
        name.push_str(version);
    }
    let crc = crc32fast::hash(&wvd_bin);
    let crc_hex = hex::encode(crc.to_be_bytes());
    name.push(' ');
    name.push_str(&crc_hex);

    let sanitized = deunicode::deunicode(&name)
        .trim()
        .to_lowercase()
        .replace(' ', "_");

    let out_path = if let Some(output) = output {
        if output.extension().is_some() {
            output.to_path_buf()
        } else {
            output.join(format!(
                "{}_{}_l{}.wvd",
                sanitized, device.system_id, device.security_level
            ))
        }
    } else {
        std::env::current_dir()?.join(format!(
            "{}_{}_l{}.wvd",
            sanitized, device.system_id, device.security_level
        ))
    };

    if out_path.exists() {
        anyhow::bail!("A file already exists at the path '{}'", out_path.display());
    }

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out_path, wvd_bin)?;

    info!("Created Widevine Device (.wvd) file, {}", out_path.file_name().unwrap().to_string_lossy());
    info!(" + Type: {:?}", device.device_type);
    info!(" + System ID: {}", device.system_id);
    info!(" + Security Level: {}", device.security_level);
    info!(" + Flags: {}", device.flags);
    info!(
        " + Private Key: {} ({} bit)",
        true,
        device.private_key.n().bits()
    );
    info!(" + Client ID: {}", device.client_id.encode_to_vec().len());
    info!(" + Saved to: {}", out_path.display());
    Ok(())
}

fn run_export_device(wvd_path: &Path, out_dir: Option<&Path>) -> anyhow::Result<()> {
    let device = Device::from_path(wvd_path).context("Failed to load WVD")?;
    let out_dir = out_dir.unwrap_or_else(|| Path::new("."));

    let out_path = out_dir.join(
        wvd_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("device"),
    );

    if out_path.exists() {
        if out_path.read_dir()?.next().is_some() {
            anyhow::bail!("Output directory is not empty, cannot overwrite.");
        }
    } else {
        std::fs::create_dir_all(&out_path)?;
    }

    let meta = DeviceMeta {
        wvd: WvdMeta {
            device_type: format!("{:?}", device.device_type),
            security_level: device.security_level,
            flags: device.flags,
        },
        client_info: client_info_map(&device.client_id),
        capabilities: device
            .client_id
            .client_capabilities
            .as_ref()
            .map(client_capabilities_to_value),
    };

    let meta_path = out_path.join("metadata.yml");
    let meta_yaml = serde_yaml::to_string(&meta)?;
    std::fs::write(&meta_path, meta_yaml)?;
    info!("Exported Device Metadata as metadata.yml");

    let private_key_path = out_path.join("private_key.pem");
    let private_key_pem = device.private_key.to_pkcs1_pem(Default::default())?;
    std::fs::write(&private_key_path, private_key_pem.as_bytes())?;
    std::fs::write(out_path.join("private_key.der"), device.private_key.to_pkcs1_der()?.as_bytes())?;
    info!("Exported Private Key as private_key.der and private_key.pem");

    let client_id_path = out_path.join("client_id.bin");
    std::fs::write(&client_id_path, device.client_id.encode_to_vec())?;
    info!("Exported Client ID as client_id.bin");

    if let Some(vmp_data) = device.client_id.vmp_data.as_ref() {
        let vmp_path = out_path.join("vmp.bin");
        std::fs::write(&vmp_path, vmp_data)?;
        info!("Exported VMP (File Hashes) as vmp.bin");
    } else {
        info!("No VMP (File Hashes) available");
    }

    Ok(())
}

fn run_migrate(path: &Path) -> anyhow::Result<()> {
    let mut targets = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wvd") {
                targets.push(path);
            }
        }
    } else {
        targets.push(path.to_path_buf());
    }

    let total = targets.len();
    let mut migrated = 0usize;
    for device_path in targets {
        info!("Migrating {}...", device_path.display());
        let data = std::fs::read(&device_path)?;
        if data.len() < 4 || &data[..3] != b"WVD" {
            error!(" - Not a WVD file");
            continue;
        }
        let version = data[3];
        if version == 2 {
            error!(" - Device Data is already migrated to the latest version.");
            continue;
        }
        if version != 1 {
            error!(" - Device Data does not seem to be a WVD file (v0).");
            continue;
        }

        let device = Device::from_bytes(&data)?;
        device.save(&device_path)?;
        info!(" + Success");
        migrated += 1;
    }

    info!("Migrated {}/{} devices!", migrated, total);
    Ok(())
}

#[cfg(feature = "serve")]
fn run_serve(config_path: &Path, host: &str, port: u16) -> anyhow::Result<()> {
    let config_str = std::fs::read_to_string(config_path)?;
    let config: rswidevine::serve::ServeConfig = serde_yaml::from_str(&config_str)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create runtime")?;
    runtime.block_on(rswidevine::serve::run(config, host, port))?;
    Ok(())
}

fn parse_device_type(type_: &str) -> anyhow::Result<DeviceType> {
    match type_.to_uppercase().as_str() {
        "CHROME" => Ok(DeviceType::Chrome),
        "ANDROID" => Ok(DeviceType::Android),
        _ => anyhow::bail!("Invalid device type '{}'", type_),
    }
}

fn load_private_key(path: &Path) -> anyhow::Result<rsa::RsaPrivateKey> {
    let data = std::fs::read(path).context("Failed to read private key")?;

    if let Ok(pem) = std::str::from_utf8(&data) {
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
            return Ok(key);
        }
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_pem(pem) {
            return Ok(key);
        }
    }

    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(&data) {
        return Ok(key);
    }
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(&data) {
        return Ok(key);
    }

    anyhow::bail!("Failed to parse RSA private key");
}

fn ensure_full_parse(
    client_id: ClientIdentification,
    original: &[u8],
) -> anyhow::Result<ClientIdentification> {
    let encoded = client_id.encode_to_vec();
    if encoded != original {
        anyhow::bail!("Failed to parse client_id fully (partial parse)");
    }
    Ok(client_id)
}

#[derive(Serialize)]
struct DeviceMeta {
    wvd: WvdMeta,
    client_info: HashMap<String, String>,
    capabilities: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct WvdMeta {
    device_type: String,
    security_level: u8,
    flags: u8,
}

fn client_info_map(client_id: &ClientIdentification) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in client_id.client_info.iter() {
        if let (Some(name), Some(value)) = (entry.name.as_ref(), entry.value.as_ref()) {
            map.insert(name.clone(), value.clone());
        }
    }
    map
}

fn client_capabilities_to_value(cap: &ClientCapabilities) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("client_token".to_string(), serde_json::Value::Bool(cap.client_token.unwrap_or(false)));
    map.insert("session_token".to_string(), serde_json::Value::Bool(cap.session_token.unwrap_or(false)));
    map.insert(
        "video_resolution_constraints".to_string(),
        serde_json::Value::Bool(cap.video_resolution_constraints.unwrap_or(false)),
    );
    map.insert(
        "max_hdcp_version".to_string(),
        cap.max_hdcp_version
            .and_then(|v| HdcpVersion::try_from(v).ok())
            .map(|v| serde_json::Value::String(v.as_str_name().to_string()))
            .unwrap_or_else(|| serde_json::Value::String("HDCP_NONE".to_string())),
    );
    if let Some(v) = cap.oem_crypto_api_version {
        map.insert("oem_crypto_api_version".to_string(), serde_json::Value::Number(v.into()));
    }
    map.insert(
        "anti_rollback_usage_table".to_string(),
        serde_json::Value::Bool(cap.anti_rollback_usage_table.unwrap_or(false)),
    );
    if let Some(v) = cap.srm_version {
        map.insert("srm_version".to_string(), serde_json::Value::Number(v.into()));
    }
    map.insert(
        "can_update_srm".to_string(),
        serde_json::Value::Bool(cap.can_update_srm.unwrap_or(false)),
    );
    let cert_types = cap
        .supported_certificate_key_type
        .iter()
        .filter_map(|v| CertificateKeyType::try_from(*v).ok())
        .map(|v| serde_json::Value::String(v.as_str_name().to_string()))
        .collect::<Vec<_>>();
    map.insert(
        "supported_certificate_key_type".to_string(),
        serde_json::Value::Array(cert_types),
    );
    map.insert(
        "analog_output_capabilities".to_string(),
        cap.analog_output_capabilities
            .and_then(|v| AnalogOutputCapabilities::try_from(v).ok())
            .map(|v| serde_json::Value::String(v.as_str_name().to_string()))
            .unwrap_or_else(|| serde_json::Value::String("ANALOG_OUTPUT_UNKNOWN".to_string())),
    );
    map.insert(
        "can_disable_analog_output".to_string(),
        serde_json::Value::Bool(cap.can_disable_analog_output.unwrap_or(false)),
    );
    if let Some(v) = cap.resource_rating_tier {
        map.insert("resource_rating_tier".to_string(), serde_json::Value::Number(v.into()));
    }
    serde_json::Value::Object(map)
}
