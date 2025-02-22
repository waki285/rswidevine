use std::process;

use clap::{Arg, Command};
use log::LevelFilter;

#[cfg(not(feature = "chrono"))]
use std::time::SystemTime;
#[cfg(feature = "chrono")]
use chrono::Datelike;

#[macro_use]
mod macros;
mod rswidevine_license_protocol;
mod pssh;

/// rswidevine—Rust Widevine CDM implementation.
fn main() {
    let matches = Command::new("rswidevine")
        .version("0.1.0")
        .disable_version_flag(true)
        .about("rswidevine CLI")
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .help("Print version information.")
                .num_args(0),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .help("Enable DEBUG level logs.")
                .num_args(0),
        )
        .subcommand(
            Command::new("install")
                .about("Install Widevine CDM.")
                .arg(
                    Arg::new("path")
                        .short('p')
                        .long("path")
                        .value_name("PATH")
                        .help("Path to the Widevine CDM.")
                        .required(true)
                        .num_args(0),
                ),
        )
        .get_matches();

    let debug = matches.contains_id("debug");

    // ロギングの設定
    if debug {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Info)
            .init();
    }

    #[cfg(not(feature = "chrono"))]
    let current_year = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() / 31_536_000 + 1970)
        .unwrap_or(2022);
    #[cfg(feature = "chrono")]
    let current_year = chrono::Local::now().year();

    let copyright_years = format!("2024-{}", current_year);

    let version = env!("CARGO_PKG_VERSION");
    info!(
        "rswidevine version {} Copyright (c) {} waki285 (Original: rlaphoenix)",
        version, copyright_years
    );
    info!("https://github.com/waki285/rswidevine");

    if matches.contains_id("version") {
        process::exit(0);
    }
}
