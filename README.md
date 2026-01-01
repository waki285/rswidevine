# rswidevine

A Rust implementation of the Widevine CDM (Content Decryption Module) APIs and data formats.
This project is a Rust port of [pywidevine](https://github.com/devine-dl/pywidevine) and is intended for **authorized** device/content
validation and interoperability work.

## Status

- Actively porting the core functionality from pywidevine.
- The CLI and library APIs are usable for device, PSSH, and license workflow validation.

## Highlights

- Parse/export Widevine device files (`.wvd`).
- CDM session management and license processing.
- PSSH parsing and generation (with optional PlayReady parsing).
- Optional remote CDM client and HTTP serve API.
- Tracing-based logging for CLI.

## Install

```bash
cargo add rswidevine
```

Or build the repo directly:

```bash
cargo build
```

## Usage (Library)

```rust
use rswidevine::device::Device;
use rswidevine::pssh::Pssh;

let device = Device::from_path("./device.wvd")?;
let pssh = Pssh::from_base64("<pssh_base64>")?;
let key_ids = pssh.key_ids()?;
# anyhow::Ok(())
```

## Usage (CLI)

Build with the default `cli` feature:

```bash
cargo run --features cli -- --help
```

Examples:

```bash
# Inspect a device file
cargo run --features cli --example device_info ./device.wvd

# Inspect a PSSH (base64)
cargo run --features cli --example pssh_inspect <pssh_base64>
```

The CLI also provides helper subcommands for license requests, device creation/export,
and basic CDM checks. See `--help` for full usage.

## Feature Flags

| Feature     | Description |
|-------------|-------------|
| `cli`       | CLI binary support (default). |
| `tracing`   | Tracing subscriber for CLI logs (default). |
| `chrono`    | Use `chrono` for date handling in CLI. |
| `playready` | PlayReady XML parsing/conversion. |
| `remote`    | Remote CDM client support. |
| `serve`     | HTTP serve API. |
| `full`      | Enables `cli`, `chrono`, `playready`, `remote`, `serve`, `tracing`. |

## Development Notes

- Protobuf definitions live in `src/license_protocol.proto` and generated code is checked in.
- Generated code is wrapped to avoid `rustfmt` rewriting it on stable.

## License

GPL-3.0-only. See `LICENSE`.

## Legal / Ethical Use

This repository is intended for **authorized testing and interoperability**.
Do not use it to bypass DRM or access content without permission.
