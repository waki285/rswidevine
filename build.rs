use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    let out_dir = PathBuf::from("src");
    config.out_dir(&out_dir);
    config.compile_protos(&["src/license_protocol.proto"], &["src"])?;
    // Add #![cfg_attr(rustfmt, rustfmt_skip)] to generated rswidevine_license_protocol.rs
    let generated_file = out_dir.join("rswidevine_license_protocol.rs");
    let contents = std::fs::read_to_string(&generated_file)?;
    let new_contents = format!("#![cfg_attr(rustfmt, rustfmt_skip)]\n{}", contents);
    std::fs::write(&generated_file, new_contents)?;
    Ok(())
}
