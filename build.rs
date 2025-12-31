//use protobuf_codegen_pure::Codegen;

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*Codegen::new()
    .out_dir("src")
    .inputs(&["src/license_protocol.proto"])
    .include("src")
    .run()
    .expect("failed to codegen")*/
    /*protobuf_codegen::Codegen::new()
    // Use `protoc` parser, optional.
        .protoc()
    // Use `protoc-bin-vendored` bundled protoc command, optional.
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
    // All inputs and imports from the inputs must reside in `includes` directories.
        .includes(&["src"])
    // Inputs must reside in some of include paths.
        .input("src/license_protocol.proto")
        .cargo_out_dir("src")
        .run_from_script()*/
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
