// This is a build script that cargo runs before compiling the main crate.
// It's used here to compile our vpn.proto file into Rust code.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=vpn.proto");
    tonic_prost_build::compile_protos("vpn.proto")?;
    Ok(())
}
