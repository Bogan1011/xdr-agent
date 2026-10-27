// The generated code is committed, like gen/ for the Go agent, so normal
// builds need no protoc. `cargo build -p xdr-proto --features regen` updates it.
fn main() {
    #[cfg(feature = "regen")]
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../proto");
        tonic_prost_build::configure()
            .build_server(false)
            .out_dir("src/gen")
            .compile_protos(&[root.join("xdr/v1/agent.proto")], &[root])
            .expect("protoc failed");
        println!("cargo:rerun-if-changed=../../../proto/xdr/v1/agent.proto");
    }
}
