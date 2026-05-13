//! Compiles the isolated napi-c shim (`native/rvcsi_nexmon_shim.c`) into a
//! static library linked into `rvcsi-adapter-nexmon`. This is the only place
//! the rvCSI runtime invokes a C compiler (ADR-095 D2, ADR-096).

fn main() {
    println!("cargo:rerun-if-changed=native/rvcsi_nexmon_shim.c");
    println!("cargo:rerun-if-changed=native/rvcsi_nexmon_shim.h");

    cc::Build::new()
        .file("native/rvcsi_nexmon_shim.c")
        .include("native")
        .warnings(true)
        .extra_warnings(true)
        // The shim is allocation-free and freestanding-ish; keep it tight.
        .flag_if_supported("-std=c11")
        .flag_if_supported("-fno-strict-aliasing")
        .compile("rvcsi_nexmon_shim");
}
