use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies CARGO_MANIFEST_DIR"),
    );
    let workspace = manifest_directory.join("../..");
    let target = match env::var_os("CARGO_TARGET_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                workspace.join(path)
            }
        }
        None => workspace.join("target"),
    };
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    emit_artifact_digest("BOULDER", &target.join("x86_64-sisyphus/debug/boulder"));
    emit_artifact_digest("PUSH", &target.join("x86_64-sisyphus-user/release/push"));
    emit_artifact_digest("CREST", &target.join("x86_64-sisyphus-user/release/crest"));
    emit_optional_t1000_gsp_bundle();
}

fn emit_artifact_digest(label: &str, path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    let digest = match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => blacklab::oureboros::sha256(&bytes),
        Ok(_) => {
            println!(
                "cargo:warning=Granite {label} artifact is empty; its UEFI image will fail closed"
            );
            [0; 32]
        }
        Err(_) => {
            println!(
                "cargo:warning=Granite {label} artifact is unavailable; its UEFI image will fail closed"
            );
            [0; 32]
        }
    };
    println!(
        "cargo:rustc-env=SISYPHUS_GRANITE_{label}_SHA256={}",
        encode_sha256(digest)
    );
}

/// Firmware is opt-in at image assembly time because redistributable NVIDIA
/// artifacts must be supplied by the image builder, never invented from this
/// source tree.  When selected, every member is measured into Granite itself;
/// any missing or over-large artifact aborts the build instead of producing an
/// image that merely looks GSP-capable.
fn emit_optional_t1000_gsp_bundle() {
    const ARTIFACTS: [(&str, &str, usize); 5] = [
        ("HERMES_GSP_RM", "gsp-rm.bin", 32 * 1024 * 1024),
        (
            "HERMES_SEC2_BOOTLOADER",
            "generic-sec2-bootloader.bin",
            1024 * 1024,
        ),
        ("HERMES_GSP_BOOTLOADER", "gsp-bootloader.bin", 1024 * 1024),
        ("HERMES_BOOTER_LOAD", "booter-load.bin", 1024 * 1024),
        ("HERMES_BOOTER_UNLOAD", "booter-unload.bin", 1024 * 1024),
    ];

    println!("cargo:rerun-if-env-changed=SISYPHUS_HERMES_GSP_DIR");
    let Some(directory) = env::var_os("SISYPHUS_HERMES_GSP_DIR") else {
        println!("cargo:rustc-env=SISYPHUS_GRANITE_HERMES_GSP_PRESENT=0");
        for (label, _, _) in ARTIFACTS {
            emit_digest(label, [0; 32]);
        }
        return;
    };
    let directory = PathBuf::from(directory);
    assert!(
        directory.is_dir(),
        "SISYPHUS_HERMES_GSP_DIR is not a directory: {}",
        directory.display()
    );
    println!("cargo:rustc-env=SISYPHUS_GRANITE_HERMES_GSP_PRESENT=1");
    for (label, name, maximum_bytes) in ARTIFACTS {
        let path = directory.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read selected T1000 GSP artifact {}: {error}",
                path.display()
            )
        });
        assert!(
            !bytes.is_empty() && bytes.len() <= maximum_bytes,
            "selected T1000 GSP artifact {} must be between 1 byte and {} bytes",
            path.display(),
            maximum_bytes
        );
        emit_digest(label, blacklab::oureboros::sha256(&bytes));
    }
}

fn emit_digest(label: &str, digest: [u8; 32]) {
    println!(
        "cargo:rustc-env=SISYPHUS_GRANITE_{label}_SHA256={}",
        encode_sha256(digest)
    );
}

fn encode_sha256(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
