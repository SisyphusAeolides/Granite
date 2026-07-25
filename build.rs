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

fn encode_sha256(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
