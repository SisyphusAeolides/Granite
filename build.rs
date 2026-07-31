use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies CARGO_MANIFEST_DIR"),
    );
    let artifact_directory = env::var_os("ARACH_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_directory.join("artifacts"));
    println!("cargo:rerun-if-env-changed=ARACH_ARTIFACT_DIR");

    let arach = emit_configured_artifact(
        "ARACH",
        "ARACH_KERNEL_IMAGE",
        &artifact_directory.join("arach"),
    );
    let push =
        emit_configured_artifact("PUSH", "ARACH_PUSH_IMAGE", &artifact_directory.join("push"));
    let crest = emit_configured_artifact(
        "CREST",
        "ARACH_CREST_IMAGE",
        &artifact_directory.join("crest"),
    );
    if env::var_os("CARGO_FEATURE_REQUIRE_ARTIFACTS").is_some()
        && (arach == [0; 32] || push == [0; 32] || crest == [0; 32])
    {
        panic!("Granite production builds require non-empty ARACH, PUSH, and CREST artifacts");
    }
    emit_optional_t1000_gsp_bundle();
    emit_optional_cosmic_bundle();
    build_fortran_policy();
}

fn emit_configured_artifact(label: &str, key: &str, fallback: &Path) -> [u8; 32] {
    println!("cargo:rerun-if-env-changed={key}");
    let path = env::var_os(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.into());
    emit_artifact_digest(label, &path)
}

fn emit_artifact_digest(label: &str, path: &Path) -> [u8; 32] {
    println!("cargo:rerun-if-changed={}", path.display());
    let digest = match fs::read(path) {
        Ok(bytes) if !bytes.is_empty() => sha256(&bytes),
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
    emit_digest(label, digest);
    digest
}

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

    println!("cargo:rerun-if-env-changed=ARACH_HERMES_GSP_DIR");
    println!("cargo:rerun-if-env-changed=SISYPHUS_HERMES_GSP_DIR");
    let directory =
        env::var_os("ARACH_HERMES_GSP_DIR").or_else(|| env::var_os("SISYPHUS_HERMES_GSP_DIR"));
    let Some(directory) = directory else {
        println!("cargo:rustc-env=ARACH_GRANITE_HERMES_GSP_PRESENT=0");
        for (label, _, _) in ARTIFACTS {
            emit_digest(label, [0; 32]);
        }
        return;
    };
    let directory = PathBuf::from(directory);
    assert!(
        directory.is_dir(),
        "ARACH_HERMES_GSP_DIR is not a directory: {}",
        directory.display()
    );
    println!("cargo:rustc-env=ARACH_GRANITE_HERMES_GSP_PRESENT=1");
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
        emit_digest(label, sha256(&bytes));
    }
}

fn emit_optional_cosmic_bundle() {
    const ARTIFACTS: [(&str, &str); 8] = [
        ("COSMIC_SEATD", "seatd"),
        ("COSMIC_DBUS", "dbus-broker"),
        ("COSMIC_PIPEWIRE", "pipewire"),
        ("COSMIC_WIREPLUMBER", "wireplumber"),
        ("COSMIC_COMPOSITOR", "cosmic-comp"),
        ("COSMIC_GREETER", "cosmic-greeter"),
        ("COSMIC_SESSION", "cosmic-session"),
        ("COSMIC_PORTAL", "xdg-desktop-portal-cosmic"),
    ];

    println!("cargo:rerun-if-env-changed=ARACH_COSMIC_SERVICES_DIR");
    let directory = env::var_os("ARACH_COSMIC_SERVICES_DIR").map(PathBuf::from);
    let cosmic_feature = env::var_os("CARGO_FEATURE_COSMIC_BOOT").is_some();
    let Some(directory) = directory else {
        if cosmic_feature {
            panic!("cosmic-boot requires ARACH_COSMIC_SERVICES_DIR");
        }
        println!("cargo:rustc-env=ARACH_GRANITE_COSMIC_PRESENT=0");
        for (label, _) in ARTIFACTS {
            emit_digest(label, [0; 32]);
        }
        return;
    };
    assert!(
        directory.is_dir(),
        "ARACH_COSMIC_SERVICES_DIR is not a directory: {}",
        directory.display()
    );
    println!("cargo:rustc-env=ARACH_GRANITE_COSMIC_PRESENT=1");
    for (label, name) in ARTIFACTS {
        let path = directory.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read native COSMIC service {}: {error}",
                path.display()
            )
        });
        assert!(
            !bytes.is_empty() && bytes.len() <= 16 * 1024 * 1024,
            "native COSMIC service {} must be between 1 byte and 16 MiB",
            path.display()
        );
        emit_digest(label, sha256(&bytes));
    }
    println!("cargo:rerun-if-changed={}", directory.display());
}

fn build_fortran_policy() {
    println!("cargo:rerun-if-changed=native/granite_policy.f90");
    if env::var_os("CARGO_FEATURE_FORTRAN_POLICY").is_none() {
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let object = output.join("granite_policy.o");
    let archive = output.join("libgranite_policy.a");
    let compiler = env::var_os("FC").unwrap_or_else(|| "gfortran".into());
    run(
        Command::new(compiler)
            .arg("-c")
            .arg("-O2")
            .arg("-fPIC")
            .arg(format!("-J{}", output.display()))
            .arg("native/granite_policy.f90")
            .arg("-o")
            .arg(&object),
        "Fortran boot-readiness policy compilation",
    );
    run(
        Command::new("ar").arg("crs").arg(&archive).arg(&object),
        "Fortran boot-readiness policy archive",
    );
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=granite_policy");
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to start {description}: {error}"));
    assert!(status.success(), "{description} failed with {status}");
}

fn emit_digest(label: &str, digest: [u8; 32]) {
    println!(
        "cargo:rustc-env=ARACH_GRANITE_{label}_SHA256={}",
        encode_sha256(digest)
    );
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_sha256(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
