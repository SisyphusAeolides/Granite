#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use granite::elf::{ElfError, ExecutableLayout};
use granite::measurement::{MeasurementError, boot_root, verify};
use uefi::CString16;
use uefi::boot;
use uefi::prelude::*;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;

const MAXIMUM_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 1024 * 1024;
const BOULDER_PATH: &str = "\\BOOT\\BOULDER";
const PUSH_PATH: &str = "\\BOOT\\PUSH";
const CREST_PATH: &str = "\\BOOT\\CREST";

const BOULDER_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("SISYPHUS_GRANITE_BOULDER_SHA256"));
const PUSH_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("SISYPHUS_GRANITE_PUSH_SHA256"));
const CREST_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("SISYPHUS_GRANITE_CREST_SHA256"));

/// Granite is Sisyphus OS's native UEFI boot authority.
///
/// This first executable milestone establishes a direct firmware entry point
/// without GRUB or Limine and performs bounded preflight of the three boot
/// artifacts. Subsequent stages add measured admission, boot-record
/// construction, exit from boot services, and the final control transfer.
#[entry]
fn main() -> Status {
    uefi::helpers::init().expect("Granite requires a usable UEFI console");
    uefi::println!("Granite: native Rust boot authority online");
    match preflight_bundle() {
        Ok(bundle) => {
            uefi::println!(
                "Granite: bounded Boulder/Push/Crest preflight passed ({}/{}/{} bytes)",
                bundle.boulder.bytes.len(),
                bundle.push.bytes.len(),
                bundle.crest.bytes.len(),
            );
            uefi::println!(
                "Granite: admitted ELF load segments Boulder={} Push={} Crest={}",
                bundle.boulder.layout.segments().len(),
                bundle.push.layout.segments().len(),
                bundle.crest.layout.segments().len(),
            );
            uefi::println!(
                "Granite: SHA-256 artifact admission root={:02x}{:02x}{:02x}{:02x}…",
                bundle.measurement_root[0],
                bundle.measurement_root[1],
                bundle.measurement_root[2],
                bundle.measurement_root[3],
            );
            uefi::println!("Granite: measured admission and transfer remain sealed");
            hold_loader_authority()
        }
        Err(error) => {
            let (artifact, reason, size) = error.describe();
            if size == 0 {
                uefi::println!("Granite: boot bundle rejected: {artifact} {reason}");
            } else {
                uefi::println!("Granite: boot bundle rejected: {artifact} {reason} ({size} bytes)");
            }
            hold_loader_authority()
        }
    }
}

struct BootBundle {
    boulder: BootArtifact,
    push: BootArtifact,
    crest: BootArtifact,
    measurement_root: [u8; 32],
}

struct BootArtifact {
    bytes: Vec<u8>,
    /// This is the exact bounded load plan Granite will use for its native
    /// placement stage. Keeping it with the admitted bytes prevents a second,
    /// less-checked parse after measured admission.
    layout: ExecutableLayout,
    digest: [u8; 32],
}

enum PreflightError {
    BootVolume,
    Boulder(ArtifactError),
    Push(ArtifactError),
    Crest(ArtifactError),
}

enum ArtifactError {
    InvalidPath,
    Read,
    Empty,
    Oversized(usize),
    Elf(ElfError),
    ManifestMissing,
    DigestMismatch,
}

impl PreflightError {
    fn describe(&self) -> (&'static str, &'static str, usize) {
        match self {
            Self::BootVolume => ("boot volume", "unavailable", 0),
            Self::Boulder(error) => ("Boulder", error.reason(), error.size()),
            Self::Push(error) => ("Push", error.reason(), error.size()),
            Self::Crest(error) => ("Crest", error.reason(), error.size()),
        }
    }
}

impl ArtifactError {
    fn reason(&self) -> &'static str {
        match self {
            Self::InvalidPath => "path encoding rejected",
            Self::Read => "read failed",
            Self::Empty => "is empty",
            Self::Oversized(_) => "exceeds the fixed bound",
            Self::Elf(error) => error.reason(),
            Self::ManifestMissing => "has no build-bound measurement manifest",
            Self::DigestMismatch => "does not match its build-bound SHA-256",
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Oversized(size) => *size,
            _ => 0,
        }
    }
}

fn preflight_bundle() -> Result<BootBundle, PreflightError> {
    let mut filesystem: uefi::boot::ScopedProtocol<SimpleFileSystem> =
        boot::get_image_file_system(boot::image_handle())
            .map_err(|_| PreflightError::BootVolume)?;
    let mut volume = filesystem
        .open_volume()
        .map_err(|_| PreflightError::BootVolume)?;
    let boulder = read_executable(&mut volume, BOULDER_PATH, BOULDER_EXPECTED_SHA256)
        .map_err(PreflightError::Boulder)?;
    let push = read_executable(&mut volume, PUSH_PATH, PUSH_EXPECTED_SHA256)
        .map_err(PreflightError::Push)?;
    let crest = read_executable(&mut volume, CREST_PATH, CREST_EXPECTED_SHA256)
        .map_err(PreflightError::Crest)?;
    let measurement_root = boot_root(boulder.digest, push.digest, crest.digest);
    Ok(BootBundle {
        boulder,
        push,
        crest,
        measurement_root,
    })
}

fn read_executable(
    volume: &mut Directory,
    path: &str,
    expected_digest: [u8; 32],
) -> Result<BootArtifact, ArtifactError> {
    let path = CString16::try_from(path).map_err(|_| ArtifactError::InvalidPath)?;
    let mut file = volume
        .open(path.as_ref(), FileMode::Read, FileAttribute::empty())
        .map_err(|_| ArtifactError::Read)?
        .into_regular_file()
        .ok_or(ArtifactError::Read)?;
    let length = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| ArtifactError::Read)?
        .file_size();
    let length = usize::try_from(length).map_err(|_| ArtifactError::Oversized(usize::MAX))?;
    if length == 0 {
        return Err(ArtifactError::Empty);
    }
    if length > MAXIMUM_ARTIFACT_BYTES {
        return Err(ArtifactError::Oversized(length));
    }
    let mut bytes = alloc::vec![0; length];
    let mut offset = 0;
    while offset < bytes.len() {
        let end = offset.saturating_add(READ_CHUNK_BYTES).min(bytes.len());
        let read = file
            .read(&mut bytes[offset..end])
            .map_err(|_| ArtifactError::Read)?;
        if read == 0 {
            return Err(ArtifactError::Read);
        }
        offset = offset.checked_add(read).ok_or(ArtifactError::Read)?;
        if offset > bytes.len() {
            return Err(ArtifactError::Read);
        }
    }
    let layout = ExecutableLayout::parse(&bytes).map_err(ArtifactError::Elf)?;
    let digest = verify(&bytes, expected_digest).map_err(|error| match error {
        MeasurementError::ManifestMissing => ArtifactError::ManifestMissing,
        MeasurementError::DigestMismatch => ArtifactError::DigestMismatch,
    })?;
    Ok(BootArtifact {
        bytes,
        layout,
        digest,
    })
}

const fn parse_sha256(encoded: &str) -> [u8; 32] {
    assert!(encoded.len() == 64, "invalid Granite measurement digest");
    let bytes = encoded.as_bytes();
    let mut digest = [0_u8; 32];
    let mut index = 0;
    while index < digest.len() {
        digest[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    digest
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid Granite measurement digest"),
    }
}

/// A loader cannot return after it has accepted or rejected a boot attempt:
/// returning would make firmware retry the same image and hide the exact
/// decision. Granite will replace this hold with Boulder's verified transfer.
fn hold_loader_authority() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
