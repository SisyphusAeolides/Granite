#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
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
                bundle.boulder.len(),
                bundle.push.len(),
                bundle.crest.len(),
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
    boulder: Vec<u8>,
    push: Vec<u8>,
    crest: Vec<u8>,
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
    NotElf,
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
            Self::NotElf => "is not an ELF image",
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
    let boulder = read_executable(&mut volume, BOULDER_PATH).map_err(PreflightError::Boulder)?;
    let push = read_executable(&mut volume, PUSH_PATH).map_err(PreflightError::Push)?;
    let crest = read_executable(&mut volume, CREST_PATH).map_err(PreflightError::Crest)?;
    Ok(BootBundle {
        boulder,
        push,
        crest,
    })
}

fn read_executable(volume: &mut Directory, path: &str) -> Result<Vec<u8>, ArtifactError> {
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
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err(ArtifactError::NotElf);
    }
    Ok(bytes)
}

/// A loader cannot return after it has accepted or rejected a boot attempt:
/// returning would make firmware retry the same image and hide the exact
/// decision. Granite will replace this hold with Boulder's verified transfer.
fn hold_loader_authority() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
