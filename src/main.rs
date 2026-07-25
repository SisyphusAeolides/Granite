#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use uefi::CString16;
use uefi::boot;
use uefi::fs::FileSystem;
use uefi::prelude::*;
use uefi::proto::media::fs::SimpleFileSystem;

const MAXIMUM_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
const BOULDER_PATH: &str = "/BOOT/BOULDER";
const PUSH_PATH: &str = "/BOOT/PUSH";
const CREST_PATH: &str = "/BOOT/CREST";

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
        Some(bundle) => {
            uefi::println!(
                "Granite: bounded Boulder/Push/Crest preflight passed ({}/{}/{} bytes)",
                bundle.boulder.len(),
                bundle.push.len(),
                bundle.crest.len(),
            );
            uefi::println!("Granite: measured admission and transfer remain sealed");
            hold_loader_authority()
        }
        None => {
            uefi::println!("Granite: boot bundle rejected");
            hold_loader_authority()
        }
    }
}

struct BootBundle {
    boulder: Vec<u8>,
    push: Vec<u8>,
    crest: Vec<u8>,
}

fn preflight_bundle() -> Option<BootBundle> {
    let volume: uefi::boot::ScopedProtocol<SimpleFileSystem> =
        boot::get_image_file_system(boot::image_handle()).ok()?;
    let mut filesystem = FileSystem::new(volume);
    let boulder = read_executable(&mut filesystem, BOULDER_PATH)?;
    let push = read_executable(&mut filesystem, PUSH_PATH)?;
    let crest = read_executable(&mut filesystem, CREST_PATH)?;
    Some(BootBundle {
        boulder,
        push,
        crest,
    })
}

fn read_executable(filesystem: &mut FileSystem, path: &str) -> Option<Vec<u8>> {
    let path = CString16::try_from(path).ok()?;
    let bytes = filesystem.read(path.as_ref()).ok()?;
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_ARTIFACT_BYTES
        || bytes.get(..4) != Some(b"\x7fELF")
    {
        return None;
    }
    Some(bytes)
}

/// A loader cannot return after it has accepted or rejected a boot attempt:
/// returning would make firmware retry the same image and hide the exact
/// decision. Granite will replace this hold with Boulder's verified transfer.
fn hold_loader_authority() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
