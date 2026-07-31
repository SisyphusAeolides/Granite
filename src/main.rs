#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use granite::elf::{ElfError, ExecutableLayout};
use granite::handoff::{
    self, BootModule, EARLY_MAPPED_PHYSICAL_LIMIT, FirmwareMemoryRegion, Framebuffer,
    GRANITE_BOOTSTRAP_ENTRY_PHYSICAL, HandoffError, MAXIMUM_MEMORY_REGIONS, MemoryKind, PAGE_BYTES,
};
use granite::measurement::{MeasurementError, boot_root, boot_root_with_services, sha256, verify};
use uefi::CString16;
use uefi::boot;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::mem::memory_map::MemoryType;
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::system;
use uefi::table::cfg::ConfigTableEntry;

#[panic_handler]
fn granite_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    uefi::println!("Granite panic: {}", info);
    loop {
        core::hint::spin_loop();
    }
}

const MAXIMUM_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 1024 * 1024;
const BOOT_INFORMATION_BYTES: usize = 64 * 1024;
const BOOTSTRAP_STACK_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_ACPI_ROOT_BYTES: usize = 4096;
const ARACH_PATH: &str = "\\BOOT\\ARACH";
const PUSH_PATH: &str = "\\BOOT\\PUSH";
const CREST_PATH: &str = "\\BOOT\\CREST";
const COSMIC_DBUS_PATH: &str = "\\BOOT\\DBUS.BIN";
const COSMIC_COMPOSITOR_PATH: &str = "\\BOOT\\COSCOMP.BIN";
const COSMIC_GREETER_PATH: &str = "\\BOOT\\COSGREETER.BIN";
const COSMIC_SESSION_PATH: &str = "\\BOOT\\COSSESSION.BIN";
const COSMIC_PORTAL_PATH: &str = "\\BOOT\\COSPORTAL.BIN";
const HERMES_GSP_RM_PATH: &str = "\\BOOT\\GSPRM.BIN";
const HERMES_SEC2_BOOTLOADER_PATH: &str = "\\BOOT\\SEC2.BIN";
const HERMES_GSP_BOOTLOADER_PATH: &str = "\\BOOT\\GSPBL.BIN";
const HERMES_BOOTER_LOAD_PATH: &str = "\\BOOT\\BOOTL.BIN";
const HERMES_BOOTER_UNLOAD_PATH: &str = "\\BOOT\\BOOTU.BIN";

const ARACH_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("ARACH_GRANITE_ARACH_SHA256"));
const PUSH_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("ARACH_GRANITE_PUSH_SHA256"));
const CREST_EXPECTED_SHA256: [u8; 32] = parse_sha256(env!("ARACH_GRANITE_CREST_SHA256"));
const COSMIC_DBUS_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_COSMIC_DBUS_SHA256"));
const COSMIC_COMPOSITOR_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_COSMIC_COMPOSITOR_SHA256"));
const COSMIC_GREETER_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_COSMIC_GREETER_SHA256"));
const COSMIC_SESSION_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_COSMIC_SESSION_SHA256"));
const COSMIC_PORTAL_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_COSMIC_PORTAL_SHA256"));
const HERMES_GSP_RM_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_HERMES_GSP_RM_SHA256"));
const HERMES_SEC2_BOOTLOADER_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_HERMES_SEC2_BOOTLOADER_SHA256"));
const HERMES_GSP_BOOTLOADER_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_HERMES_GSP_BOOTLOADER_SHA256"));
const HERMES_BOOTER_LOAD_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_HERMES_BOOTER_LOAD_SHA256"));
const HERMES_BOOTER_UNLOAD_EXPECTED_SHA256: [u8; 32] =
    parse_sha256(env!("ARACH_GRANITE_HERMES_BOOTER_UNLOAD_SHA256"));

/// Granite is Arach OS's native UEFI boot authority.
///
/// Granite opens the firmware boot volume directly, measures the assembled
/// Arach/Push/Crest bundle, constructs Arach's bounded handoff record,
/// exits boot services, and transfers to Arach's native 64-bit entry.
#[entry]
fn main() -> Status {
    uefi::helpers::init().expect("Granite requires a usable UEFI console");
    uefi::println!("Granite: native Rust boot authority online");
    match preflight_bundle() {
        Ok(bundle) => {
            uefi::println!(
                "Granite: bounded Arach/Push/Crest preflight passed ({}/{}/{} bytes)",
                bundle.arach.bytes.len(),
                bundle.push.bytes.len(),
                bundle.crest.bytes.len(),
            );
            uefi::println!(
                "Granite: admitted ELF load segments Arach={} Push={} Crest={}",
                bundle.arach.layout.segments().len(),
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
            if let Some(gsp) = bundle.hermes_gsp.as_ref() {
                let gsp_root = gsp.measurement_root();
                uefi::println!(
                    "Granite: measured T1000 GSP bundle admitted root={:02x}{:02x}{:02x}{:02x}… (GSP-RM={} bytes, SEC2={} bytes, Booter={}/{} bytes)",
                    gsp_root[0],
                    gsp_root[1],
                    gsp_root[2],
                    gsp_root[3],
                    gsp.gsp_rm.bytes.len(),
                    gsp.sec2_bootloader.bytes.len(),
                    gsp.booter_load.bytes.len(),
                    gsp.booter_unload.bytes.len(),
                );
            } else {
                uefi::println!(
                    "Granite: no NVIDIA GSP bundle selected; native GSP stays unavailable"
                );
            }
            uefi::println!("Granite: placing measured native handoff");
            match transfer_to_arach(bundle) {
                Ok(()) => unreachable!("Arach handoff must not return"),
                Err(error) => {
                    uefi::println!("Granite: native handoff rejected: {error:?}");
                    hold_loader_authority()
                }
            }
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
    arach: BootArtifact,
    push: BootArtifact,
    crest: BootArtifact,
    cosmic: Option<CosmicBootBundle>,
    hermes_gsp: Option<T1000GspBootBundle>,
    measurement_root: [u8; 32],
}

struct CosmicBootBundle {
    dbus: BootArtifact,
    compositor: BootArtifact,
    greeter: BootArtifact,
    session: BootArtifact,
    portal: BootArtifact,
}

struct BootArtifact {
    bytes: Vec<u8>,
    /// This is the exact bounded load plan Granite will use for its native
    /// placement stage. Keeping it with the admitted bytes prevents a second,
    /// less-checked parse after measured admission.
    layout: ExecutableLayout,
    digest: [u8; 32],
}

/// A non-executable artifact that Granite only transports after independent
/// measurement.  Arach performs the stricter NVIDIA role/hash validation;
/// Granite never interprets firmware data as executable host code.
struct RawArtifact {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

struct T1000GspBootBundle {
    gsp_rm: RawArtifact,
    sec2_bootloader: RawArtifact,
    gsp_bootloader: RawArtifact,
    booter_load: RawArtifact,
    booter_unload: RawArtifact,
}

impl T1000GspBootBundle {
    /// Binds the ordered raw firmware measurements separately from the
    /// executable boot root. Firmware never becomes a host executable, but a
    /// reordered or substituted member must still change its evidence.
    fn measurement_root(&self) -> [u8; 32] {
        let mut material = [0_u8; 32 * 5];
        for (index, digest) in [
            self.gsp_rm.digest,
            self.sec2_bootloader.digest,
            self.gsp_bootloader.digest,
            self.booter_load.digest,
            self.booter_unload.digest,
        ]
        .iter()
        .enumerate()
        {
            let start = index * 32;
            material[start..start + 32].copy_from_slice(digest);
        }
        sha256(&material)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeHandoffError {
    Layout(HandoffError),
    PageCount,
    ArachPlacement(usize),
    ModulePlacement,
    BootInformationPlacement,
    AcpiRoot,
    GraphicsOutput,
    GraphicsFormat,
    BootstrapStackPlacement,
    DeferredBssPlacement,
}

impl From<HandoffError> for NativeHandoffError {
    fn from(error: HandoffError) -> Self {
        Self::Layout(error)
    }
}

#[derive(Clone, Copy)]
struct PlacedModule {
    physical_address: u64,
    bytes: u64,
}

struct PlacedT1000GspBundle {
    gsp_rm: PlacedModule,
    sec2_bootloader: PlacedModule,
    gsp_bootloader: PlacedModule,
    booter_load: PlacedModule,
    booter_unload: PlacedModule,
}

struct PlacedCosmicBootBundle {
    dbus: PlacedModule,
    compositor: PlacedModule,
    greeter: PlacedModule,
    session: PlacedModule,
    portal: PlacedModule,
}

#[derive(Clone, Copy)]
struct AcpiRoot {
    bytes: [u8; MAXIMUM_ACPI_ROOT_BYTES],
    length: usize,
}

impl AcpiRoot {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

enum PreflightError {
    BootVolume,
    Arach(ArtifactError),
    Push(ArtifactError),
    Crest(ArtifactError),
    CosmicDbus(ArtifactError),
    CosmicCompositor(ArtifactError),
    CosmicGreeter(ArtifactError),
    CosmicSession(ArtifactError),
    CosmicPortal(ArtifactError),
    HermesGspRm(ArtifactError),
    HermesSec2Bootloader(ArtifactError),
    HermesGspBootloader(ArtifactError),
    HermesBooterLoad(ArtifactError),
    HermesBooterUnload(ArtifactError),
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
            Self::Arach(error) => ("Arach", error.reason(), error.size()),
            Self::Push(error) => ("Push", error.reason(), error.size()),
            Self::Crest(error) => ("Crest", error.reason(), error.size()),
            Self::CosmicDbus(error) => ("COSMIC dbus-broker", error.reason(), error.size()),
            Self::CosmicCompositor(error) => ("COSMIC compositor", error.reason(), error.size()),
            Self::CosmicGreeter(error) => ("COSMIC greeter", error.reason(), error.size()),
            Self::CosmicSession(error) => ("COSMIC session", error.reason(), error.size()),
            Self::CosmicPortal(error) => ("COSMIC portal", error.reason(), error.size()),
            Self::HermesGspRm(error) => ("Hermes GSP-RM", error.reason(), error.size()),
            Self::HermesSec2Bootloader(error) => {
                ("Hermes SEC2 bootloader", error.reason(), error.size())
            }
            Self::HermesGspBootloader(error) => {
                ("Hermes GSP bootloader", error.reason(), error.size())
            }
            Self::HermesBooterLoad(error) => ("Hermes Booter Load", error.reason(), error.size()),
            Self::HermesBooterUnload(error) => {
                ("Hermes Booter Unload", error.reason(), error.size())
            }
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
    let arach = read_executable(&mut volume, ARACH_PATH, ARACH_EXPECTED_SHA256)
        .map_err(PreflightError::Arach)?;
    let push = read_executable(&mut volume, PUSH_PATH, PUSH_EXPECTED_SHA256)
        .map_err(PreflightError::Push)?;
    let crest = read_executable(&mut volume, CREST_PATH, CREST_EXPECTED_SHA256)
        .map_err(PreflightError::Crest)?;
    let cosmic = if cosmic_selected() {
        Some(CosmicBootBundle {
            dbus: read_executable(&mut volume, COSMIC_DBUS_PATH, COSMIC_DBUS_EXPECTED_SHA256)
                .map_err(PreflightError::CosmicDbus)?,
            compositor: read_executable(
                &mut volume,
                COSMIC_COMPOSITOR_PATH,
                COSMIC_COMPOSITOR_EXPECTED_SHA256,
            )
            .map_err(PreflightError::CosmicCompositor)?,
            greeter: read_executable(
                &mut volume,
                COSMIC_GREETER_PATH,
                COSMIC_GREETER_EXPECTED_SHA256,
            )
            .map_err(PreflightError::CosmicGreeter)?,
            session: read_executable(
                &mut volume,
                COSMIC_SESSION_PATH,
                COSMIC_SESSION_EXPECTED_SHA256,
            )
            .map_err(PreflightError::CosmicSession)?,
            portal: read_executable(
                &mut volume,
                COSMIC_PORTAL_PATH,
                COSMIC_PORTAL_EXPECTED_SHA256,
            )
            .map_err(PreflightError::CosmicPortal)?,
        })
    } else {
        None
    };
    let hermes_gsp = if hermes_gsp_selected() {
        Some(T1000GspBootBundle {
            gsp_rm: read_raw_artifact(
                &mut volume,
                HERMES_GSP_RM_PATH,
                HERMES_GSP_RM_EXPECTED_SHA256,
            )
            .map_err(PreflightError::HermesGspRm)?,
            sec2_bootloader: read_raw_artifact(
                &mut volume,
                HERMES_SEC2_BOOTLOADER_PATH,
                HERMES_SEC2_BOOTLOADER_EXPECTED_SHA256,
            )
            .map_err(PreflightError::HermesSec2Bootloader)?,
            gsp_bootloader: read_raw_artifact(
                &mut volume,
                HERMES_GSP_BOOTLOADER_PATH,
                HERMES_GSP_BOOTLOADER_EXPECTED_SHA256,
            )
            .map_err(PreflightError::HermesGspBootloader)?,
            booter_load: read_raw_artifact(
                &mut volume,
                HERMES_BOOTER_LOAD_PATH,
                HERMES_BOOTER_LOAD_EXPECTED_SHA256,
            )
            .map_err(PreflightError::HermesBooterLoad)?,
            booter_unload: read_raw_artifact(
                &mut volume,
                HERMES_BOOTER_UNLOAD_PATH,
                HERMES_BOOTER_UNLOAD_EXPECTED_SHA256,
            )
            .map_err(PreflightError::HermesBooterUnload)?,
        })
    } else {
        None
    };
    let measurement_root = match cosmic.as_ref() {
        Some(cosmic) => boot_root_with_services(
            arach.digest,
            push.digest,
            crest.digest,
            [
                cosmic.dbus.digest,
                cosmic.compositor.digest,
                cosmic.greeter.digest,
                cosmic.session.digest,
                cosmic.portal.digest,
            ],
        ),
        None => boot_root(arach.digest, push.digest, crest.digest),
    };
    Ok(BootBundle {
        arach,
        push,
        crest,
        cosmic,
        hermes_gsp,
        measurement_root,
    })
}

fn cosmic_selected() -> bool {
    env!("ARACH_GRANITE_COSMIC_PRESENT") == "1"
}

fn hermes_gsp_selected() -> bool {
    env!("ARACH_GRANITE_HERMES_GSP_PRESENT") == "1"
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

fn read_raw_artifact(
    volume: &mut Directory,
    path: &str,
    expected_digest: [u8; 32],
) -> Result<RawArtifact, ArtifactError> {
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
    let digest = verify(&bytes, expected_digest).map_err(|error| match error {
        MeasurementError::ManifestMissing => ArtifactError::ManifestMissing,
        MeasurementError::DigestMismatch => ArtifactError::DigestMismatch,
    })?;
    Ok(RawArtifact { bytes, digest })
}

fn transfer_to_arach(bundle: BootBundle) -> Result<(), NativeHandoffError> {
    handoff::validate_arach_layout(&bundle.arach.layout)?;
    let deferred_bss = deferred_bss_range(&bundle.arach.layout)?;
    place_arach(&bundle.arach)?;
    let push = place_module(&bundle.push.bytes, deferred_bss)?;
    let crest = place_module(&bundle.crest.bytes, deferred_bss)?;
    let cosmic = match bundle.cosmic.as_ref() {
        Some(cosmic) => Some(PlacedCosmicBootBundle {
            dbus: place_module(&cosmic.dbus.bytes, deferred_bss)?,
            compositor: place_module(&cosmic.compositor.bytes, deferred_bss)?,
            greeter: place_module(&cosmic.greeter.bytes, deferred_bss)?,
            session: place_module(&cosmic.session.bytes, deferred_bss)?,
            portal: place_module(&cosmic.portal.bytes, deferred_bss)?,
        }),
        None => None,
    };
    let hermes_gsp = match bundle.hermes_gsp.as_ref() {
        Some(gsp) => Some(PlacedT1000GspBundle {
            gsp_rm: place_module(&gsp.gsp_rm.bytes, deferred_bss)?,
            sec2_bootloader: place_module(&gsp.sec2_bootloader.bytes, deferred_bss)?,
            gsp_bootloader: place_module(&gsp.gsp_bootloader.bytes, deferred_bss)?,
            booter_load: place_module(&gsp.booter_load.bytes, deferred_bss)?,
            booter_unload: place_module(&gsp.booter_unload.bytes, deferred_bss)?,
        }),
        None => None,
    };
    let framebuffer = capture_framebuffer()?;
    let acpi_root = capture_acpi_root()?;
    let bootstrap_stack = boot::allocate_pages(
        boot::AllocateType::MaxAddress(EARLY_MAPPED_PHYSICAL_LIMIT - 1),
        MemoryType::LOADER_DATA,
        page_count(BOOTSTRAP_STACK_BYTES as u64)?,
    )
    .map_err(|_| NativeHandoffError::BootstrapStackPlacement)?;
    let bootstrap_stack_start = bootstrap_stack.as_ptr() as u64;
    let bootstrap_stack_end = bootstrap_stack_start
        .checked_add(BOOTSTRAP_STACK_BYTES as u64)
        .ok_or(NativeHandoffError::BootstrapStackPlacement)?;
    if bootstrap_stack_end > EARLY_MAPPED_PHYSICAL_LIMIT
        || overlaps_deferred_bss(bootstrap_stack_start, bootstrap_stack_end, deferred_bss)
    {
        return Err(NativeHandoffError::BootstrapStackPlacement);
    }
    let boot_information = boot::allocate_pages(
        boot::AllocateType::MaxAddress(EARLY_MAPPED_PHYSICAL_LIMIT - 1),
        MemoryType::LOADER_DATA,
        page_count(BOOT_INFORMATION_BYTES as u64)?,
    )
    .map_err(|_| NativeHandoffError::BootInformationPlacement)?;
    let boot_information_address = boot_information.as_ptr() as u64;
    let boot_information_end = boot_information_address
        .checked_add(BOOT_INFORMATION_BYTES as u64)
        .ok_or(NativeHandoffError::BootInformationPlacement)?;
    if boot_information_end > EARLY_MAPPED_PHYSICAL_LIMIT
        || overlaps_deferred_bss(boot_information_address, boot_information_end, deferred_bss)
    {
        return Err(NativeHandoffError::BootInformationPlacement);
    }

    // Build the fixed Multiboot module table while UEFI allocation services
    // are still live.  Nothing after ExitBootServices may grow a Vec: the
    // firmware-backed allocator is no longer available at that point.
    let mut modules = [BootModule {
        start: 0,
        bytes: 0,
        name: &[],
    }; 12];
    let mut module_count = 0usize;
    modules[module_count] = BootModule {
        start: push.physical_address,
        bytes: push.bytes,
        name: b"push",
    };
    module_count += 1;
    modules[module_count] = BootModule {
        start: crest.physical_address,
        bytes: crest.bytes,
        name: b"crest",
    };
    module_count += 1;
    if let Some(cosmic) = cosmic.as_ref() {
        for module in [
            BootModule {
                start: cosmic.dbus.physical_address,
                bytes: cosmic.dbus.bytes,
                name: b"dbus-broker",
            },
            BootModule {
                start: cosmic.compositor.physical_address,
                bytes: cosmic.compositor.bytes,
                name: b"cosmic-comp",
            },
            BootModule {
                start: cosmic.greeter.physical_address,
                bytes: cosmic.greeter.bytes,
                name: b"cosmic-greeter",
            },
            BootModule {
                start: cosmic.session.physical_address,
                bytes: cosmic.session.bytes,
                name: b"cosmic-session",
            },
            BootModule {
                start: cosmic.portal.physical_address,
                bytes: cosmic.portal.bytes,
                name: b"xdg-desktop-portal-cosmic",
            },
        ] {
            modules[module_count] = module;
            module_count += 1;
        }
    }
    if let Some(gsp) = hermes_gsp.as_ref() {
        for module in [
            BootModule {
                start: gsp.gsp_rm.physical_address,
                bytes: gsp.gsp_rm.bytes,
                name: b"hermes-gsp",
            },
            BootModule {
                start: gsp.sec2_bootloader.physical_address,
                bytes: gsp.sec2_bootloader.bytes,
                name: b"hermes-sec2",
            },
            BootModule {
                start: gsp.gsp_bootloader.physical_address,
                bytes: gsp.gsp_bootloader.bytes,
                name: b"hermes-gsp-bootloader",
            },
            BootModule {
                start: gsp.booter_load.physical_address,
                bytes: gsp.booter_load.bytes,
                name: b"hermes-booter-load",
            },
            BootModule {
                start: gsp.booter_unload.physical_address,
                bytes: gsp.booter_unload.bytes,
                name: b"hermes-booter-unload",
            },
        ] {
            modules[module_count] = module;
            module_count += 1;
        }
    }

    // All FAT-backed artifact vectors are now copied into their retained
    // physical locations, so release their firmware allocations before the
    // final memory map is acquired.
    drop(bundle);

    match hermes_gsp.as_ref() {
        Some(gsp) => uefi::println!(
            "Granite: Arach placed; Push={:#x} Crest={:#x} GSP-RM={:#x}; leaving UEFI boot services",
            push.physical_address,
            crest.physical_address,
            gsp.gsp_rm.physical_address,
        ),
        None => uefi::println!(
            "Granite: Arach placed; Push={:#x} Crest={:#x}; leaving UEFI boot services",
            push.physical_address,
            crest.physical_address,
        ),
    }
    if let Some(cosmic) = cosmic.as_ref() {
        uefi::println!(
            "Granite: native COSMIC modules placed dbus={:#x} compositor={:#x} greeter={:#x} session={:#x} portal={:#x}",
            cosmic.dbus.physical_address,
            cosmic.compositor.physical_address,
            cosmic.greeter.physical_address,
            cosmic.session.physical_address,
            cosmic.portal.physical_address,
        );
    }

    // After this call neither the firmware allocator nor protocol references
    // may be used. Any invariant failure below halts before an untrusted or
    // incomplete handoff can reach Arach.
    let memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    let mut regions = [FirmwareMemoryRegion::EMPTY; MAXIMUM_MEMORY_REGIONS];
    let region_count = match collect_memory_regions(&memory_map, &mut regions) {
        Ok(count) => count,
        Err(_) => halt_after_boot_services(),
    };
    let boot_information = unsafe {
        core::slice::from_raw_parts_mut(boot_information.as_ptr(), BOOT_INFORMATION_BYTES)
    };
    let handoff = handoff::write_multiboot2(
        boot_information,
        &regions[..region_count],
        &modules[..module_count],
        framebuffer,
        acpi_root.as_slice(),
    );
    match handoff {
        Ok(_) => {}
        Err(_) => halt_after_boot_services(),
    }

    // The dedicated Arach entry uses the System V register convention so
    // the physical handoff address arrives in RDI. It installs a fresh
    // higher-half map before it reaches any Rust code.
    let entry: unsafe extern "sysv64" fn(usize, usize) -> ! =
        unsafe { core::mem::transmute(GRANITE_BOOTSTRAP_ENTRY_PHYSICAL as usize) };
    unsafe {
        entry(
            boot_information_address as usize,
            bootstrap_stack_end as usize,
        )
    }
}

fn place_arach(artifact: &BootArtifact) -> Result<(), NativeHandoffError> {
    for (index, segment) in artifact.layout.segments().iter().enumerate() {
        let physical_address = segment.physical_address();
        let end = segment
            .physical_end()
            .ok_or(NativeHandoffError::ArachPlacement(index))?;
        if physical_address < 0x10_0000 || end > EARLY_MAPPED_PHYSICAL_LIMIT {
            return Err(NativeHandoffError::ArachPlacement(index));
        }
        if segment.file_bytes() == 0 && segment.virtual_address() >= 0xffff_8000_0000_0000 {
            continue;
        }
        let target = boot::allocate_pages(
            boot::AllocateType::Address(physical_address),
            MemoryType::LOADER_DATA,
            page_count(segment.memory_bytes())?,
        )
        .map_err(|_| NativeHandoffError::ArachPlacement(index))?;
        if target.as_ptr() as u64 != physical_address {
            return Err(NativeHandoffError::ArachPlacement(index));
        }
        let file_offset = usize::try_from(segment.file_offset())
            .map_err(|_| NativeHandoffError::ArachPlacement(index))?;
        let file_bytes = usize::try_from(segment.file_bytes())
            .map_err(|_| NativeHandoffError::ArachPlacement(index))?;
        let source_end = file_offset
            .checked_add(file_bytes)
            .ok_or(NativeHandoffError::ArachPlacement(index))?;
        let source = artifact
            .bytes
            .get(file_offset..source_end)
            .ok_or(NativeHandoffError::ArachPlacement(index))?;
        let zero_bytes = page_count(segment.memory_bytes())?
            .checked_mul(PAGE_BYTES as usize)
            .ok_or(NativeHandoffError::PageCount)?;
        unsafe {
            // SAFETY: Granite allocated exactly this page-rounded target range
            // and the checked source range comes from the admitted artifact.
            core::ptr::write_bytes(target.as_ptr(), 0, zero_bytes);
            core::ptr::copy_nonoverlapping(source.as_ptr(), target.as_ptr(), source.len());
        }
    }
    Ok(())
}

fn place_module(
    bytes: &[u8],
    deferred_bss: Option<(u64, u64)>,
) -> Result<PlacedModule, NativeHandoffError> {
    let byte_count = u64::try_from(bytes.len()).map_err(|_| NativeHandoffError::ModulePlacement)?;
    let target = boot::allocate_pages(
        boot::AllocateType::MaxAddress(EARLY_MAPPED_PHYSICAL_LIMIT - 1),
        MemoryType::LOADER_DATA,
        page_count(byte_count)?,
    )
    .map_err(|_| NativeHandoffError::ModulePlacement)?;
    let physical_address = target.as_ptr() as u64;
    let end = physical_address
        .checked_add(byte_count)
        .ok_or(NativeHandoffError::ModulePlacement)?;
    if end > EARLY_MAPPED_PHYSICAL_LIMIT
        || overlaps_deferred_bss(physical_address, end, deferred_bss)
    {
        return Err(NativeHandoffError::ModulePlacement);
    }
    unsafe {
        // SAFETY: the returned page range is at least `bytes.len()` bytes and
        // source and destination cannot overlap.
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), target.as_ptr(), bytes.len());
    }
    Ok(PlacedModule {
        physical_address,
        bytes: byte_count,
    })
}

fn deferred_bss_range(layout: &ExecutableLayout) -> Result<Option<(u64, u64)>, NativeHandoffError> {
    let mut deferred = None;
    for segment in layout.segments() {
        if segment.file_bytes() != 0 || segment.virtual_address() < 0xffff_8000_0000_0000 {
            continue;
        }
        let end = segment
            .physical_end()
            .ok_or(NativeHandoffError::DeferredBssPlacement)?;
        if deferred
            .replace((segment.physical_address(), end))
            .is_some()
        {
            return Err(NativeHandoffError::DeferredBssPlacement);
        }
    }
    Ok(deferred)
}

fn overlaps_deferred_bss(start: u64, end: u64, deferred_bss: Option<(u64, u64)>) -> bool {
    deferred_bss
        .is_some_and(|(reserved_start, reserved_end)| start < reserved_end && reserved_start < end)
}

fn page_count(bytes: u64) -> Result<usize, NativeHandoffError> {
    if bytes == 0 {
        return Err(NativeHandoffError::PageCount);
    }
    let pages = bytes
        .checked_add(PAGE_BYTES - 1)
        .map(|value| value / PAGE_BYTES)
        .ok_or(NativeHandoffError::PageCount)?;
    usize::try_from(pages).map_err(|_| NativeHandoffError::PageCount)
}

fn capture_framebuffer() -> Result<Option<Framebuffer>, NativeHandoffError> {
    let handles =
        boot::find_handles::<GraphicsOutput>().map_err(|_| NativeHandoffError::GraphicsOutput)?;
    let Some(handle) = handles.first().copied() else {
        return Ok(None);
    };
    let mut graphics = unsafe {
        boot::open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|_| NativeHandoffError::GraphicsOutput)?;
    let mode = graphics.current_mode_info();
    let (width, height) = mode.resolution();
    let (red_position, green_position, blue_position) = match mode.pixel_format() {
        GopPixelFormat::Rgb => (0, 8, 16),
        GopPixelFormat::Bgr => (16, 8, 0),
        GopPixelFormat::Bitmask | GopPixelFormat::BltOnly => {
            return Err(NativeHandoffError::GraphicsFormat);
        }
    };
    let pitch = mode
        .stride()
        .checked_mul(4)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(NativeHandoffError::GraphicsFormat)?;
    let mut frame_buffer = graphics.frame_buffer();
    let physical_address = frame_buffer.as_mut_ptr() as u64;
    let byte_length =
        u64::try_from(frame_buffer.size()).map_err(|_| NativeHandoffError::GraphicsFormat)?;
    let width = u32::try_from(width).map_err(|_| NativeHandoffError::GraphicsFormat)?;
    let height = u32::try_from(height).map_err(|_| NativeHandoffError::GraphicsFormat)?;
    Ok(Some(Framebuffer {
        physical_address,
        byte_length,
        width,
        height,
        pitch,
        red_position,
        green_position,
        blue_position,
    }))
}

fn capture_acpi_root() -> Result<AcpiRoot, NativeHandoffError> {
    let address = system::with_config_table(|tables| {
        let mut acpi_v1 = None;
        for entry in tables {
            if entry.guid == ConfigTableEntry::ACPI2_GUID {
                return Some(entry.address as usize);
            }
            if entry.guid == ConfigTableEntry::ACPI_GUID {
                acpi_v1 = Some(entry.address as usize);
            }
        }
        acpi_v1
    })
    .ok_or(NativeHandoffError::AcpiRoot)?;
    if address == 0 || address as u64 >= EARLY_MAPPED_PHYSICAL_LIMIT {
        return Err(NativeHandoffError::AcpiRoot);
    }
    let revision = unsafe {
        // SAFETY: an ACPI configuration table entry supplies a firmware-owned
        // RSDP pointer while boot services are active.
        (address as *const u8).add(15).read_volatile()
    };
    let length = if revision >= 2 {
        let encoded = unsafe {
            // SAFETY: ACPI revision 2 RSDP records include the length field at
            // byte 20; Granite bounds that value before copying it.
            (address as *const u8)
                .add(20)
                .cast::<u32>()
                .read_unaligned()
        };
        usize::try_from(u32::from_le(encoded)).map_err(|_| NativeHandoffError::AcpiRoot)?
    } else {
        20
    };
    if !(20..=MAXIMUM_ACPI_ROOT_BYTES).contains(&length)
        || (address as u64)
            .checked_add(length as u64)
            .is_none_or(|end| end > EARLY_MAPPED_PHYSICAL_LIMIT)
    {
        return Err(NativeHandoffError::AcpiRoot);
    }
    let mut root = AcpiRoot {
        bytes: [0; MAXIMUM_ACPI_ROOT_BYTES],
        length,
    };
    unsafe {
        // SAFETY: the validated firmware range is copied into Granite-owned
        // stack storage before firmware services are exited.
        core::ptr::copy_nonoverlapping(address as *const u8, root.bytes.as_mut_ptr(), root.length);
    }
    if root.bytes[..8] != *b"RSD PTR " {
        return Err(NativeHandoffError::AcpiRoot);
    }
    Ok(root)
}

fn collect_memory_regions(
    memory_map: &impl uefi::mem::memory_map::MemoryMap,
    target: &mut [FirmwareMemoryRegion; MAXIMUM_MEMORY_REGIONS],
) -> Result<usize, HandoffError> {
    let mut count: usize = 0;
    for descriptor in memory_map.entries() {
        let length = descriptor
            .page_count
            .checked_mul(PAGE_BYTES)
            .ok_or(HandoffError::InvalidMemoryRegion)?;
        if length == 0 {
            continue;
        }
        let region = FirmwareMemoryRegion {
            start: descriptor.phys_start,
            length,
            kind: match descriptor.ty {
                MemoryType::CONVENTIONAL
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA => MemoryKind::Usable,
                MemoryType::ACPI_RECLAIM => MemoryKind::AcpiReclaimable,
                MemoryType::ACPI_NON_VOLATILE => MemoryKind::AcpiNonVolatile,
                MemoryType::UNUSABLE => MemoryKind::Defective,
                _ => MemoryKind::Reserved,
            },
        };
        if region.end().is_none() {
            return Err(HandoffError::InvalidMemoryRegion);
        }
        if let Some(previous) = count.checked_sub(1).and_then(|index| target.get_mut(index))
            && previous.kind == region.kind
            && previous.end() == Some(region.start)
        {
            previous.length = previous
                .length
                .checked_add(region.length)
                .ok_or(HandoffError::InvalidMemoryRegion)?;
            continue;
        }
        let slot = target
            .get_mut(count)
            .ok_or(HandoffError::TooManyMemoryRegions)?;
        *slot = region;
        count += 1;
    }
    if count == 0 {
        return Err(HandoffError::InvalidMemoryRegion);
    }
    Ok(count)
}

fn halt_after_boot_services() -> ! {
    loop {
        unsafe {
            // SAFETY: UEFI boot services have ended and this is the terminal
            // failure path before any kernel control transfer.
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
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
/// decision. Granite will replace this hold with Arach's verified transfer.
fn hold_loader_authority() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
