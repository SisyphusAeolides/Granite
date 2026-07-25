//! Bounded construction of the Multiboot2-shaped handoff consumed by Boulder.
//!
//! Granite owns firmware discovery, but Boulder already has a carefully
//! validated Multiboot2 information parser.  This module writes only the
//! subset of that record Boulder consumes, into loader-owned physical memory,
//! after every source datum has been bounds checked.

use crate::elf::ExecutableLayout;

pub const PAGE_BYTES: u64 = 4096;
pub const EARLY_MAPPED_PHYSICAL_LIMIT: u64 = 1024 * 1024 * 1024;
pub const GRANITE_BOOTSTRAP_ENTRY_PHYSICAL: u64 = 0x0010_1000;
pub const MAXIMUM_MEMORY_REGIONS: usize = 128;

const MULTIBOOT_HEADER_BYTES: usize = 8;
const TAG_END: u32 = 0;
const TAG_MODULE: u32 = 3;
const TAG_MEMORY_MAP: u32 = 6;
const TAG_FRAMEBUFFER: u32 = 8;
const TAG_ACPI_NEW: u32 = 15;
const MEMORY_MAP_HEADER_BYTES: usize = 16;
const MEMORY_MAP_ENTRY_BYTES: usize = 24;
const MODULE_HEADER_BYTES: usize = 16;
const FRAMEBUFFER_TAG_BYTES: usize = 38;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNonVolatile,
    Defective,
}

impl MemoryKind {
    const fn multiboot_type(self) -> u32 {
        match self {
            Self::Usable => 1,
            Self::AcpiReclaimable => 3,
            Self::AcpiNonVolatile => 4,
            Self::Defective => 5,
            Self::Reserved => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareMemoryRegion {
    pub start: u64,
    pub length: u64,
    pub kind: MemoryKind,
}

impl FirmwareMemoryRegion {
    pub const EMPTY: Self = Self {
        start: 0,
        length: 0,
        kind: MemoryKind::Reserved,
    };

    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootModule<'a> {
    pub start: u64,
    pub bytes: u64,
    pub name: &'a [u8],
}

impl BootModule<'_> {
    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Framebuffer {
    pub physical_address: u64,
    pub byte_length: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub red_position: u8,
    pub green_position: u8,
    pub blue_position: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    BoulderBootstrapOutsideExecutableSegment,
    BoulderSegmentOutsideEarlyMap,
    TooManyMemoryRegions,
    InvalidMemoryRegion,
    InvalidModule,
    InvalidFramebuffer,
    InvalidAcpiRoot,
    BufferTooSmall,
    SizeOverflow,
}

/// Ensures the image being placed contains Granite's fixed 64-bit entry and
/// every loaded Boulder byte remains inside the page tables that entry builds.
pub fn validate_boulder_layout(layout: &ExecutableLayout) -> Result<(), HandoffError> {
    if !layout.contains_executable_physical_address(GRANITE_BOOTSTRAP_ENTRY_PHYSICAL) {
        return Err(HandoffError::BoulderBootstrapOutsideExecutableSegment);
    }
    for segment in layout.segments() {
        if segment.physical_address() >= EARLY_MAPPED_PHYSICAL_LIMIT
            || segment
                .physical_end()
                .is_none_or(|end| end > EARLY_MAPPED_PHYSICAL_LIMIT)
        {
            return Err(HandoffError::BoulderSegmentOutsideEarlyMap);
        }
    }
    Ok(())
}

/// Writes a complete, aligned Multiboot2 information structure and returns its
/// exact byte length.  The caller owns the storage for the duration of Boulder
/// bootstrap.
pub fn write_multiboot2(
    target: &mut [u8],
    memory_regions: &[FirmwareMemoryRegion],
    modules: &[BootModule<'_>],
    framebuffer: Option<Framebuffer>,
    acpi_root: &[u8],
) -> Result<usize, HandoffError> {
    if memory_regions.len() > MAXIMUM_MEMORY_REGIONS {
        return Err(HandoffError::TooManyMemoryRegions);
    }
    if !(20..=4096).contains(&acpi_root.len()) {
        return Err(HandoffError::InvalidAcpiRoot);
    }
    for region in memory_regions {
        if region.length == 0 || region.end().is_none() {
            return Err(HandoffError::InvalidMemoryRegion);
        }
    }
    for module in modules {
        let Some(end) = module.end() else {
            return Err(HandoffError::InvalidModule);
        };
        if module.bytes == 0
            || end > u64::from(u32::MAX)
            || module.name.is_empty()
            || module.name.contains(&0)
        {
            return Err(HandoffError::InvalidModule);
        }
    }
    if let Some(framebuffer) = framebuffer {
        let Some(required_bytes) =
            u64::from(framebuffer.pitch).checked_mul(u64::from(framebuffer.height))
        else {
            return Err(HandoffError::InvalidFramebuffer);
        };
        if framebuffer.physical_address == 0
            || framebuffer.width == 0
            || framebuffer.height == 0
            || framebuffer.pitch < framebuffer.width.saturating_mul(4)
            || required_bytes > framebuffer.byte_length
            || framebuffer
                .physical_address
                .checked_add(required_bytes)
                .is_none()
        {
            return Err(HandoffError::InvalidFramebuffer);
        }
    }

    let mut writer = Writer::new(target);
    writer.reserve(MULTIBOOT_HEADER_BYTES)?;
    writer.memory_map(memory_regions)?;
    for module in modules {
        writer.module(*module)?;
    }
    if let Some(framebuffer) = framebuffer {
        writer.framebuffer(framebuffer)?;
    }
    writer.acpi_root(acpi_root)?;
    writer.tag_header(TAG_END, 8)?;

    let total = writer.cursor;
    let total = u32::try_from(total).map_err(|_| HandoffError::SizeOverflow)?;
    writer.target[..4].copy_from_slice(&total.to_le_bytes());
    writer.target[4..8].fill(0);
    Ok(total as usize)
}

struct Writer<'a> {
    target: &'a mut [u8],
    cursor: usize,
}

impl<'a> Writer<'a> {
    fn new(target: &'a mut [u8]) -> Self {
        Self { target, cursor: 0 }
    }

    fn reserve(&mut self, bytes: usize) -> Result<usize, HandoffError> {
        let start = self.cursor;
        let end = start.checked_add(bytes).ok_or(HandoffError::SizeOverflow)?;
        let destination = self
            .target
            .get_mut(start..end)
            .ok_or(HandoffError::BufferTooSmall)?;
        destination.fill(0);
        self.cursor = end;
        Ok(start)
    }

    fn align(&mut self) -> Result<(), HandoffError> {
        let end = self
            .cursor
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or(HandoffError::SizeOverflow)?;
        self.reserve(end.saturating_sub(self.cursor))?;
        Ok(())
    }

    fn tag_header(&mut self, kind: u32, size: usize) -> Result<(), HandoffError> {
        let size = u32::try_from(size).map_err(|_| HandoffError::SizeOverflow)?;
        let start = self.reserve(8)?;
        self.target[start..start + 4].copy_from_slice(&kind.to_le_bytes());
        self.target[start + 4..start + 8].copy_from_slice(&size.to_le_bytes());
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), HandoffError> {
        let start = self.reserve(1)?;
        self.target[start] = value;
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<(), HandoffError> {
        let start = self.reserve(2)?;
        self.target[start..start + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), HandoffError> {
        let start = self.reserve(4)?;
        self.target[start..start + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), HandoffError> {
        let start = self.reserve(8)?;
        self.target[start..start + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), HandoffError> {
        let start = self.reserve(bytes.len())?;
        self.target[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn memory_map(&mut self, regions: &[FirmwareMemoryRegion]) -> Result<(), HandoffError> {
        let payload = regions
            .len()
            .checked_mul(MEMORY_MAP_ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(MEMORY_MAP_HEADER_BYTES))
            .ok_or(HandoffError::SizeOverflow)?;
        self.tag_header(TAG_MEMORY_MAP, payload)?;
        self.write_u32(MEMORY_MAP_ENTRY_BYTES as u32)?;
        self.write_u32(0)?;
        for region in regions {
            self.write_u64(region.start)?;
            self.write_u64(region.length)?;
            self.write_u32(region.kind.multiboot_type())?;
            self.write_u32(0)?;
        }
        self.align()
    }

    fn module(&mut self, module: BootModule<'_>) -> Result<(), HandoffError> {
        let payload = MODULE_HEADER_BYTES
            .checked_add(module.name.len())
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(HandoffError::SizeOverflow)?;
        self.tag_header(TAG_MODULE, payload)?;
        self.write_u32(module.start as u32)?;
        self.write_u32(module.end().ok_or(HandoffError::InvalidModule)? as u32)?;
        self.write_bytes(module.name)?;
        self.write_u8(0)?;
        self.align()
    }

    fn framebuffer(&mut self, framebuffer: Framebuffer) -> Result<(), HandoffError> {
        self.tag_header(TAG_FRAMEBUFFER, FRAMEBUFFER_TAG_BYTES)?;
        self.write_u64(framebuffer.physical_address)?;
        self.write_u32(framebuffer.pitch)?;
        self.write_u32(framebuffer.width)?;
        self.write_u32(framebuffer.height)?;
        self.write_u8(32)?;
        self.write_u8(1)?;
        self.write_u16(0)?;
        self.write_u8(framebuffer.red_position)?;
        self.write_u8(8)?;
        self.write_u8(framebuffer.green_position)?;
        self.write_u8(8)?;
        self.write_u8(framebuffer.blue_position)?;
        self.write_u8(8)?;
        self.align()
    }

    fn acpi_root(&mut self, acpi_root: &[u8]) -> Result<(), HandoffError> {
        let payload = 8_usize
            .checked_add(acpi_root.len())
            .ok_or(HandoffError::SizeOverflow)?;
        self.tag_header(TAG_ACPI_NEW, payload)?;
        self.write_bytes(acpi_root)?;
        self.align()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_bounded_aligned_boot_record() {
        let regions = [FirmwareMemoryRegion {
            start: 0x10_0000,
            length: 0x40_0000,
            kind: MemoryKind::Usable,
        }];
        let modules = [
            BootModule {
                start: 0x60_0000,
                bytes: 0x1000,
                name: b"push",
            },
            BootModule {
                start: 0x61_0000,
                bytes: 0x1000,
                name: b"crest",
            },
        ];
        let mut rsdp = [0_u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        let mut bytes = [0_u8; 512];
        let used = write_multiboot2(
            &mut bytes,
            &regions,
            &modules,
            Some(Framebuffer {
                physical_address: 0xe000_0000,
                byte_length: 4096 * 768,
                width: 1024,
                height: 768,
                pitch: 4096,
                red_position: 16,
                green_position: 8,
                blue_position: 0,
            }),
            &rsdp,
        )
        .unwrap();

        assert_eq!(used % 8, 0);
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            used
        );
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            TAG_MEMORY_MAP
        );
        assert_eq!(
            u32::from_le_bytes(bytes[used - 8..used - 4].try_into().unwrap()),
            TAG_END
        );
    }

    #[test]
    fn rejects_a_module_that_cannot_be_represented_by_multiboot() {
        let regions = [FirmwareMemoryRegion {
            start: 0x10_0000,
            length: 0x40_0000,
            kind: MemoryKind::Usable,
        }];
        let modules = [BootModule {
            start: u64::from(u32::MAX),
            bytes: 2,
            name: b"push",
        }];
        let mut bytes = [0_u8; 256];
        assert_eq!(
            write_multiboot2(&mut bytes, &regions, &modules, None, &[0; 20]),
            Err(HandoffError::InvalidModule)
        );
    }
}
