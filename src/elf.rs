//! Bounded ELF64 admission for Granite's native boot artifacts.
//!
//! Granite accepts only an x86-64, little-endian ET_EXEC image with a finite,
//! non-overlapping set of page-aligned `PT_LOAD` segments. The parsed layout is
//! deliberately allocation-free so it remains valid before the loader has
//! chosen any placement memory. A later Granite stage will copy exactly these
//! segments and zero only their admitted tails.

const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const PT_LOAD: u32 = 1;
const PF_EXECUTE: u32 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 0x3e;

/// The loader accepts a deliberately small program-header surface. Boulder
/// currently has eight loadable segments; this leaves headroom without turning
/// an untrusted table into an unbounded boot-time allocation.
pub const MAXIMUM_LOAD_SEGMENTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    file_offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_bytes: u64,
    memory_bytes: u64,
    flags: u32,
}

impl LoadSegment {
    const EMPTY: Self = Self {
        file_offset: 0,
        virtual_address: 0,
        physical_address: 0,
        file_bytes: 0,
        memory_bytes: 0,
        flags: 0,
    };

    pub const fn file_offset(self) -> u64 {
        self.file_offset
    }

    pub const fn virtual_address(self) -> u64 {
        self.virtual_address
    }

    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }

    pub const fn file_bytes(self) -> u64 {
        self.file_bytes
    }

    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    pub const fn executable(self) -> bool {
        self.flags & PF_EXECUTE != 0
    }

    pub const fn file_end(self) -> Option<u64> {
        self.file_offset.checked_add(self.file_bytes)
    }

    pub const fn virtual_end(self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_bytes)
    }

    pub const fn physical_end(self) -> Option<u64> {
        self.physical_address.checked_add(self.memory_bytes)
    }
}

/// Fully checked placement evidence for one executable image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableLayout {
    entry: u64,
    segments: [LoadSegment; MAXIMUM_LOAD_SEGMENTS],
    segment_count: usize,
}

impl ExecutableLayout {
    pub const fn entry(self) -> u64 {
        self.entry
    }

    pub fn segments(&self) -> &[LoadSegment] {
        &self.segments[..self.segment_count]
    }

    /// Checks whether a physical address is part of an executable segment.
    /// Granite uses this to select Boulder's dedicated 64-bit firmware entry
    /// without trusting a second, independently parsed ELF table.
    pub fn contains_executable_physical_address(&self, address: u64) -> bool {
        self.segments().iter().any(|segment| {
            segment.executable()
                && address >= segment.physical_address
                && segment.physical_end().is_some_and(|end| address < end)
        })
    }

    /// Parses the image without trusting any offset, size, alignment, or
    /// address supplied by the image itself.
    pub fn parse(bytes: &[u8]) -> Result<Self, ElfError> {
        if bytes.len() < ELF_HEADER_BYTES {
            return Err(ElfError::TruncatedHeader);
        }
        if bytes.get(..4) != Some(b"\x7fELF") {
            return Err(ElfError::Magic);
        }
        if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
            return Err(ElfError::UnsupportedEncoding);
        }
        if read_u16(bytes, 16)? != ET_EXEC {
            return Err(ElfError::UnsupportedType);
        }
        if read_u16(bytes, 18)? != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }
        if read_u32(bytes, 20)? != 1 {
            return Err(ElfError::UnsupportedVersion);
        }
        if read_u16(bytes, 52)? != ELF_HEADER_BYTES as u16 {
            return Err(ElfError::HeaderSize);
        }
        if read_u16(bytes, 54)? != PROGRAM_HEADER_BYTES as u16 {
            return Err(ElfError::ProgramHeaderSize);
        }

        let entry = read_u64(bytes, 24)?;
        let program_offset = usize::try_from(read_u64(bytes, 32)?)
            .map_err(|_| ElfError::ProgramTableOutsideImage)?;
        let program_count = usize::from(read_u16(bytes, 56)?);
        if program_count == 0 {
            return Err(ElfError::NoLoadSegments);
        }
        let program_bytes = program_count
            .checked_mul(PROGRAM_HEADER_BYTES)
            .ok_or(ElfError::ProgramTableOutsideImage)?;
        let program_end = program_offset
            .checked_add(program_bytes)
            .ok_or(ElfError::ProgramTableOutsideImage)?;
        if program_end > bytes.len() {
            return Err(ElfError::ProgramTableOutsideImage);
        }

        let mut segments = [LoadSegment::EMPTY; MAXIMUM_LOAD_SEGMENTS];
        let mut segment_count = 0;
        let mut entry_is_executable = false;
        let mut index = 0;
        while index < program_count {
            let offset = program_offset + index * PROGRAM_HEADER_BYTES;
            if read_u32(bytes, offset)? != PT_LOAD {
                index += 1;
                continue;
            }
            if segment_count == MAXIMUM_LOAD_SEGMENTS {
                return Err(ElfError::TooManyLoadSegments);
            }
            let flags = read_u32(bytes, offset + 4)?;
            let file_offset = read_u64(bytes, offset + 8)?;
            let virtual_address = read_u64(bytes, offset + 16)?;
            let physical_address = read_u64(bytes, offset + 24)?;
            let file_bytes = read_u64(bytes, offset + 32)?;
            let memory_bytes = read_u64(bytes, offset + 40)?;
            let alignment = read_u64(bytes, offset + 48)?;
            let segment = LoadSegment {
                file_offset,
                virtual_address,
                physical_address,
                file_bytes,
                memory_bytes,
                flags,
            };
            validate_segment(bytes.len(), segment, alignment)?;
            let mut previous = 0;
            while previous < segment_count {
                let accepted = segments[previous];
                if ranges_overlap(
                    segment.virtual_address,
                    segment.virtual_end().ok_or(ElfError::AddressOverflow)?,
                    accepted.virtual_address,
                    accepted.virtual_end().ok_or(ElfError::AddressOverflow)?,
                ) {
                    return Err(ElfError::VirtualOverlap);
                }
                if ranges_overlap(
                    segment.physical_address,
                    segment.physical_end().ok_or(ElfError::AddressOverflow)?,
                    accepted.physical_address,
                    accepted.physical_end().ok_or(ElfError::AddressOverflow)?,
                ) {
                    return Err(ElfError::PhysicalOverlap);
                }
                previous += 1;
            }
            if segment.executable()
                && entry >= segment.virtual_address
                && entry < segment.virtual_end().ok_or(ElfError::AddressOverflow)?
            {
                entry_is_executable = true;
            }
            segments[segment_count] = segment;
            segment_count += 1;
            index += 1;
        }
        if segment_count == 0 {
            return Err(ElfError::NoLoadSegments);
        }
        if !entry_is_executable {
            return Err(ElfError::EntryOutsideExecutableSegment);
        }
        Ok(Self {
            entry,
            segments,
            segment_count,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    TruncatedHeader,
    Magic,
    UnsupportedEncoding,
    UnsupportedType,
    UnsupportedMachine,
    UnsupportedVersion,
    HeaderSize,
    ProgramHeaderSize,
    ProgramTableOutsideImage,
    NoLoadSegments,
    TooManyLoadSegments,
    SegmentFileRange,
    SegmentSize,
    SegmentAlignment,
    AddressOverflow,
    VirtualOverlap,
    PhysicalOverlap,
    EntryOutsideExecutableSegment,
}

impl ElfError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "has a truncated ELF header",
            Self::Magic => "has an invalid ELF magic",
            Self::UnsupportedEncoding => "uses an unsupported ELF encoding",
            Self::UnsupportedType => "is not an ET_EXEC image",
            Self::UnsupportedMachine => "does not target x86-64",
            Self::UnsupportedVersion => "uses an unsupported ELF version",
            Self::HeaderSize => "has an invalid ELF header size",
            Self::ProgramHeaderSize => "has an invalid program-header size",
            Self::ProgramTableOutsideImage => "has a program table outside its bytes",
            Self::NoLoadSegments => "has no loadable segments",
            Self::TooManyLoadSegments => "has too many loadable segments",
            Self::SegmentFileRange => "has a segment outside its bytes",
            Self::SegmentSize => "has an invalid load-segment size",
            Self::SegmentAlignment => "has an invalid load-segment alignment",
            Self::AddressOverflow => "has an overflowing load address",
            Self::VirtualOverlap => "has overlapping virtual load segments",
            Self::PhysicalOverlap => "has overlapping physical load segments",
            Self::EntryOutsideExecutableSegment => "has no executable entry segment",
        }
    }
}

fn validate_segment(
    image_bytes: usize,
    segment: LoadSegment,
    alignment: u64,
) -> Result<(), ElfError> {
    if segment.memory_bytes == 0 || segment.file_bytes > segment.memory_bytes {
        return Err(ElfError::SegmentSize);
    }
    if alignment < 4096 || !alignment.is_power_of_two() {
        return Err(ElfError::SegmentAlignment);
    }
    if segment.file_offset % alignment != segment.virtual_address % alignment
        || segment.file_offset % alignment != segment.physical_address % alignment
    {
        return Err(ElfError::SegmentAlignment);
    }
    let file_end = segment.file_end().ok_or(ElfError::SegmentFileRange)?;
    if file_end > image_bytes as u64 {
        return Err(ElfError::SegmentFileRange);
    }
    if segment.virtual_end().is_none() || segment.physical_end().is_none() {
        return Err(ElfError::AddressOverflow);
    }
    Ok(())
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let source = bytes
        .get(offset..offset + 2)
        .ok_or(ElfError::TruncatedHeader)?;
    Ok(u16::from_le_bytes([source[0], source[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let source = bytes
        .get(offset..offset + 4)
        .ok_or(ElfError::TruncatedHeader)?;
    Ok(u32::from_le_bytes([
        source[0], source[1], source[2], source[3],
    ]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    let source = bytes
        .get(offset..offset + 8)
        .ok_or(ElfError::TruncatedHeader)?;
    Ok(u64::from_le_bytes([
        source[0], source[1], source[2], source[3], source[4], source[5], source[6], source[7],
    ]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    const PROGRAM_OFFSET: usize = ELF_HEADER_BYTES;
    const SEGMENT_OFFSET: usize = 0x1000;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn image() -> Vec<u8> {
        let mut bytes = vec![0; 0x1100];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, ET_EXEC);
        put_u16(&mut bytes, 18, EM_X86_64);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 24, 0x1000);
        put_u64(&mut bytes, 32, PROGRAM_OFFSET as u64);
        put_u16(&mut bytes, 52, ELF_HEADER_BYTES as u16);
        put_u16(&mut bytes, 54, PROGRAM_HEADER_BYTES as u16);
        put_u16(&mut bytes, 56, 1);
        put_u32(&mut bytes, PROGRAM_OFFSET, PT_LOAD);
        put_u32(&mut bytes, PROGRAM_OFFSET + 4, PF_EXECUTE);
        put_u64(&mut bytes, PROGRAM_OFFSET + 8, SEGMENT_OFFSET as u64);
        put_u64(&mut bytes, PROGRAM_OFFSET + 16, 0x1000);
        put_u64(&mut bytes, PROGRAM_OFFSET + 24, 0x1000);
        put_u64(&mut bytes, PROGRAM_OFFSET + 32, 0x40);
        put_u64(&mut bytes, PROGRAM_OFFSET + 40, 0x80);
        put_u64(&mut bytes, PROGRAM_OFFSET + 48, 0x1000);
        bytes
    }

    #[test]
    fn accepts_bounded_executable_layout() {
        let layout = ExecutableLayout::parse(&image()).unwrap();
        assert_eq!(layout.entry(), 0x1000);
        assert_eq!(layout.segments().len(), 1);
        assert_eq!(layout.segments()[0].memory_bytes(), 0x80);
    }

    #[test]
    fn rejects_entry_outside_executable_load_segment() {
        let mut bytes = image();
        put_u32(&mut bytes, PROGRAM_OFFSET + 4, 0);
        assert_eq!(
            ExecutableLayout::parse(&bytes),
            Err(ElfError::EntryOutsideExecutableSegment)
        );
    }

    #[test]
    fn rejects_overlapping_physical_segments() {
        let mut bytes = image();
        put_u16(&mut bytes, 56, 2);
        let second = PROGRAM_OFFSET + PROGRAM_HEADER_BYTES;
        let first = bytes[PROGRAM_OFFSET..PROGRAM_OFFSET + PROGRAM_HEADER_BYTES].to_vec();
        bytes[second..second + PROGRAM_HEADER_BYTES].copy_from_slice(&first);
        put_u64(&mut bytes, second + 16, 0x3000);
        assert_eq!(
            ExecutableLayout::parse(&bytes),
            Err(ElfError::PhysicalOverlap)
        );
    }
}
