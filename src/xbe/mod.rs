mod raw;

use bitflags::bitflags;
use itertools::Itertools;
use std::ops::Range;

macro_rules! round_to_next {
    ($num:expr, $round_to:expr) => {{
        let n = $num;
        let to = $round_to;
        n + ((to - n % to) % to)
    }};
}

pub struct Xbe {
    pub header: Header,
    pub sections: Vec<Section>,
    library_versions: Vec<raw::LibraryVersion>,
    logo_bitmap: raw::LogoBitmap,
}

impl Xbe {
    pub fn new(bytes: &[u8]) -> Result<Self, std::io::Error> {
        Ok(Self::from_raw(raw::Xbe::load(bytes)?))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        self.convert_to_raw().serialize()
    }

    pub fn get_next_virtual_address(&self) -> u32 {
        match self.sections.last() {
            None => 0,
            Some(s) => {
                let end = s.virtual_address + s.virtual_size;
                round_to_next!(end, 0x20)
            }
        }
    }

    pub fn get_next_virtual_address_after(&self, after: u32) -> u32 {
        round_to_next!(after, 0x20)
    }

    pub fn add_section(
        &mut self,
        name: String,
        flags: SectionFlags,
        data: Vec<u8>,
        virtual_address: u32,
        virtual_size: u32,
    ) {
        let raw_address = self
            .sections
            .iter()
            .sorted_by(|a, b| a.raw_address.cmp(&b.raw_address))
            .last()
            // TODO: this assumes raw_size == virtual_size
            .map(|a| round_to_next!(a.raw_address + a.virtual_size, 0x1000))
            .unwrap_or(0);

        let section = Section {
            name,
            flags,
            data,
            virtual_address,
            virtual_size,
            raw_address,
            digest: None,
        };
        self.sections.push(section);
    }

    // TODO
    #[allow(dead_code)]
    pub fn get_bytes(&self, virtual_range: Range<u32>) -> Option<&[u8]> {
        let section = self.sections.iter().find(|s| {
            s.virtual_address <= virtual_range.start
                && s.virtual_address + s.virtual_size >= virtual_range.end
        })?;

        let start = (virtual_range.start - section.virtual_address) as usize;
        let end = (virtual_range.end - section.virtual_address) as usize;
        Some(&section.data[start..end])
    }

    pub fn get_bytes_mut(&mut self, virtual_range: Range<u32>) -> Option<&mut [u8]> {
        let section = self.sections.iter_mut().find(|s| {
            s.virtual_address <= virtual_range.start
                && s.virtual_address + s.virtual_size >= virtual_range.end
        })?;

        let start = (virtual_range.start - section.virtual_address) as usize;
        let end = (virtual_range.end - section.virtual_address) as usize;
        Some(&mut section.data[start..end])
    }

    fn convert_to_raw(&self) -> raw::Xbe {
        let base_address = 0x10000;
        let image_header_size = 0x184;
        let certificate = raw::Certificate {
            size: raw::Certificate::SIZE,
            time_date: self.header.cert_time_date,
            title_id: self.header.title_id.unwrap_or(0),
            title_name: self.header.title_name,
            alternate_title_ids: [0u8; 0x40],
            allowed_media: self.header.allowed_media.bits,
            game_region: self.header.game_region.bits,
            game_ratings: self.header.game_ratings.unwrap_or(0xFFFFFFFF),
            disk_number: 0,
            version: self.header.cert_version,
            lan_key: self.header.lan_key.unwrap_or([0u8; 0x10]),
            signature_key: self.header.signature_key.unwrap_or([0u8; 0x10]),
            alternate_signature_keys: self.header.alternate_signature_keys.unwrap_or([0u8; 0x100]),
            unknown: self.header.unknown.clone(),
        };
        let certificate_size = raw::Certificate::SIZE;

        let mut section_names_size = 0;
        let mut section_name_offsets = vec![];
        let section_names: Vec<String> = self
            .sections
            .iter()
            .map(|s| {
                section_name_offsets.push(section_names_size);
                section_names_size += s.name.len() as u32;
                s.name.clone()
            })
            .collect();
        section_names_size = round_to_next!(section_names_size, 4);

        // Size of sections headers plus size of head/tail reference pages
        let section_headers_size = self.sections.len() as u32 * 0x38;
        let section_page_reference_size = self.sections.len() as u32 * 2 + 2;

        // TODO: This assumes the header will never grow past 0x1000 bytes
        // Fixing this requires managing more pointers like TLS, Kernel Thunk,
        // and Entry Point, as it will move the vanilla sections
        // (Actually these may all be virtual addresses, entry point certainly is, investigate more)
        let section_headers: Vec<raw::SectionHeader> = self
            .sections
            .iter()
            .enumerate()
            .map(|(i, s)| raw::SectionHeader {
                section_flags: s.flags.bits,
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_address: s.raw_address,
                raw_size: s.data.len() as u32,
                section_name_address: base_address
                    + image_header_size
                    + certificate_size
                    + section_headers_size
                    + section_page_reference_size
                    + section_name_offsets[i],
                section_name_reference_count: 0,
                head_shared_page_reference_count_address: base_address
                    + image_header_size
                    + certificate_size
                    + section_headers_size
                    + i as u32 * 2,
                tail_shared_page_reference_count_address: base_address
                    + image_header_size
                    + certificate_size
                    + section_headers_size
                    + i as u32 * 2
                    + 2,
                section_digest: s.digest.unwrap_or([0u8; 0x14]),
            })
            .collect();

        let library_versions = self.library_versions.clone();
        let kernel_index = library_versions
            .iter()
            .position(|l| l.library_name.eq(b"XBOXKRNL"))
            .expect("No Kernel Library!");
        let xapi_index = library_versions
            .iter()
            .position(|l| l.library_name.eq(b"XAPILIB\0"))
            .expect("No XAPILIB!");
        let library_versions_size = library_versions.len() as u32 * 0x10;

        let sections: Vec<raw::Section> = self
            .sections
            .iter()
            .map(|s| raw::Section {
                bytes: s.data.clone(),
            })
            .collect();

        let size_of_image = section_headers
            .iter()
            .sorted_by(|a, b| a.virtual_address.cmp(&b.virtual_address))
            .last()
            .map(|x| round_to_next!(x.virtual_address + x.virtual_size, 0x20))
            .unwrap_or(base_address)
            - base_address;

        // pathname and filename are part of the same string, so it's not added to the total
        let debug_strings_size = self.header.debug_unicode_filename.len() as u32 * 2
            + self.header.debug_pathname.len() as u32;
        let debug_unicode_filename_address = image_header_size
            + certificate_size
            + section_headers_size
            + section_page_reference_size
            + section_names_size
            + library_versions_size
            + base_address;
        let debug_pathname_address =
            debug_unicode_filename_address + self.header.debug_unicode_filename.len() as u32 * 2;
        let debug_filename_address = debug_pathname_address
            + self
                .header
                .debug_pathname
                .rfind('\\')
                .expect("Malformed debug path") as u32
            + 1;
        let logo_bitmap_size = self.logo_bitmap.bitmap.len() as u32;
        let mut size_of_headers = image_header_size
            + certificate_size
            + section_headers_size
            + section_page_reference_size
            + section_names_size
            + library_versions_size
            + debug_strings_size
            + logo_bitmap_size;
        size_of_headers = round_to_next!(size_of_headers, 4);

        let image_header = raw::ImageHeader {
            magic_number: b"XBEH".to_owned(),
            digital_signature: self.header.digital_signature.unwrap_or([0u8; 256]),
            base_address,
            size_of_headers,
            size_of_image,
            size_of_image_header: image_header_size,
            time_date: self.header.image_time_date,
            certificate_address: image_header_size + base_address,
            number_of_sections: self.sections.len() as u32,
            section_headers_address: image_header_size + certificate_size + base_address,
            initialization_flags: 5,
            entry_point: self.header.entry_point,
            tls_address: self.header.tls_address,
            pe_stack_commit: self.header.pe.stack_commit,
            pe_heap_reserve: self.header.pe.heap_reserve,
            pe_head_commit: self.header.pe.head_commit,
            pe_base_address: self.header.pe.base_address,
            pe_size_of_image: self.header.pe.size_of_image,
            pe_checksum: self.header.pe.checksum,
            pe_time_date: self.header.pe.timedate,
            debug_pathname_address,
            debug_filename_address,
            debug_unicode_filename_address,
            kernel_image_thunk_address: self.header.kernel_image_thunk_address,
            non_kernel_import_directory_address: 0,
            number_of_library_versions: self.library_versions.len() as u32,
            library_versions_address: image_header_size
                + certificate_size
                + section_headers_size
                + section_page_reference_size
                + section_names_size
                + base_address,
            kernel_library_version_address: image_header_size
                + certificate_size
                + section_headers_size
                + section_page_reference_size
                + section_names_size
                + kernel_index as u32 * 0x10
                + base_address,
            xapi_library_version_address: image_header_size
                + certificate_size
                + section_headers_size
                + section_page_reference_size
                + section_names_size
                + xapi_index as u32 * 0x10
                + base_address,
            logo_bitmap_address: image_header_size
                + certificate_size
                + section_headers_size
                + section_page_reference_size
                + section_names_size
                + library_versions_size
                + debug_strings_size
                + base_address,
            logo_bitmap_size,
        };

        raw::Xbe {
            image_header,
            certificate,
            section_headers,
            section_names,
            library_versions,
            debug_pathname: self.header.debug_pathname.clone(),
            debug_filename: self.header.debug_filename.clone(),
            debug_unicode_filename: self.header.debug_unicode_filename.clone(),
            logo_bitmap: self.logo_bitmap.clone(),
            sections,
        }
    }

    fn from_raw(xbe: raw::Xbe) -> Self {
        let pe = PE {
            stack_commit: xbe.image_header.pe_stack_commit,
            heap_reserve: xbe.image_header.pe_heap_reserve,
            head_commit: xbe.image_header.pe_head_commit,
            base_address: xbe.image_header.pe_base_address,
            size_of_image: xbe.image_header.pe_size_of_image,
            checksum: xbe.image_header.pe_checksum,
            timedate: xbe.image_header.pe_time_date,
        };

        let header = Header {
            digital_signature: Some(xbe.image_header.digital_signature),
            debug_pathname: xbe.debug_pathname,
            debug_filename: xbe.debug_filename,
            debug_unicode_filename: xbe.debug_unicode_filename,
            image_time_date: xbe.image_header.time_date,
            entry_point: xbe.image_header.entry_point,
            tls_address: xbe.image_header.tls_address,
            pe,
            kernel_image_thunk_address: xbe.image_header.kernel_image_thunk_address,
            cert_time_date: xbe.certificate.time_date,
            title_id: Some(xbe.certificate.title_id),
            title_name: xbe.certificate.title_name,
            allowed_media: AllowedMedia::from_bits_truncate(xbe.certificate.allowed_media),
            game_ratings: Some(xbe.certificate.game_ratings),
            game_region: GameRegion::from_bits_truncate(xbe.certificate.game_region),
            cert_version: xbe.certificate.version,
            lan_key: Some(xbe.certificate.lan_key),
            signature_key: Some(xbe.certificate.signature_key),
            alternate_signature_keys: Some(xbe.certificate.alternate_signature_keys),
            unknown: xbe.certificate.unknown,
        };

        let sections = xbe
            .sections
            .into_iter()
            .zip(xbe.section_headers.into_iter())
            .zip(xbe.section_names.into_iter())
            .map(|((sec, hdr), name)| Section {
                name,
                flags: SectionFlags::from_bits_truncate(hdr.section_flags),
                virtual_address: hdr.virtual_address,
                virtual_size: hdr.virtual_size,
                data: sec.bytes,
                raw_address: hdr.raw_address,
                digest: Some(hdr.section_digest),
            })
            .collect();

        Xbe {
            header,
            sections,
            library_versions: xbe.library_versions,
            logo_bitmap: xbe.logo_bitmap,
        }
    }
}

pub struct Header {
    pub digital_signature: Option<[u8; 0x100]>,
    pub debug_pathname: String,
    pub debug_filename: String,
    pub debug_unicode_filename: Vec<u16>,
    pub image_time_date: u32,
    pub entry_point: u32,
    pub tls_address: u32,
    pub pe: PE,
    pub kernel_image_thunk_address: u32,
    pub cert_time_date: u32,
    pub title_id: Option<u32>,
    pub title_name: [u8; 0x50],
    pub allowed_media: AllowedMedia,
    pub game_ratings: Option<u32>,
    pub game_region: GameRegion,
    pub cert_version: u32,
    pub lan_key: Option<[u8; 0x10]>,
    pub signature_key: Option<[u8; 0x10]>,
    pub alternate_signature_keys: Option<[u8; 0x100]>,
    pub unknown: Vec<u8>,
}

pub struct PE {
    stack_commit: u32,
    heap_reserve: u32,
    head_commit: u32,
    base_address: u32,
    size_of_image: u32,
    checksum: u32,
    timedate: u32,
}

bitflags! {
    pub struct AllowedMedia : u32 {
        const XBEIMAGE_MEDIA_TYPE_HARD_DISK           = 0x00000001;
        const XBEIMAGE_MEDIA_TYPE_DVD_X2              = 0x00000002;
        const XBEIMAGE_MEDIA_TYPE_DVD_CD              = 0x00000004;
        const XBEIMAGE_MEDIA_TYPE_CD                  = 0x00000008;
        const XBEIMAGE_MEDIA_TYPE_DVD_5_RO            = 0x00000010;
        const XBEIMAGE_MEDIA_TYPE_DVD_9_RO            = 0x00000020;
        const XBEIMAGE_MEDIA_TYPE_DVD_5_RW            = 0x00000040;
        const XBEIMAGE_MEDIA_TYPE_DVD_9_RW            = 0x00000080;
        const XBEIMAGE_MEDIA_TYPE_DONGLE              = 0x00000100;
        const XBEIMAGE_MEDIA_TYPE_MEDIA_BOARD         = 0x00000200;
        const XBEIMAGE_MEDIA_TYPE_NONSECURE_HARD_DISK = 0x40000000;
        const XBEIMAGE_MEDIA_TYPE_NONSECURE_MODE      = 0x80000000;
        const XBEIMAGE_MEDIA_TYPE_MEDIA_MASK          = 0x00FFFFFF;
    }
}

bitflags! {
    pub struct GameRegion : u32 {
        const REGION_NA = 0x1;
        const REGION_JAPAN = 0x2;
        const REGION_REST_OF_WORLD = 0x4;
        const REGION_MANUFACTURING = 0x80000000;
    }
}

pub struct Section {
    pub name: String,
    pub flags: SectionFlags,
    pub data: Vec<u8>,
    pub virtual_address: u32,
    pub virtual_size: u32,
    raw_address: u32,
    digest: Option<[u8; 0x14]>,
}

impl std::fmt::Debug for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Section")
            .field("Name", &self.name)
            .field("Virtual Address", &self.virtual_address)
            .field("Virtual Size", &self.virtual_size)
            .field("Raw Address", &self.raw_address)
            .finish()
    }
}

bitflags! {
    pub struct SectionFlags : u32 {
        const WRITABLE = 0x1;
        const PRELOAD = 0x2;
        const EXECUTABLE= 0x4;
        const INSERTED_FILE = 0x8;
        const HEAD_PAGE_READ_ONLY = 0x10;
        const TAIL_PAGE_READ_ONLY = 0x20;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Read an xbe and immediately serialize it to a new file, asserting that both files
    /// are identical
    fn vanilla_serialization() -> Result<(), std::io::Error> {
        use sha1::{Digest, Sha1};

        let default_bytes = std::fs::read("test/bin/default.xbe")?;
        let default_hash = {
            let mut hasher = Sha1::new();
            hasher.update(&default_bytes);
            hasher.finalize()
        };

        let xbe = Xbe::new(&default_bytes)?;
        let bytes = xbe.serialize()?;
        let output_hash = {
            let mut hasher = Sha1::new();
            hasher.update(&bytes);
            hasher.finalize()
        };

        assert_eq!(*default_hash, *output_hash);
        Ok(())
    }
}
