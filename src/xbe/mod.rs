mod raw;

use std::{ops::Range, path::Path};

use bitflags::bitflags;

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
    pub fn from_path<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self::from_raw(&raw::load_xbe(std::fs::File::open(path).unwrap()).unwrap())
    }

    pub fn write_to_file<P>(&self, path: P)
    where
        P: AsRef<Path>,
    {
        std::fs::write(path, &self.convert_to_raw().serialize().unwrap()).unwrap();
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

    pub fn add_section(&mut self, section: Section) {
        self.sections.push(section);
    }

    #[allow(dead_code)]
    pub fn get_bytes(&self, virtual_range: Range<u32>) -> Result<&[u8], String> {
        let section = self.sections.iter().find(|s| {
            s.virtual_address <= virtual_range.start
                && s.virtual_address + s.virtual_size >= virtual_range.end
        });

        if section.is_none() {
            return Err(format!(
                "Virtual address range [{},{}) is not used in this XBE",
                virtual_range.start, virtual_range.end
            ));
        }
        let section = section.unwrap();

        let start = (virtual_range.start - section.virtual_address) as usize;
        let end = (virtual_range.end - section.virtual_address) as usize;
        Ok(&section.data[start..end])
    }

    pub fn get_bytes_mut(&mut self, virtual_range: Range<u32>) -> Result<&mut [u8], String> {
        let section = self.sections.iter_mut().find(|s| {
            s.virtual_address <= virtual_range.start
                && s.virtual_address + s.virtual_size >= virtual_range.end
        });

        if section.is_none() {
            return Err(format!(
                "Virtual address range [{},{}) is not used in this XBE",
                virtual_range.start, virtual_range.end
            ));
        }
        let section = section.unwrap();

        let start = (virtual_range.start - section.virtual_address) as usize;
        let end = (virtual_range.end - section.virtual_address) as usize;
        Ok(&mut section.data[start..end])
    }

    fn convert_to_raw(&self) -> raw::Xbe {
        let base_address = 0x10000;
        let image_header_size = 0x184;
        let certificate = raw::Certificate {
            size: raw::Certificate::SIZE,
            time_date: self.header.cert_time_date,
            title_id: 0,
            title_name: self.header.title_name,
            alternate_title_ids: [0u8; 0x40],
            allowed_media: self.header.allowed_media.bits,
            game_region: self.header.game_region.bits,
            game_ratings: 0xFFFFFFFF,
            disk_number: 0,
            version: self.header.cert_version,
            lan_key: [0u8; 0x10],
            signature_key: [0u8; 0x10],
            alternate_signature_keys: [0u8; 0x100],
            reserved: [0u8; 0x1C].to_vec(),
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

        // TODO: Use the virtual_address field added to Section (and ensure that
        // it is properly set)
        let mut virtual_address = 0x11000;
        let mut raw_address = 0x1000;
        let section_headers: Vec<raw::SectionHeader> = self
            .sections
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let virtual_size = s.virtual_size;
                let raw_size = s.data.len() as u32;
                let hdr = raw::SectionHeader {
                    section_flags: s.flags.bits,
                    virtual_address,
                    virtual_size,
                    raw_address,
                    raw_size,
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
                    section_digest: [0u8; 0x14],
                };
                virtual_address += virtual_size;
                virtual_address = round_to_next!(virtual_address, 0x20);
                raw_address += raw_size;
                raw_address = round_to_next!(raw_address, 0x1000);
                hdr
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

        let size_of_image = virtual_address - base_address;

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
            digital_signature: [0u8; 256],
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

    fn from_raw(xbe: &raw::Xbe) -> Self {
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
            debug_pathname: xbe.debug_pathname.clone(),
            debug_filename: xbe.debug_filename.clone(),
            debug_unicode_filename: xbe.debug_unicode_filename.clone(),
            image_time_date: xbe.image_header.time_date,
            entry_point: xbe.image_header.entry_point,
            tls_address: xbe.image_header.tls_address,
            pe,
            kernel_image_thunk_address: xbe.image_header.kernel_image_thunk_address,
            cert_time_date: xbe.certificate.time_date,
            title_name: xbe.certificate.title_name,
            allowed_media: AllowedMedia::from_bits_truncate(xbe.certificate.allowed_media),
            game_region: GameRegion::from_bits_truncate(xbe.certificate.game_region),
            cert_version: xbe.certificate.version,
        };

        let sections = xbe
            .sections
            .iter()
            .zip(xbe.section_headers.iter())
            .zip(xbe.section_names.iter())
            .map(|t| Section {
                name: t.1.clone(),
                flags: SectionFlags::from_bits_truncate(t.0 .1.section_flags),
                virtual_address: t.0 .1.virtual_address,
                virtual_size: t.0 .1.virtual_size,
                data: t.0 .0.bytes.clone(),
            })
            .collect();

        Xbe {
            header,
            sections,
            library_versions: xbe.library_versions.clone(),
            logo_bitmap: xbe.logo_bitmap.clone(),
        }
    }
}

pub struct Header {
    pub debug_pathname: String,
    pub debug_filename: String,
    pub debug_unicode_filename: Vec<u16>,
    pub image_time_date: u32,
    pub entry_point: u32,
    pub tls_address: u32,
    pub pe: PE,
    pub kernel_image_thunk_address: u32,
    pub cert_time_date: u32,
    pub title_name: [u8; 0x50],
    pub allowed_media: AllowedMedia,
    pub game_region: GameRegion,
    pub cert_version: u32,
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
