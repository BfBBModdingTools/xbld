use std::path::Path;

use bitflags::bitflags;

pub struct XBE {
    pub header: Header,
    pub sections: Vec<Section>,
    library_versions: Vec<raw::LibraryVersion>,
    logo_bitmap: raw::LogoBitmap,
}

impl XBE {
    pub fn new<P>(path: P) -> Self
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
                end + ((0x20 - end % 0x20) % 0x20)
            }
        }
    }

    pub fn add_section(&mut self, section: Section) {
        self.sections.push(section);
    }

    fn convert_to_raw(&self) -> raw::XBE {
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
        section_names_size += (4 - section_names_size % 4) % 4;

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
                    virtual_address: virtual_address,
                    virtual_size,
                    raw_address: raw_address,
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
                virtual_address += (0x20 - virtual_address % 0x20) % 0x20;
                raw_address += raw_size;
                raw_address += (0x1000 - raw_address % 0x1000) % 0x1000;
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
        size_of_headers += (4 - size_of_headers % 4) % 4;

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

        raw::XBE {
            image_header,
            certificate,
            section_headers,
            section_names,
            library_versions,
            debug_pathname: self.header.debug_pathname.clone(),
            debug_filename: self.header.debug_filename.clone(),
            debug_unicode_filename: self.header.debug_unicode_filename.clone(),
            logo_bitmap: self.logo_bitmap.clone(),
            sections: sections,
        }
    }

    fn from_raw(xbe: &raw::XBE) -> Self {
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

        XBE {
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

mod raw {
    use std::{
        fs::File,
        io,
        io::{Read, Result, Seek, SeekFrom, Write},
    };

    fn pad_to_exact(v: &mut Vec<u8>, to: usize) {
        while v.len() < to {
            v.push(0u8);
        }
    }

    fn pad_to_nearest(v: &mut Vec<u8>, to: usize) {
        while v.len() % to != 0 {
            v.push(0u8);
        }
    }

    use byteorder::{ReadBytesExt, WriteBytesExt, LE};
    #[derive(Default, Debug)]
    pub struct XBE {
        pub image_header: ImageHeader,
        pub certificate: Certificate,
        pub section_headers: Vec<SectionHeader>,
        pub section_names: Vec<String>,
        pub library_versions: Vec<LibraryVersion>,
        pub debug_pathname: String,
        pub debug_filename: String,
        pub debug_unicode_filename: Vec<u16>,
        pub logo_bitmap: LogoBitmap,
        pub sections: Vec<Section>,
    }

    impl XBE {
        /// Serialize this XBE object to a valid .xbe executable
        ///
        /// Note: this currently results in an xbe file with less ending padding
        /// when tested with SpongeBob SquarePants: Battle for Bikini Bottom,
        /// but the outputted xbe works regardless.
        pub fn serialize(&self) -> Result<Vec<u8>> {
            let mut img_hdr_v = self.image_header.serialize()?;
            let mut ctf_v = self.certificate.serialize()?;
            let mut sec_hdrs = self.serialize_section_headers()?;
            let mut sec_names = self.serialize_section_names()?;
            let mut library_versions = self.serialize_library_versions()?;
            let mut bitmap = self.logo_bitmap.serialize()?;
            let mut sections = self.serialize_sections()?;

            pad_to_exact(
                &mut &mut img_hdr_v,
                (self.image_header.certificate_address - self.image_header.base_address) as usize,
            );
            img_hdr_v.append(&mut ctf_v);

            pad_to_exact(
                &mut img_hdr_v,
                (self.image_header.section_headers_address - self.image_header.base_address)
                    as usize,
            );
            img_hdr_v.append(&mut sec_hdrs);

            // pad_to_exact(
            //     &mut img_hdr_v,
            //     (self.section_headers[0].section_name_address - self.image_header.base_address)
            //         as usize,
            // );
            img_hdr_v.append(&mut sec_names);

            // library versions array appears to be 4-byte-aligned
            pad_to_nearest(&mut img_hdr_v, 4);
            img_hdr_v.append(&mut library_versions);

            // Write Debug file/path names
            pad_to_exact(
                &mut img_hdr_v,
                (self.image_header.debug_unicode_filename_address - self.image_header.base_address)
                    as usize,
            );

            for x in self.debug_unicode_filename.iter() {
                img_hdr_v.write_u16::<LE>(*x)?;
            }

            // debug filename is part of this string, just starting at a later offset
            pad_to_exact(
                &mut img_hdr_v,
                (self.image_header.debug_pathname_address - self.image_header.base_address)
                    as usize,
            );
            img_hdr_v.write(self.debug_pathname.as_bytes())?;

            // Write bitmap
            pad_to_exact(
                &mut img_hdr_v,
                (self.image_header.logo_bitmap_address - self.image_header.base_address) as usize,
            );
            img_hdr_v.append(&mut bitmap);

            // Pad header
            pad_to_nearest(&mut img_hdr_v, 0x1000);

            // Add sections
            img_hdr_v.append(&mut sections);

            // End padding
            pad_to_nearest(&mut img_hdr_v, 0x1000);

            Ok(img_hdr_v)
        }

        fn serialize_section_headers(&self) -> Result<Vec<u8>> {
            let mut v = vec![];
            for hdr in self.section_headers.iter() {
                v.append(&mut hdr.serialize()?);
            }

            // write head/tail reference bytes
            v.append(&mut vec![0u8; self.section_headers.len() * 2 + 2]);

            Ok(v)
        }

        fn serialize_section_names(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            for n in self.section_names.iter() {
                v.write(&n.as_bytes())?;
            }

            Ok(v)
        }

        fn serialize_library_versions(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            for l in self.library_versions.iter() {
                v.append(&mut l.serialize()?);
            }

            Ok(v)
        }

        fn serialize_sections(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            if self.section_headers.len() != self.sections.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Number of section headers does not match number of sections.",
                ));
            }

            // sort headers by raw address
            // TODO: This currently makes some assumptions that may or may not be true.
            // it doesn't actually ensure that the raw_address field of the section header is
            // where the section is actually placed. Instead it places the sections order from
            // lowest raw address to highest and pads them to the next 0x1000 bytes.
            // This approach works for BfBB but may not for other xbes
            let mut sorted_headers = vec![];
            for i in 0..self.section_headers.len() {
                sorted_headers.push((&self.section_headers[i], &self.sections[i]));
            }
            sorted_headers.sort_by(|a, b| {
                if a.0.raw_address > b.0.raw_address {
                    std::cmp::Ordering::Greater
                } else if a.0.raw_address == b.0.raw_address {
                    std::cmp::Ordering::Equal
                } else {
                    std::cmp::Ordering::Less
                }
            });

            for (_, sec) in sorted_headers {
                // let s = &self.sections[i];
                v.append(&mut sec.serialize()?);
                pad_to_nearest(&mut v, 0x1000);
            }

            Ok(v)
        }
    }

    #[derive(Debug)]
    pub struct ImageHeader {
        pub magic_number: [u8; 4],
        pub digital_signature: [u8; 256],
        pub base_address: u32,
        pub size_of_headers: u32,
        pub size_of_image: u32, // Size of virtual address space
        pub size_of_image_header: u32,
        pub time_date: u32,
        pub certificate_address: u32,
        pub number_of_sections: u32,
        pub section_headers_address: u32,
        pub initialization_flags: u32,
        pub entry_point: u32,
        pub tls_address: u32,
        pub pe_stack_commit: u32,
        pub pe_heap_reserve: u32,
        pub pe_head_commit: u32,
        pub pe_base_address: u32,
        pub pe_size_of_image: u32,
        pub pe_checksum: u32,
        pub pe_time_date: u32,
        pub debug_pathname_address: u32,
        pub debug_filename_address: u32,
        pub debug_unicode_filename_address: u32,
        pub kernel_image_thunk_address: u32,
        pub non_kernel_import_directory_address: u32,
        pub number_of_library_versions: u32,
        pub library_versions_address: u32,
        pub kernel_library_version_address: u32,
        pub xapi_library_version_address: u32,
        pub logo_bitmap_address: u32,
        pub logo_bitmap_size: u32,
    }

    impl ImageHeader {
        fn serialize(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            v.write(&self.magic_number)?;
            v.write(&self.digital_signature)?;
            v.write_u32::<LE>(self.base_address)?;
            v.write_u32::<LE>(self.size_of_headers)?;
            v.write_u32::<LE>(self.size_of_image)?;
            v.write_u32::<LE>(self.size_of_image_header)?;
            v.write_u32::<LE>(self.time_date)?;
            v.write_u32::<LE>(self.certificate_address)?;
            v.write_u32::<LE>(self.number_of_sections)?;
            v.write_u32::<LE>(self.section_headers_address)?;
            v.write_u32::<LE>(self.initialization_flags)?;
            v.write_u32::<LE>(self.entry_point)?;
            v.write_u32::<LE>(self.tls_address)?;
            v.write_u32::<LE>(self.pe_stack_commit)?;
            v.write_u32::<LE>(self.pe_heap_reserve)?;
            v.write_u32::<LE>(self.pe_head_commit)?;
            v.write_u32::<LE>(self.pe_base_address)?;
            v.write_u32::<LE>(self.pe_size_of_image)?;
            v.write_u32::<LE>(self.pe_checksum)?;
            v.write_u32::<LE>(self.pe_time_date)?;
            v.write_u32::<LE>(self.debug_pathname_address)?;
            v.write_u32::<LE>(self.debug_filename_address)?;
            v.write_u32::<LE>(self.debug_unicode_filename_address)?;
            v.write_u32::<LE>(self.kernel_image_thunk_address)?;
            v.write_u32::<LE>(self.non_kernel_import_directory_address)?;
            v.write_u32::<LE>(self.number_of_library_versions)?;
            v.write_u32::<LE>(self.library_versions_address)?;
            v.write_u32::<LE>(self.kernel_library_version_address)?;
            v.write_u32::<LE>(self.xapi_library_version_address)?;
            v.write_u32::<LE>(self.logo_bitmap_address)?;
            v.write_u32::<LE>(self.logo_bitmap_size)?;

            while v.len() < self.size_of_image_header as usize {
                v.write_u8(0)?;
            }

            Ok(v)
        }
    }

    impl Default for ImageHeader {
        fn default() -> Self {
            ImageHeader {
                magic_number: [0u8; 4],
                digital_signature: [0u8; 256],
                base_address: 0,
                size_of_headers: 0,
                size_of_image: 0,
                size_of_image_header: 0,
                time_date: 0,
                certificate_address: 0,
                number_of_sections: 0,
                section_headers_address: 0,
                initialization_flags: 0,
                entry_point: 0,
                tls_address: 0,
                pe_stack_commit: 0,
                pe_heap_reserve: 0,
                pe_head_commit: 0,
                pe_base_address: 0,
                pe_size_of_image: 0,
                pe_checksum: 0,
                pe_time_date: 0,
                debug_pathname_address: 0,
                debug_filename_address: 0,
                debug_unicode_filename_address: 0,
                kernel_image_thunk_address: 0,
                non_kernel_import_directory_address: 0,
                number_of_library_versions: 0,
                library_versions_address: 0,
                kernel_library_version_address: 0,
                xapi_library_version_address: 0,
                logo_bitmap_address: 0,
                logo_bitmap_size: 0,
            }
        }
    }

    #[derive(Debug)]
    pub struct Certificate {
        pub size: u32,
        pub time_date: u32,
        pub title_id: u32,
        pub title_name: [u8; 0x50],
        pub alternate_title_ids: [u8; 0x40],
        pub allowed_media: u32,
        pub game_region: u32,
        pub game_ratings: u32,
        pub disk_number: u32,
        pub version: u32,
        pub lan_key: [u8; 0x10],
        pub signature_key: [u8; 0x10],
        pub alternate_signature_keys: [u8; 0x100],
        pub reserved: Vec<u8>, //There seems to be more bytes I can't find any documentation on.
    }

    impl Certificate {
        pub const SIZE: u32 = 0x1ec;
        fn serialize(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            v.write_u32::<LE>(self.size)?;
            v.write_u32::<LE>(self.time_date)?;
            v.write_u32::<LE>(self.title_id)?;
            v.write(&self.title_name)?;
            v.write(&self.alternate_title_ids)?;
            v.write_u32::<LE>(self.allowed_media)?;
            v.write_u32::<LE>(self.game_region)?;
            v.write_u32::<LE>(self.game_ratings)?;
            v.write_u32::<LE>(self.disk_number)?;
            v.write_u32::<LE>(self.version)?;
            v.write(&self.lan_key)?;
            v.write(&self.signature_key)?;
            v.write(&self.alternate_signature_keys)?;
            v.write(&self.reserved)?;

            Ok(v)
        }
    }

    impl Default for Certificate {
        fn default() -> Self {
            Certificate {
                size: 0,
                time_date: 0,
                title_id: 0,
                title_name: [0u8; 0x50],
                alternate_title_ids: [0u8; 0x40],
                allowed_media: 0,
                game_region: 0,
                game_ratings: 0,
                disk_number: 0,
                version: 0,
                lan_key: [0u8; 16],
                signature_key: [0u8; 16],
                alternate_signature_keys: [0u8; 0x100],
                reserved: vec![],
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct LogoBitmap {
        pub bitmap: Vec<u8>,
    }

    impl LogoBitmap {
        fn serialize(&self) -> Result<Vec<u8>> {
            Ok(self.bitmap.clone())
        }
    }

    #[derive(Debug, Default)]
    pub struct SectionHeader {
        pub section_flags: u32,
        pub virtual_address: u32,
        pub virtual_size: u32,
        pub raw_address: u32,
        pub raw_size: u32,
        pub section_name_address: u32,
        pub section_name_reference_count: u32,
        pub head_shared_page_reference_count_address: u32,
        pub tail_shared_page_reference_count_address: u32,
        pub section_digest: [u8; 0x14],
    }

    impl SectionHeader {
        fn serialize(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            v.write_u32::<LE>(self.section_flags)?;
            v.write_u32::<LE>(self.virtual_address)?;
            v.write_u32::<LE>(self.virtual_size)?;
            v.write_u32::<LE>(self.raw_address)?;
            v.write_u32::<LE>(self.raw_size)?;
            v.write_u32::<LE>(self.section_name_address)?;
            v.write_u32::<LE>(self.section_name_reference_count)?;
            v.write_u32::<LE>(self.head_shared_page_reference_count_address)?;
            v.write_u32::<LE>(self.tail_shared_page_reference_count_address)?;
            v.write(&self.section_digest)?;

            Ok(v)
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct LibraryVersion {
        pub library_name: [u8; 8],
        pub major_version: u16,
        pub minor_version: u16,
        pub build_version: u16,
        pub library_flags: u16,
    }

    impl LibraryVersion {
        fn serialize(&self) -> Result<Vec<u8>> {
            let mut v = vec![];

            v.write(&self.library_name)?;
            v.write_u16::<LE>(self.major_version)?;
            v.write_u16::<LE>(self.minor_version)?;
            v.write_u16::<LE>(self.build_version)?;
            v.write_u16::<LE>(self.library_flags)?;

            Ok(v)
        }
    }

    #[allow(dead_code)]
    #[derive(Debug, Default)]
    struct TLS {
        data_start_address: u32,
        data_end_address: u32,
        tls_index_address: u32,
        tls_callback_address: u32,
        size_of_zero_fill: u32,
        characteristics: u32,
    }

    #[derive(Debug, Default)]
    pub struct Section {
        pub bytes: Vec<u8>,
    }

    impl Section {
        fn serialize(&self) -> Result<Vec<u8>> {
            Ok(self.bytes.clone())
        }
    }

    pub fn load_xbe(mut file: File) -> std::io::Result<XBE> {
        // let mut xbe = XBE::default();

        // Read header data
        let image_header = load_image_header(&mut file)?;

        // Read certificate data
        let certificate = load_certificate(&mut file, &image_header)?;

        // Read logo bitmap data
        let logo_bitmap = load_logo_bitmap(&mut file, &image_header)?;

        // Read section data
        let section_headers = load_section_headers(&mut file, &image_header)?;
        let section_names = load_section_names(&mut file, &image_header, &section_headers)?;

        // Read debug path data
        let debug_filename = load_debug_filename(&mut file, &image_header)?;
        let debug_pathname = load_debug_pathname(&mut file, &image_header)?;
        let debug_unicode_filename = load_debug_unicode_filename(&mut file, &image_header)?;

        // Read sections
        let mut sections = vec![];
        for sec_hdr in section_headers.iter() {
            sections.push(load_section(&mut file, sec_hdr)?);
        }

        // Read library versions
        let library_version = load_library_versions(&mut file, &image_header)?;
        Ok(XBE {
            image_header,
            certificate,
            section_headers,
            section_names,
            library_versions: library_version,
            debug_filename,
            debug_pathname,
            debug_unicode_filename,
            logo_bitmap,
            sections,
        })
    }

    fn load_image_header(file: &mut File) -> Result<ImageHeader> {
        let mut header = ImageHeader::default();

        file.read_exact(&mut header.magic_number)?;
        file.read_exact(&mut header.digital_signature)?;
        header.base_address = file.read_u32::<LE>()?;
        header.size_of_headers = file.read_u32::<LE>()?;
        header.size_of_image = file.read_u32::<LE>()?;
        header.size_of_image_header = file.read_u32::<LE>()?;
        header.time_date = file.read_u32::<LE>()?;
        header.certificate_address = file.read_u32::<LE>()?;
        header.number_of_sections = file.read_u32::<LE>()?;
        header.section_headers_address = file.read_u32::<LE>()?;
        header.initialization_flags = file.read_u32::<LE>()?;
        header.entry_point = file.read_u32::<LE>()?;
        header.tls_address = file.read_u32::<LE>()?;
        header.pe_stack_commit = file.read_u32::<LE>()?;
        header.pe_heap_reserve = file.read_u32::<LE>()?;
        header.pe_head_commit = file.read_u32::<LE>()?;
        header.pe_base_address = file.read_u32::<LE>()?;
        header.pe_size_of_image = file.read_u32::<LE>()?;
        header.pe_checksum = file.read_u32::<LE>()?;
        header.pe_time_date = file.read_u32::<LE>()?;
        header.debug_pathname_address = file.read_u32::<LE>()?;
        header.debug_filename_address = file.read_u32::<LE>()?;
        header.debug_unicode_filename_address = file.read_u32::<LE>()?;
        header.kernel_image_thunk_address = file.read_u32::<LE>()?;
        header.non_kernel_import_directory_address = file.read_u32::<LE>()?;
        header.number_of_library_versions = file.read_u32::<LE>()?;
        header.library_versions_address = file.read_u32::<LE>()?;
        header.kernel_library_version_address = file.read_u32::<LE>()?;
        header.xapi_library_version_address = file.read_u32::<LE>()?;
        header.logo_bitmap_address = file.read_u32::<LE>()?;
        header.logo_bitmap_size = file.read_u32::<LE>()?;
        Ok(header)
    }

    fn load_certificate(file: &mut File, header: &ImageHeader) -> Result<Certificate> {
        let start = (header.certificate_address - header.base_address) as u64;
        file.seek(SeekFrom::Start(start))?;

        let mut certificate = Certificate::default();

        certificate.size = file.read_u32::<LE>()?;
        certificate.time_date = file.read_u32::<LE>()?;
        certificate.title_id = file.read_u32::<LE>()?;
        file.read_exact(&mut certificate.title_name)?;
        file.read_exact(&mut certificate.alternate_title_ids)?;
        certificate.allowed_media = file.read_u32::<LE>()?;
        certificate.game_region = file.read_u32::<LE>()?;
        certificate.game_ratings = file.read_u32::<LE>()?;
        certificate.disk_number = file.read_u32::<LE>()?;
        certificate.version = file.read_u32::<LE>()?;
        file.read_exact(&mut certificate.lan_key)?;
        file.read_exact(&mut certificate.signature_key)?;
        file.read_exact(&mut certificate.alternate_signature_keys)?;

        while file.stream_position()? < start + certificate.size as u64 {
            certificate.reserved.push(file.read_u8()?);
        }

        Ok(certificate)
    }

    fn load_section_headers(
        file: &mut File,
        image_header: &ImageHeader,
    ) -> Result<Vec<SectionHeader>> {
        file.seek(SeekFrom::Start(
            (image_header.section_headers_address - image_header.base_address).into(),
        ))?;

        let mut headers = Vec::with_capacity(image_header.number_of_sections as usize);
        for _ in 0..image_header.number_of_sections {
            let mut h = SectionHeader::default();

            h.section_flags = file.read_u32::<LE>()?;
            h.virtual_address = file.read_u32::<LE>()?;
            h.virtual_size = file.read_u32::<LE>()?;
            h.raw_address = file.read_u32::<LE>()?;
            h.raw_size = file.read_u32::<LE>()?;
            h.section_name_address = file.read_u32::<LE>()?;
            h.section_name_reference_count = file.read_u32::<LE>()?;
            h.head_shared_page_reference_count_address = file.read_u32::<LE>()?;
            h.tail_shared_page_reference_count_address = file.read_u32::<LE>()?;
            file.read_exact(&mut h.section_digest)?;

            headers.push(h);
        }

        Ok(headers)
    }

    fn load_section_names(
        file: &mut File,
        image_header: &ImageHeader,
        sections_headers: &Vec<SectionHeader>,
    ) -> Result<Vec<String>> {
        let mut strings = vec![];

        for hdr in sections_headers.iter() {
            file.seek(SeekFrom::Start(
                (hdr.section_name_address - image_header.base_address) as u64,
            ))?;

            // Read null-terminated string
            let mut string = vec![];
            loop {
                let c = file.read_u8()?;
                string.push(c);
                if c == b'\0' {
                    break;
                }
            }
            strings.push(String::from_utf8(string).expect("Section name not valid"));
        }

        Ok(strings)
    }

    fn load_library_versions(
        file: &mut File,
        image_header: &ImageHeader,
    ) -> Result<Vec<LibraryVersion>> {
        file.seek(SeekFrom::Start(
            (image_header.library_versions_address - image_header.base_address).into(),
        ))?;

        let mut library_versions =
            Vec::with_capacity(image_header.number_of_library_versions as usize);
        for _ in 0..image_header.number_of_library_versions {
            let mut l = LibraryVersion::default();

            file.read_exact(&mut l.library_name)?;
            l.major_version = file.read_u16::<LE>()?;
            l.minor_version = file.read_u16::<LE>()?;
            l.build_version = file.read_u16::<LE>()?;
            l.library_flags = file.read_u16::<LE>()?;

            library_versions.push(l);
        }

        Ok(library_versions)
    }

    fn load_debug_filename(file: &mut File, image_header: &ImageHeader) -> Result<String> {
        file.seek(SeekFrom::Start(
            (image_header.debug_filename_address - image_header.base_address) as u64,
        ))?;

        // Read null-terminated string
        let mut string = vec![];
        loop {
            let c = file.read_u8()?;
            string.push(c);
            if c == b'\0' {
                break;
            }
        }
        Ok(String::from_utf8(string).unwrap())
    }

    fn load_debug_pathname(file: &mut File, image_header: &ImageHeader) -> Result<String> {
        file.seek(SeekFrom::Start(
            (image_header.debug_pathname_address - image_header.base_address) as u64,
        ))?;

        // Read null-terminated string
        let mut string = vec![];
        loop {
            let c = file.read_u8()?;
            string.push(c);
            if c == b'\0' {
                break;
            }
        }
        Ok(String::from_utf8(string).unwrap())
    }

    fn load_debug_unicode_filename(
        file: &mut File,
        image_header: &ImageHeader,
    ) -> Result<Vec<u16>> {
        file.seek(SeekFrom::Start(
            (image_header.debug_unicode_filename_address - image_header.base_address) as u64,
        ))?;

        // Read null-terminated string
        let mut string = vec![];
        loop {
            let c = file.read_u16::<LE>()?;
            string.push(c);
            if c == 0 {
                break;
            }
        }
        Ok(string)
    }

    fn load_logo_bitmap(file: &mut File, image_header: &ImageHeader) -> Result<LogoBitmap> {
        file.seek(SeekFrom::Start(
            (image_header.logo_bitmap_address - image_header.base_address).into(),
        ))?;

        let mut buf = vec![0u8; image_header.logo_bitmap_size as usize];
        file.read_exact(&mut buf)?;
        Ok(LogoBitmap { bitmap: buf })
    }

    fn load_section(file: &mut File, section_header: &SectionHeader) -> Result<Section> {
        file.seek(SeekFrom::Start(section_header.raw_address as u64))?;
        let mut section = Section::default();

        let mut buf = vec![0u8; section_header.raw_size as usize];
        file.read_exact(&mut buf)?;
        section.bytes = buf;

        Ok(section)
    }
}
