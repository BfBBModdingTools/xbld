use std::{
    fs::File,
    io,
    io::{Read, Result, Seek, SeekFrom, Write},
};

/// adds `amount` bytes of padding to a byte vector
fn pad(v: &mut Vec<u8>, amount: usize) {
    for _ in 0..amount {
        v.push(0);
    }
}

/// adds padding to a byte vector until its len equals `to`
fn pad_to(v: &mut Vec<u8>, to: usize) {
    while v.len() < to {
        v.push(0);
    }
}

/// adds padding to a byte vector until its len is a multiple of `to`
/// no padding is added if the len is already a multiple of `to`
fn pad_to_nearest(v: &mut Vec<u8>, to: usize) {
    while v.len() % to != 0 {
        v.push(0);
    }
}

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
#[derive(Default, Debug)]
pub struct Xbe {
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

impl Xbe {
    /// Serialize this XBE object to a valid .xbe executable
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut img_hdr_v = self.image_header.serialize()?;
        let mut ctf_v = self.certificate.serialize()?;
        let mut sec_hdrs = self.serialize_section_headers()?;
        let mut sec_names = self.serialize_section_names()?;
        let mut library_versions = self.serialize_library_versions()?;
        let mut bitmap = self.logo_bitmap.serialize()?;
        let mut sections = self.serialize_sections()?;

        pad_to(
            &mut &mut img_hdr_v,
            (self.image_header.certificate_address - self.image_header.base_address) as usize,
        );
        img_hdr_v.append(&mut ctf_v);

        pad_to(
            &mut img_hdr_v,
            (self.image_header.section_headers_address - self.image_header.base_address) as usize,
        );
        img_hdr_v.append(&mut sec_hdrs);
        img_hdr_v.append(&mut sec_names);

        // library versions array appears to be 4-byte-aligned
        pad_to_nearest(&mut img_hdr_v, 4);
        img_hdr_v.append(&mut library_versions);

        // Write Debug file/path names
        pad_to(
            &mut img_hdr_v,
            (self.image_header.debug_unicode_filename_address - self.image_header.base_address)
                as usize,
        );

        for x in self.debug_unicode_filename.iter() {
            img_hdr_v.write_u16::<LE>(*x)?;
        }

        // debug filename is part of this string, just starting at a later offset
        pad_to(
            &mut img_hdr_v,
            (self.image_header.debug_pathname_address - self.image_header.base_address) as usize,
        );
        img_hdr_v.write_all(self.debug_pathname.as_bytes())?;

        // Write bitmap
        pad_to(
            &mut img_hdr_v,
            (self.image_header.logo_bitmap_address - self.image_header.base_address) as usize,
        );
        img_hdr_v.append(&mut bitmap);

        // Pad header
        pad_to_nearest(&mut img_hdr_v, 0x1000);

        // Add sections
        img_hdr_v.append(&mut sections);

        // End padding (not sure if this is present in all XBEs)
        pad(&mut img_hdr_v, 0x1000);

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
            v.write_all(&n.as_bytes())?;
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
        sorted_headers.sort_by(|a, b| a.0.raw_address.cmp(&b.0.raw_address));

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

        v.write_all(&self.magic_number)?;
        v.write_all(&self.digital_signature)?;
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
    pub unknown: Vec<u8>, //There seems to be more bytes I can't find any documentation on.
}

impl Certificate {
    pub const SIZE: u32 = 0x1ec;
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut v = vec![];

        v.write_u32::<LE>(self.size)?;
        v.write_u32::<LE>(self.time_date)?;
        v.write_u32::<LE>(self.title_id)?;
        v.write_all(&self.title_name)?;
        v.write_all(&self.alternate_title_ids)?;
        v.write_u32::<LE>(self.allowed_media)?;
        v.write_u32::<LE>(self.game_region)?;
        v.write_u32::<LE>(self.game_ratings)?;
        v.write_u32::<LE>(self.disk_number)?;
        v.write_u32::<LE>(self.version)?;
        v.write_all(&self.lan_key)?;
        v.write_all(&self.signature_key)?;
        v.write_all(&self.alternate_signature_keys)?;
        v.write_all(&self.unknown)?;

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
            unknown: vec![],
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
        v.write_all(&self.section_digest)?;

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

        v.write_all(&self.library_name)?;
        v.write_u16::<LE>(self.major_version)?;
        v.write_u16::<LE>(self.minor_version)?;
        v.write_u16::<LE>(self.build_version)?;
        v.write_u16::<LE>(self.library_flags)?;

        Ok(v)
    }
}

#[derive(Debug, Default)]
struct Tls {
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

pub fn load_xbe(mut file: File) -> std::io::Result<Xbe> {
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
    Ok(Xbe {
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

    let mut certificate = Certificate {
        size: file.read_u32::<LE>()?,
        time_date: file.read_u32::<LE>()?,
        title_id: file.read_u32::<LE>()?,
        ..Default::default()
    };
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
        certificate.unknown.push(file.read_u8()?);
    }

    Ok(certificate)
}

fn load_section_headers(file: &mut File, image_header: &ImageHeader) -> Result<Vec<SectionHeader>> {
    file.seek(SeekFrom::Start(
        (image_header.section_headers_address - image_header.base_address).into(),
    ))?;

    let mut headers = Vec::with_capacity(image_header.number_of_sections as usize);
    for _ in 0..image_header.number_of_sections {
        let mut h = SectionHeader {
            section_flags: file.read_u32::<LE>()?,
            virtual_address: file.read_u32::<LE>()?,
            virtual_size: file.read_u32::<LE>()?,
            raw_address: file.read_u32::<LE>()?,
            raw_size: file.read_u32::<LE>()?,
            section_name_address: file.read_u32::<LE>()?,
            section_name_reference_count: file.read_u32::<LE>()?,
            head_shared_page_reference_count_address: file.read_u32::<LE>()?,
            tail_shared_page_reference_count_address: file.read_u32::<LE>()?,
            ..Default::default()
        };
        file.read_exact(&mut h.section_digest)?;

        headers.push(h);
    }

    Ok(headers)
}

fn load_section_names(
    file: &mut File,
    image_header: &ImageHeader,
    sections_headers: &[SectionHeader],
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

    let mut library_versions = Vec::with_capacity(image_header.number_of_library_versions as usize);
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

fn load_debug_unicode_filename(file: &mut File, image_header: &ImageHeader) -> Result<Vec<u16>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_and_reserialize() {
        use sha1::{Digest, Sha1};

        let xbe = load_xbe(std::fs::File::open("bin/default.xbe").unwrap()).unwrap();
        let bytes = xbe.serialize().unwrap();

        const XBE_SHA1: &'static [u8] = &[
            0xa9, 0xac, 0x85, 0x5c, 0x4e, 0xe8, 0xb4, 0x1b, 0x66, 0x1c, 0x35, 0x78, 0xc9, 0x59,
            0xc0, 0x24, 0xf1, 0x06, 0x8c, 0x47,
        ];
        let mut hasher = Sha1::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();
        assert_eq!(*XBE_SHA1, *hash);
    }
}
