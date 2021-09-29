use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use itertools::Itertools;
use std::{
    io,
    io::{Cursor, Read, Result, Write},
};

/// adds padding to a byte vector until its len is a multiple of `to`
/// no padding is added if the len is already a multiple of `to`
fn pad_to_nearest(v: &mut Vec<u8>, to: usize) {
    let len = v.len();
    let to = (to - len % to) % to;
    v.resize(len + to, 0);
}

/// read characters until a null character (zero) is reached and return a utf8
/// encoded string from those bytes
fn read_null_string_ascii<T>(reader: &mut T) -> Result<String>
where
    T: Read,
{
    let mut string = vec![];
    loop {
        let c = reader.read_u8()?;
        string.push(c);
        if c == b'\0' {
            break;
        }
    }
    Ok(String::from_utf8(string).unwrap())
}

/// read characters until a null character (two zeroes in a row) is reached and return those
/// characters as an array of `u16`s
fn read_null_string_widestring<T>(file: &mut T) -> Result<Vec<u16>>
where
    T: Read,
{
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

#[derive(Debug)]
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
    pub fn load(file: &[u8]) -> std::io::Result<Xbe> {
        let mut cur = Cursor::new(file);
        // Read header data
        let image_header = ImageHeader::load(&mut cur)?;

        // Read certificate data
        cur.set_position((image_header.certificate_address - image_header.base_address) as u64);
        let certificate = Certificate::load(&mut cur)?;

        // Read logo bitmap data
        cur.set_position((image_header.logo_bitmap_address - image_header.base_address) as u64);
        let logo_bitmap = LogoBitmap::load(&mut cur, image_header.logo_bitmap_size as usize)?;

        // Read section data
        cur.set_position((image_header.section_headers_address - image_header.base_address) as u64);
        let section_headers =
            SectionHeader::load(&mut cur, image_header.number_of_sections as usize)?;

        let section_names = section_headers
            .iter()
            .map(|x| {
                cur.set_position((x.section_name_address - image_header.base_address) as u64);
                read_null_string_ascii(&mut cur)
            })
            .collect::<std::result::Result<_, _>>()?;

        // Read debug path data
        cur.set_position(
            (image_header.debug_unicode_filename_address - image_header.base_address) as u64,
        );
        let debug_unicode_filename = read_null_string_widestring(&mut cur)?;
        let debug_pathname = read_null_string_ascii(&mut cur)?;
        cur.set_position((image_header.debug_filename_address - image_header.base_address) as u64);
        let debug_filename = read_null_string_ascii(&mut cur)?;

        // Read sections
        let sections = section_headers
            .iter()
            .map(|hdr| {
                cur.set_position(hdr.raw_address as u64);
                Section::load(&mut cur, hdr.raw_size as usize)
            })
            .collect::<std::result::Result<_, _>>()?;

        // Read library versions
        cur.set_position(
            (image_header.library_versions_address - image_header.base_address) as u64,
        );
        let library_version =
            LibraryVersion::load(&mut cur, image_header.number_of_library_versions as usize)?;

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

    /// Serialize this XBE object to a valid .xbe executable
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut img_hdr_v = self.image_header.serialize()?;
        let mut ctf_v = self.certificate.serialize()?;
        let mut sec_hdrs = self.serialize_section_headers()?;
        let mut sec_names = self.serialize_section_names()?;
        let mut library_versions = self.serialize_library_versions()?;
        let mut bitmap = self.logo_bitmap.serialize()?;
        let mut sections = self.serialize_sections()?;

        img_hdr_v.resize(
            (self.image_header.certificate_address - self.image_header.base_address) as usize,
            0,
        );
        img_hdr_v.append(&mut ctf_v);

        img_hdr_v.resize(
            (self.image_header.section_headers_address - self.image_header.base_address) as usize,
            0,
        );
        img_hdr_v.append(&mut sec_hdrs);
        img_hdr_v.append(&mut sec_names);

        // library versions array appears to be 4-byte-aligned
        pad_to_nearest(&mut img_hdr_v, 4);
        img_hdr_v.append(&mut library_versions);

        // Write Debug file/path names
        img_hdr_v.resize(
            (self.image_header.debug_unicode_filename_address - self.image_header.base_address)
                as usize,
            0,
        );

        for x in self.debug_unicode_filename.iter() {
            img_hdr_v.write_u16::<LE>(*x)?;
        }

        // debug filename is part of this string, just starting at a later offset
        img_hdr_v.resize(
            (self.image_header.debug_pathname_address - self.image_header.base_address) as usize,
            0,
        );
        img_hdr_v.write_all(self.debug_pathname.as_bytes())?;

        // Write bitmap
        img_hdr_v.resize(
            (self.image_header.logo_bitmap_address - self.image_header.base_address) as usize,
            0,
        );
        img_hdr_v.append(&mut bitmap);

        // Pad header
        pad_to_nearest(&mut img_hdr_v, 0x1000);

        // Add sections
        img_hdr_v.append(&mut sections);

        // End padding (not sure if this is present in all XBEs)
        img_hdr_v.resize(img_hdr_v.len() + 0x1000, 0);

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
            v.write_all(n.as_bytes())?;
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
        for (_, sec) in self
            .section_headers
            .iter()
            .zip(self.sections.iter())
            .sorted_by(|(a, _), (b, _)| a.raw_address.cmp(&b.raw_address))
        {
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
    fn load<T>(reader: &mut T) -> Result<ImageHeader>
    where
        T: Read,
    {
        let mut magic_number = [0u8; 4];
        reader.read_exact(&mut magic_number)?;
        let mut digital_signature = [0u8; 0x100];
        reader.read_exact(&mut digital_signature)?;

        Ok(Self {
            magic_number,
            digital_signature,
            base_address: reader.read_u32::<LE>()?,
            size_of_headers: reader.read_u32::<LE>()?,
            size_of_image: reader.read_u32::<LE>()?,
            size_of_image_header: reader.read_u32::<LE>()?,
            time_date: reader.read_u32::<LE>()?,
            certificate_address: reader.read_u32::<LE>()?,
            number_of_sections: reader.read_u32::<LE>()?,
            section_headers_address: reader.read_u32::<LE>()?,
            initialization_flags: reader.read_u32::<LE>()?,
            entry_point: reader.read_u32::<LE>()?,
            tls_address: reader.read_u32::<LE>()?,
            pe_stack_commit: reader.read_u32::<LE>()?,
            pe_heap_reserve: reader.read_u32::<LE>()?,
            pe_head_commit: reader.read_u32::<LE>()?,
            pe_base_address: reader.read_u32::<LE>()?,
            pe_size_of_image: reader.read_u32::<LE>()?,
            pe_checksum: reader.read_u32::<LE>()?,
            pe_time_date: reader.read_u32::<LE>()?,
            debug_pathname_address: reader.read_u32::<LE>()?,
            debug_filename_address: reader.read_u32::<LE>()?,
            debug_unicode_filename_address: reader.read_u32::<LE>()?,
            kernel_image_thunk_address: reader.read_u32::<LE>()?,
            non_kernel_import_directory_address: reader.read_u32::<LE>()?,
            number_of_library_versions: reader.read_u32::<LE>()?,
            library_versions_address: reader.read_u32::<LE>()?,
            kernel_library_version_address: reader.read_u32::<LE>()?,
            xapi_library_version_address: reader.read_u32::<LE>()?,
            logo_bitmap_address: reader.read_u32::<LE>()?,
            logo_bitmap_size: reader.read_u32::<LE>()?,
        })
    }

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
    /// Used for converting to raw. The size of a certificate header
    pub const SIZE: u32 = 0x1ec;

    fn load<T>(reader: &mut T) -> Result<Certificate>
    where
        T: Read,
    {
        let mut certificate = Certificate {
            size: reader.read_u32::<LE>()?,
            time_date: reader.read_u32::<LE>()?,
            title_id: reader.read_u32::<LE>()?,
            ..Default::default()
        };
        reader.read_exact(&mut certificate.title_name)?;
        reader.read_exact(&mut certificate.alternate_title_ids)?;
        certificate.allowed_media = reader.read_u32::<LE>()?;
        certificate.game_region = reader.read_u32::<LE>()?;
        certificate.game_ratings = reader.read_u32::<LE>()?;
        certificate.disk_number = reader.read_u32::<LE>()?;
        certificate.version = reader.read_u32::<LE>()?;
        reader.read_exact(&mut certificate.lan_key)?;
        reader.read_exact(&mut certificate.signature_key)?;
        reader.read_exact(&mut certificate.alternate_signature_keys)?;

        // This is kinda hacky but this shouldn't change unless the purpose of the remaing bytes
        // is discovered and they are added as fields to this struct
        // NOTE: we can't use size_of because it will include padding for the struct's layout in memory
        const BYTES_READ: u32 = 0x1D0;
        certificate
            .unknown
            .resize((certificate.size - BYTES_READ) as usize, 0);
        reader.read_exact(&mut certificate.unknown)?;

        Ok(certificate)
    }

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
    fn load<T>(file: &mut T, size: usize) -> Result<LogoBitmap>
    where
        T: Read,
    {
        let mut buf = vec![0u8; size];
        file.read_exact(&mut buf)?;
        Ok(LogoBitmap { bitmap: buf })
    }

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
    fn load<T>(reader: &mut T, number_of_sections: usize) -> Result<Vec<SectionHeader>>
    where
        T: Read,
    {
        let mut headers = Vec::with_capacity(number_of_sections);
        for _ in 0..number_of_sections {
            let mut h = SectionHeader {
                section_flags: reader.read_u32::<LE>()?,
                virtual_address: reader.read_u32::<LE>()?,
                virtual_size: reader.read_u32::<LE>()?,
                raw_address: reader.read_u32::<LE>()?,
                raw_size: reader.read_u32::<LE>()?,
                section_name_address: reader.read_u32::<LE>()?,
                section_name_reference_count: reader.read_u32::<LE>()?,
                head_shared_page_reference_count_address: reader.read_u32::<LE>()?,
                tail_shared_page_reference_count_address: reader.read_u32::<LE>()?,
                ..Default::default()
            };
            reader.read_exact(&mut h.section_digest)?;

            headers.push(h);
        }

        Ok(headers)
    }

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
    fn load<T>(reader: &mut T, number_of_library_versions: usize) -> Result<Vec<LibraryVersion>>
    where
        T: Read,
    {
        let mut library_versions = Vec::with_capacity(number_of_library_versions);
        for _ in 0..number_of_library_versions {
            let mut l = LibraryVersion::default();

            reader.read_exact(&mut l.library_name)?;
            l.major_version = reader.read_u16::<LE>()?;
            l.minor_version = reader.read_u16::<LE>()?;
            l.build_version = reader.read_u16::<LE>()?;
            l.library_flags = reader.read_u16::<LE>()?;

            library_versions.push(l);
        }

        Ok(library_versions)
    }

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

impl Section {
    fn load<T>(reader: &mut T, raw_size: usize) -> Result<Section>
    where
        T: Read,
    {
        let mut bytes = vec![0u8; raw_size];
        reader.read_exact(&mut bytes)?;

        Ok(Section { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_and_reserialize() -> std::result::Result<(), std::io::Error> {
        use sha1::{Digest, Sha1};

        let default_bytes = std::fs::read("test/bin/default.xbe")?;
        let default_hash = {
            let mut hasher = Sha1::new();
            hasher.update(&default_bytes);
            hasher.finalize()
        };

        let xbe = Xbe::load(&default_bytes)?;
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
