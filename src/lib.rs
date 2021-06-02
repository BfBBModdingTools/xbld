pub mod error;
mod xbe;

use error::{Error, Result};

use itertools::Itertools;
use std::{
    collections::hash_map::HashMap,
    fs,
    io::{Cursor, Write},
};

use goblin::pe::{self, symbol::Symbol, Coff};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use xbe::{SectionFlags, Xbe};

#[derive(Debug, Clone)]
pub struct Configuration {
    pub patchfiles: Vec<String>,
    pub modfiles: Vec<String>,
    pub input_xbe: String,
    pub output_xbe: String,
}

#[derive(Debug, Default, Clone)]
struct SectionInProgress<'a> {
    bytes: Vec<u8>,
    file_offset_start: HashMap<&'a str, u32>,
    virtual_address: u32,
}

impl<'a> SectionInProgress<'a> {
    pub fn add_bytes(&mut self, bytes: &[u8], filename: &'a str) {
        self.file_offset_start
            .insert(filename, self.bytes.len() as u32);
        self.bytes.append(&mut bytes.to_owned());
    }

    /// Read the value located at `file_section_address` (plus the `file_start_offset` of `filename`),
    /// add `value`, and overwrite the original value with the result.
    pub fn relative_update_u32(&mut self, filename: &str, file_section_address: u32, value: u32) {
        let mut cur = Cursor::new(&mut self.bytes);

        let d_start = self.file_offset_start.get(filename).unwrap() + file_section_address;
        cur.set_position(d_start as u64);
        let offset = cur.read_u32::<LE>().unwrap();
        cur.set_position(d_start as u64);

        // update data
        cur.write_u32::<LE>(value + offset).unwrap();
    }

    /// Read the value located at `file_section_address` (plus the `file_start_offset` of `filename`),
    /// add `value`, and overwrite the original value with the result.
    pub fn relative_update_i32(&mut self, filename: &str, file_section_address: u32, value: i32) {
        self.relative_update_u32(filename, file_section_address, value as u32)
    }
}

struct ObjectFile<'a> {
    bytes: &'a [u8],
    coff: Coff<'a>,
    filename: &'a str,
}

impl<'a> ObjectFile<'a> {
    fn new(bytes: &'a [u8], filename: &'a str) -> Result<Self> {
        Ok(Self {
            bytes,
            coff: Coff::parse(&bytes).map_err(|e| Error::Goblin(filename.to_string(), e))?,
            filename,
        })
    }
}

struct Patch<'a> {
    patchfile: &'a ObjectFile<'a>,
    start_symbol_name: &'a str,
    end_symbol_name: &'a str,
    virtual_address: u32,
}

impl Patch<'_> {
    pub fn apply(&self, xbe: &mut Xbe, symbol_table: &SymbolTable) -> Result<()> {
        // find patch symbols
        let start_symbol = self.find_symbol(self.start_symbol_name)?;
        let end_symbol = self.find_symbol(self.end_symbol_name)?;
        if start_symbol.section_number != end_symbol.section_number {
            return Err(Error::Patch(
                self.start_symbol_name.to_string(),
                error::PatchError::SectionMismatch(),
            ));
        }

        let sec_name = self
            .patchfile
            .coff
            .sections
            .get(start_symbol.section_number as usize - 1)
            .unwrap()
            .name()
            .map_err(|e| Error::Goblin(self.patchfile.filename.to_string(), e))?;

        // Process Patch Coff (symbols have already been read)
        let mut section_map = SectionMap::from_data(std::slice::from_ref(self.patchfile));
        //TODO: This assumes patch is at beginning of .text
        section_map
            .get_mut(sec_name)
            .ok_or_else(|| {
                Error::Patch(
                    self.start_symbol_name.to_string(),
                    error::PatchError::MissingSection(sec_name.to_string()),
                )
            })?
            .virtual_address = self.virtual_address;

        section_map.process_relocations(symbol_table, std::slice::from_ref(self.patchfile))?;

        let xbe_bytes = xbe
            .get_bytes_mut(self.virtual_address..self.virtual_address + 5)
            .ok_or_else(|| {
                Error::Patch(
                    self.start_symbol_name.to_string(),
                    error::PatchError::InvalidAddress(self.virtual_address),
                )
            })?;

        let patch_bytes = &section_map
            .get(sec_name)
            .ok_or_else(|| {
                Error::Patch(
                    self.start_symbol_name.to_string(),
                    error::PatchError::MissingSection(sec_name.to_string()),
                )
            })?
            .bytes[start_symbol.value as usize..end_symbol.value as usize];

        let mut c = Cursor::new(xbe_bytes);
        c.write_all(patch_bytes).expect("Failed to apply patch");

        Ok(())
    }

    fn find_symbol(&self, name: &str) -> Result<Symbol> {
        for (_, n, s) in self.patchfile.coff.symbols.iter() {
            let n = match n {
                Some(n) => n,
                None => s
                    .name(&self.patchfile.coff.strings)
                    .map_err(|e| Error::Goblin(self.patchfile.filename.to_string(), e))?,
            };

            if n == name {
                return Ok(s);
            }
        }
        Err(Error::Patch(
            self.patchfile.filename.to_string(),
            error::PatchError::UndefinedSymbol(name.to_string()),
        ))
    }
}

#[derive(Default, Debug, Clone)]
struct SectionBytes<'a> {
    text: Option<&'a [u8]>,
    data: Option<&'a [u8]>,
    bss: Option<&'a [u8]>,
    rdata: Option<&'a [u8]>,
}

impl<'a> SectionBytes<'a> {
    pub fn from_obj(file: &'a ObjectFile) -> Self {
        let mut s = SectionBytes::default();

        for sec in file
            .coff
            .sections
            .iter()
            .filter(|s| s.size_of_raw_data != 0)
        {
            let start = sec.pointer_to_raw_data as usize;
            let end = start + sec.size_of_raw_data as usize;
            let data = &file.bytes[start..end];
            match &sec.name {
                b".text\0\0\0" => s.text = Some(data),
                b".data\0\0\0" => s.data = Some(data),
                b".bss\0\0\0\0" => s.bss = Some(data),
                b".rdata\0\0" => s.rdata = Some(data),
                _ => continue,
            }
        }
        s
    }
}

/// Maps from a given section name to it's section data
#[derive(Debug, Clone)]
struct SectionMap<'a>(HashMap<&'a str, SectionInProgress<'a>>);

impl<'a> SectionMap<'a> {
    pub fn from_data(files: &'a [ObjectFile]) -> Self {
        let mut section_map = HashMap::new();
        for file in files.iter() {
            // Extract section data from file
            let section_bytes = SectionBytes::from_obj(file);

            // Combine sections from all files
            if let Some(b) = section_bytes.text {
                section_map
                    .entry(".mtext")
                    .or_insert_with(SectionInProgress::default)
                    .add_bytes(b, file.filename);
            }
            if let Some(b) = section_bytes.data {
                section_map
                    .entry(".mdata")
                    .or_insert_with(SectionInProgress::default)
                    .add_bytes(b, file.filename);
            }
            if let Some(b) = section_bytes.bss {
                section_map
                    .entry(".mbss")
                    .or_insert_with(SectionInProgress::default)
                    .add_bytes(b, file.filename);
            }
            if let Some(b) = section_bytes.rdata {
                section_map
                    .entry(".mrdata")
                    .or_insert_with(SectionInProgress::default)
                    .add_bytes(b, file.filename);
            }
        }
        Self(section_map)
    }

    pub fn get(&self, section: &str) -> Option<&SectionInProgress> {
        self.0.get(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    pub fn get_mut(&mut self, section: &str) -> Option<&mut SectionInProgress<'a>> {
        self.0.get_mut(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    pub fn process_relocations(
        &mut self,
        symbol_table: &SymbolTable,
        files: &[ObjectFile],
    ) -> Result<()> {
        for file in files.iter() {
            for section in file.coff.sections.iter() {
                for reloc in section.relocations(&file.bytes).unwrap_or_default() {
                    // find data to update
                    // TODO: This is assuming 32 bit relocations
                    // TODO: handle section_number -2,-1 and 0
                    let section_name = section
                        .name()
                        .map_err(|e| Error::Goblin(file.filename.to_string(), e))?;
                    let section_data = self.get_mut(section_name).ok_or_else(|| {
                        Error::Relocation(
                            file.filename.to_string(),
                            error::RelocationError::MissingSection(section_name.to_string()),
                        )
                    })?;

                    // Find target symbol and name
                    let (symbol_name, symbol) = file
                        .coff
                        .symbols
                        .get(reloc.symbol_table_index as usize)
                        .ok_or_else(|| {
                            Error::Relocation(
                                file.filename.to_string(),
                                error::RelocationError::MissingSymbol(reloc.symbol_table_index),
                            )
                        })?;
                    let symbol_name = match symbol_name {
                        Some(n) => n,
                        None => symbol.name(&file.coff.strings).map_err(|e| {
                            Error::Relocation(
                                file.filename.to_string(),
                                error::RelocationError::MissingName(e),
                            )
                        })?,
                    };

                    // Find virtual address of symbol
                    let target_address = *symbol_table.0.get(symbol_name).ok_or_else(|| {
                        Error::Relocation(
                            file.filename.to_string(),
                            error::RelocationError::MissingAddress(symbol_name.to_string()),
                        )
                    })?;

                    // We are targeting Xbox so we use x86 relocations
                    match reloc.typ {
                        goblin::pe::relocation::IMAGE_REL_I386_DIR32 => section_data
                            .relative_update_u32(
                                file.filename,
                                reloc.virtual_address,
                                target_address,
                            ),
                        goblin::pe::relocation::IMAGE_REL_I386_REL32 => {
                            let sec_address =
                                section_data.file_offset_start.get(file.filename).expect(
                                    "Failed to get file start information to process a relocation.",
                                ) + reloc.virtual_address;

                            // Calculate relative jump based on distance from the virtual address of the next instruction
                            // (AKA the value of the CPU program counter after reading this instruction) and the target
                            const INSTRUCTION_SIZE: u32 = 5;
                            let from_address =
                                sec_address + section_data.virtual_address + INSTRUCTION_SIZE;
                            section_data.relative_update_i32(
                                file.filename,
                                sec_address,
                                target_address as i32 - from_address as i32,
                            );
                        }
                        //TODO: Support all relocations
                        _ => panic!("relocation type {} not supported", reloc.typ),
                    }
                }
            }
        }

        Ok(())
    }
}

/// Maps from a given symbol name to its virtual address
// TODO: Remove heap allocation (String)
#[derive(Debug, Clone)]
struct SymbolTable(HashMap<String, u32>);

impl SymbolTable {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn extract_symbols(&mut self, section_map: &SectionMap, obj: &ObjectFile) -> Result<()> {
        for (_index, _name, sym) in obj.coff.symbols.iter() {
            if sym.section_number < 1 {
                continue;
            }

            // Get section data from table
            let sec_data = match section_map.get(
                obj.coff
                    .sections
                    .get(sym.section_number as usize - 1)
                    .unwrap_or_else(|| {
                        panic!(
                            "No section for section number {} in file {}",
                            sym.section_number, obj.filename
                        )
                    })
                    .name()
                    .map_err(|e| Error::Goblin(obj.filename.to_string(), e))?,
            ) {
                Some(data) => data,
                None => continue,
            };

            match sym.storage_class {
                pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if sym.typ == 0x20 => {
                    self.0.insert(
                        sym.name(&obj.coff.strings)
                            .map_err(|e| Error::Goblin(obj.filename.to_string(), e))?
                            .to_owned(),
                        match sec_data.file_offset_start.get(obj.filename) {
                            Some(addr) => *addr + sym.value + sec_data.virtual_address,
                            None => {
                                let patch_conf = std::fs::read_to_string("bin/patch.conf")
                                    .map_err(|e| Error::Io(obj.filename.to_string(), e))?;
                                let mut split = patch_conf.split(' ');

                                // Todo deduplicate conf parsing and extract parsing to module
                                let patchname = split.next().unwrap();
                                //skip end symbol
                                split.next();
                                let address: u32 = split.next().unwrap().parse().unwrap();

                                if sym
                                    .name(&obj.coff.strings)
                                    .map_err(|e| Error::Goblin(obj.filename.to_string(), e))?
                                    == patchname
                                {
                                    address
                                } else {
                                    continue;
                                }
                            }
                        },
                    );
                }
                pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if sym.section_number > 0 => {
                    self.0.insert(
                        sym.name(&obj.coff.strings)
                            .map_err(|e| Error::Goblin(obj.filename.to_string(), e))?
                            .to_owned(),
                        match sec_data.file_offset_start.get(obj.filename) {
                            Some(addr) => *addr + sym.value + sec_data.virtual_address,
                            None => continue,
                        },
                    );
                }
                pe::symbol::IMAGE_SYM_CLASS_EXTERNAL => {
                    // TODO: Check if this is a link-time symbol necessary for modloader
                    // functionality.

                    // External symbol should be declared in a future file
                    // TODO: Keep up with unresolved externals for errors?
                    continue;
                }
                pe::symbol::IMAGE_SYM_CLASS_STATIC => {
                    self.0.insert(
                        sym.name(&obj.coff.strings)
                            .map_err(|e| Error::Goblin(obj.filename.to_string(), e))?
                            .to_owned(),
                        match sec_data.file_offset_start.get(obj.filename) {
                            Some(addr) => *addr + sec_data.virtual_address,
                            None => continue,
                        },
                    );
                }
                pe::symbol::IMAGE_SYM_CLASS_FILE => continue,
                _ => todo!("storage_class {} not implemented", sym.storage_class),
            }
        }

        Ok(())
    }
}

/// How to inject
/// - separate patch files from other object files
///     - Symbols are shared between Patches and Mods
///     - Sections from patches are not combined into the '.m{text,data,bss,rdata}' sections.
/// - combine .text, .data, .bss, .rdata of each non-patch file
///     - have start offsets within the sections for each file
/// - assign virtual address ranges to each combined section
/// - build combined symbol table
///     - Most symbols are assigned a virtual address within a combined section
///     - Patch symbols are assigned a virtual address from a config file
/// - process relocations within each file
/// - process base game patch files
/// - insert sections into xbe
pub fn inject(config: Configuration) -> Result<()> {
    let patchbytes: Vec<Vec<u8>> = config
        .patchfiles
        .iter()
        .map(|f| fs::read(f).map_err(|e| (f.clone(), e)))
        .collect::<std::result::Result<_, _>>()
        .map_err(|(f, e)| Error::Io(f, e))?;
    let patches: Vec<ObjectFile> = config
        .patchfiles
        .iter()
        .zip(patchbytes.iter())
        .map(|(f, b)| ObjectFile::new(b, f))
        .collect::<std::result::Result<_, _>>()?;

    let modbytes: Vec<Vec<u8>> = config
        .modfiles
        .iter()
        .map(|f| fs::read(f).map_err(|e| (f.clone(), e)))
        .collect::<std::result::Result<_, _>>()
        .map_err(|(f, e)| Error::Io(f, e))?;
    let mods: Vec<ObjectFile> = config
        .modfiles
        .iter()
        .zip(modbytes.iter())
        .map(|(f, b)| ObjectFile::new(b, f))
        .collect::<std::result::Result<_, _>>()?;

    // combine sections
    let mut section_map = SectionMap::from_data(&mods);

    // Assign virtual addresses
    let mut xbe = Xbe::from_path(config.input_xbe);
    let mut last_virtual_address = xbe.get_next_virtual_address();

    for (_, sec) in section_map.0.iter_mut().sorted_by(|a, b| a.0.cmp(b.0)) {
        sec.virtual_address = last_virtual_address;
        last_virtual_address =
            xbe.get_next_virtual_address_after(last_virtual_address + sec.bytes.len() as u32);
    }

    // build symbol table
    let mut symbol_table = SymbolTable::new();
    for obj in patches.iter().chain(mods.iter()) {
        symbol_table.extract_symbols(&section_map, obj)?;
    }

    // process relocations for mods
    section_map.process_relocations(&symbol_table, &mods)?;

    // read patch config
    let patch_config =
        String::from_utf8(std::fs::read("bin/patch.conf").expect("Could not read config file."))
            .expect("Could not read config file.");
    let patches: Vec<Patch> = patch_config
        .split(' ')
        .tuples()
        .zip(patches.iter())
        .map(
            |((start_symbol_name, end_symbol_name, addr), patchfile)| Patch {
                patchfile,
                start_symbol_name,
                end_symbol_name,
                virtual_address: addr.parse().expect("Malformed address in config"),
            },
        )
        .collect();

    // apply patches
    for patch in &patches {
        patch.apply(&mut xbe, &symbol_table)?;
    }

    // insert sections into XBE
    for (name, sec) in section_map
        .0
        .into_iter()
        .sorted_by(|a, b| a.1.virtual_address.cmp(&b.1.virtual_address))
    {
        let virtual_size = sec.bytes.len() as u32;
        xbe.add_section(
            name.to_owned() + "\0",
            SectionFlags::PRELOAD
                | match name {
                    ".mtext" => SectionFlags::EXECUTABLE,
                    ".mdata" | ".mbss" => SectionFlags::WRITABLE,
                    _ => SectionFlags::PRELOAD, //No "zero" value
                },
            sec.bytes,
            sec.virtual_address,
            virtual_size,
        )
    }
    xbe.write_to_file(config.output_xbe);

    Ok(())
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::{inject, Configuration, SectionInProgress};

    #[test]
    fn no_panic() {
        match inject(Configuration {
            patchfiles: vec!["bin/framehook_patch.o".to_string()],
            modfiles: vec!["bin/loader.o".to_string()],
            input_xbe: "bin/default.xbe".to_string(),
            output_xbe: "bin/output.xbe".to_string(),
        }) {
            Ok(()) => (),
            Err(e) => panic!("bfbb_linker::inject returned error:\n\n{}\n\n", e),
        }
    }

    #[test]
    fn file_offsets() {
        let mut section = SectionInProgress::default();
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        assert_eq!(section.file_offset_start.len(), 2);
        assert_eq!(*section.file_offset_start.get("bytesA").unwrap(), 0);
        assert_eq!(*section.file_offset_start.get("bytesB").unwrap(), 12);
    }

    #[test]
    fn add_bytes() {
        let mut section = SectionInProgress::default();
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        assert_eq!(section.bytes.len(), 20);
        assert_eq!(section.bytes, (0..12).chain(0..8).collect_vec());
    }

    #[test]
    fn relative_update() {
        let mut section = SectionInProgress::default();
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        section.relative_update_u32("bytesB", 0, 0x100);
        assert_eq!(
            section.bytes,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 2, 2, 3, 4, 5, 6, 7]
        )
    }
}
