#![warn(rust_2018_idioms)]
pub mod error;
pub mod xbe;

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use error::{Error, Result};
use goblin::pe::{self, symbol::Symbol, Coff};
use itertools::Itertools;
use std::{
    collections::hash_map::HashMap,
    fs,
    io::{Cursor, Write},
};
use xbe::{SectionFlags, Xbe};

#[derive(Debug)]
pub struct Configuration<'a> {
    patches: Vec<Patch<'a>>,
    modfiles: Vec<ObjectFile<'a>>,
}

impl Configuration<'_> {
    pub fn from_toml(conf: &str) -> Result<Self> {
        // These structs define the format of the config file
        #[derive(serde::Deserialize)]
        struct ConfToml {
            patch: Vec<PatchToml>,
            modfiles: Vec<String>,
        }
        #[derive(serde::Deserialize)]
        struct PatchToml {
            patchfile: String,
            start_symbol: String,
            end_symbol: String,
            virtual_address: u32,
        }
        let conf: ConfToml = toml::from_str(conf)?;

        // Create patches from configuration data
        let patches = conf
            .patch
            .into_iter()
            .map(|patch| {
                Patch::new(
                    patch.patchfile,
                    patch.start_symbol,
                    patch.end_symbol,
                    patch.virtual_address,
                )
            })
            .collect::<Result<_>>()?;

        // Create mod files from configuration data
        let modfiles = conf
            .modfiles
            .into_iter()
            .map(ObjectFile::new)
            .collect::<Result<_>>()?;
        Ok(Self { patches, modfiles })
    }
}

#[derive(Debug)]
struct ObjectFile<'a> {
    filename: String,
    bytes: Vec<u8>,
    coff: Coff<'a>,
}

impl<'a> ObjectFile<'a> {
    fn new(filename: String) -> Result<Self> {
        let bytes = fs::read(filename.as_str()).map_err(|e| Error::Io(filename.to_string(), e))?;

        // SAFETY: We are referecing data stored on the heap that will be allocated for the
        // lifetime of this object (`'a`). Therefore we can safely extend the liftime of the
        // reference to that data to the lifetime of this object
        let coff = Coff::parse(unsafe { std::mem::transmute(&*bytes) })
            .map_err(|e| Error::Goblin(filename.clone(), e))?;

        Ok(Self {
            filename,
            bytes,
            coff,
        })
    }
}

#[derive(Debug)]
struct Patch<'a> {
    patchfile: ObjectFile<'a>,
    start_symbol_name: String,
    end_symbol_name: String,
    virtual_address: u32,
}

impl<'a> Patch<'a> {
    fn new(
        filename: String,
        start_symbol_name: String,
        end_symbol_name: String,
        virtual_address: u32,
    ) -> Result<Self> {
        let patchfile = ObjectFile::new(filename)?;
        Ok(Self {
            patchfile,
            start_symbol_name,
            end_symbol_name,
            virtual_address,
        })
    }

    fn apply(&self, xbe: &mut Xbe, symbol_table: &SymbolTable) -> Result<()> {
        // find patch symbols
        let start_symbol = self.find_symbol(self.start_symbol_name.as_str())?;
        let end_symbol = self.find_symbol(self.end_symbol_name.as_str())?;
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
        let mut section_map = SectionMap::from_data(std::slice::from_ref(&self.patchfile));
        section_map
            .get_mut(sec_name)
            .ok_or_else(|| {
                Error::Patch(
                    self.start_symbol_name.to_string(),
                    error::PatchError::MissingSection(sec_name.to_string()),
                )
            })?
            .virtual_address = self.virtual_address;

        section_map.process_relocations(symbol_table, std::slice::from_ref(&self.patchfile))?;

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

#[derive(Debug)]
struct SectionInProgress<'a> {
    name: String,
    bytes: Vec<u8>,
    file_offset_start: HashMap<&'a str, u32>,
    virtual_address: u32,
}

impl<'a> SectionInProgress<'a> {
    fn new(name: String) -> Self {
        Self {
            name,
            bytes: Vec::new(),
            file_offset_start: HashMap::new(),
            virtual_address: 0,
        }
    }

    fn add_bytes(&mut self, bytes: &[u8], filename: &'a str) {
        self.file_offset_start
            .insert(filename, self.bytes.len() as u32);
        self.bytes.append(&mut bytes.to_owned());
    }

    /// Read the value located at `file_section_address` (plus the `file_start_offset` of `filename`),
    /// add `value`, and overwrite the original value with the result.
    fn relative_update_u32(
        &mut self,
        filename: &str,
        file_section_address: u32,
        value: u32,
    ) -> Result<()> {
        let mut cur = Cursor::new(&mut self.bytes);

        // rust compiler is literally stupid and we need to borrow this field now
        // in order to capture with the closure (because the closure will borrow)
        // the entire struct
        let name = &self.name;

        // find the offset of the data to update
        let d_start = self.file_offset_start.get(filename).ok_or_else(|| {
            Error::Relocation(
                filename.to_string(),
                error::RelocationError::MissingSectionOffset(name.clone()),
            )
        })? + file_section_address;

        // read the current value, so we can add it to the new value
        cur.set_position(d_start as u64);
        let offset = cur
            .read_u32::<LE>()
            .map_err(|e| Error::Io(filename.to_string(), e))?;
        cur.set_position(d_start as u64);

        // update data
        cur.write_u32::<LE>(value + offset)
            .map_err(|e| Error::Io(filename.to_string(), e))
    }

    /// Read the value located at `file_section_address` (plus the `file_start_offset` of `filename`),
    /// add `value`, and overwrite the original value with the result.
    fn relative_update_i32(
        &mut self,
        filename: &str,
        file_section_address: u32,
        value: i32,
    ) -> Result<()> {
        self.relative_update_u32(filename, file_section_address, value as u32)
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
    fn from_obj(file: &'a ObjectFile<'_>) -> Self {
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
#[derive(Debug)]
struct SectionMap<'a>(HashMap<&'a str, SectionInProgress<'a>>);

impl<'a> SectionMap<'a> {
    fn from_data(files: &'a [ObjectFile<'_>]) -> Self {
        let mut section_map = HashMap::new();
        for file in files.iter() {
            // Extract section data from file
            let section_bytes = SectionBytes::from_obj(file);

            // Combine sections from all files
            if let Some(b) = section_bytes.text {
                section_map
                    .entry(".mtext")
                    .or_insert_with(|| SectionInProgress::new(".mtext".to_string()))
                    .add_bytes(b, file.filename.as_str());
            }
            if let Some(b) = section_bytes.data {
                section_map
                    .entry(".mdata")
                    .or_insert_with(|| SectionInProgress::new(".mdata".to_string()))
                    .add_bytes(b, file.filename.as_str());
            }
            if let Some(b) = section_bytes.bss {
                section_map
                    .entry(".mbss")
                    .or_insert_with(|| SectionInProgress::new(".mbss".to_string()))
                    .add_bytes(b, file.filename.as_str());
            }
            if let Some(b) = section_bytes.rdata {
                section_map
                    .entry(".mrdata")
                    .or_insert_with(|| SectionInProgress::new(".mrdata".to_string()))
                    .add_bytes(b, file.filename.as_str());
            }
        }
        Self(section_map)
    }

    fn get(&self, section: &str) -> Option<&SectionInProgress<'_>> {
        self.0.get(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    fn get_mut(&mut self, section: &str) -> Option<&mut SectionInProgress<'a>> {
        self.0.get_mut(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    fn process_relocations(
        &mut self,
        symbol_table: &SymbolTable,
        files: &[ObjectFile<'_>],
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
                                file.filename.as_str(),
                                reloc.virtual_address,
                                target_address,
                            )?,
                        goblin::pe::relocation::IMAGE_REL_I386_REL32 => {
                            let sec_address = section_data
                                .file_offset_start
                                .get(file.filename.as_str())
                                .expect(
                                    "Failed to get file start information to process a relocation.",
                                )
                                + reloc.virtual_address;

                            // Calculate relative jump based on distance from the virtual address of the next instruction
                            // (AKA the value of the CPU program counter after reading this instruction) and the target
                            let from_address = sec_address
                                + section_data.virtual_address
                                + std::mem::size_of::<u32>() as u32;
                            section_data.relative_update_i32(
                                file.filename.as_str(),
                                sec_address,
                                target_address as i32 - from_address as i32,
                            )?;
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

    fn extract_symbols(
        &mut self,
        section_map: &SectionMap<'_>,
        obj: &ObjectFile<'_>,
        config: &Configuration<'_>,
    ) -> Result<()> {
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
                    let sym_name = sym
                        .name(&obj.coff.strings)
                        .map_err(|e| Error::Goblin(obj.filename.to_string(), e))?;
                    self.0.insert(
                        sym_name.to_owned(),
                        match sec_data.file_offset_start.get(obj.filename.as_str()) {
                            Some(addr) => *addr + sym.value + sec_data.virtual_address,
                            None => {
                                if let Some(patch) = config
                                    .patches
                                    .iter()
                                    .find(|p| p.start_symbol_name == sym_name)
                                {
                                    patch.virtual_address
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
                        match sec_data.file_offset_start.get(obj.filename.as_str()) {
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
                        match sec_data.file_offset_start.get(obj.filename.as_str()) {
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
pub fn inject(config: Configuration<'_>, mut xbe: Xbe) -> Result<Xbe> {
    // combine sections
    let mut section_map = SectionMap::from_data(&config.modfiles);

    // Assign virtual addresses
    let mut last_virtual_address = xbe.get_next_virtual_address();

    for (_, sec) in section_map.0.iter_mut().sorted_by(|a, b| a.0.cmp(b.0)) {
        sec.virtual_address = last_virtual_address;
        last_virtual_address =
            xbe.get_next_virtual_address_after(last_virtual_address + sec.bytes.len() as u32);
    }

    // build symbol table
    let mut symbol_table = SymbolTable::new();
    for obj in config
        .patches
        .iter()
        .map(|p| &p.patchfile)
        .chain(config.modfiles.iter())
    {
        symbol_table.extract_symbols(&section_map, obj, &config)?;
    }

    // process relocations for mods
    section_map.process_relocations(&symbol_table, &config.modfiles)?;

    // apply patches
    for patch in config.patches.iter() {
        patch.apply(&mut xbe, &symbol_table)?;
    }

    // insert sections into XBE
    for (_, sec) in section_map
        .0
        .into_iter()
        .sorted_by(|a, b| a.1.virtual_address.cmp(&b.1.virtual_address))
    {
        let flags = SectionFlags::PRELOAD
            | match sec.name.as_str() {
                ".mtext" => SectionFlags::EXECUTABLE,
                ".mdata" | ".mbss" => SectionFlags::WRITABLE,
                _ => SectionFlags::PRELOAD, //No "zero" value
            };
        let virtual_size = sec.bytes.len() as u32;
        xbe.add_section(
            sec.name + "\0",
            flags,
            sec.bytes,
            sec.virtual_address,
            virtual_size,
        )
    }
    Ok(xbe)
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;

    type TestError = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn config_parse() -> TestError {
        let toml = r#"
            modfiles = ["test/bin/loader.o", "test/bin/mod.o"]

            [[patch]]
            patchfile = "test/bin/framehook_patch.o"
            start_symbol = "_framehook_patch"
            end_symbol = "_framehook_patch_end"
            virtual_address = 396158"#;

        let config = Configuration::from_toml(toml)?;

        // Check patch configuration
        assert_eq!(config.patches.len(), 1);
        let patch = &config.patches[0];
        assert_eq!(
            patch.patchfile.filename,
            "test/bin/framehook_patch.o".to_string()
        );
        assert_eq!(patch.start_symbol_name, "_framehook_patch".to_string());
        assert_eq!(patch.end_symbol_name, "_framehook_patch_end".to_string());
        assert_eq!(patch.virtual_address, 396158);

        // Check modfile list
        assert_eq!(config.modfiles.len(), 2);
        let modfile = &config.modfiles[0];
        assert_eq!(modfile.filename, "test/bin/loader.o");
        let modfile = &config.modfiles[1];
        assert_eq!(modfile.filename, "test/bin/mod.o");
        Ok(())
    }

    #[test]
    fn config_parse_multi_patch() -> TestError {
        let toml = r#"
            modfiles = []

            [[patch]]
            patchfile = "test/bin/framehook_patch.o"
            start_symbol = "_framehook_patch"
            end_symbol = "_framehook_patch_end"
            virtual_address = 396158

            [[patch]]
            patchfile = "test/bin/mod.o"
            start_symbol = "start"
            end_symbol = "end"
            virtual_address = 1234"#;

        let config = Configuration::from_toml(toml)?;

        // Check patch configuration
        assert_eq!(config.patches.len(), 2);
        let patch = &config.patches[0];
        assert_eq!(
            patch.patchfile.filename,
            "test/bin/framehook_patch.o".to_string()
        );
        assert_eq!(patch.start_symbol_name, "_framehook_patch".to_string());
        assert_eq!(patch.end_symbol_name, "_framehook_patch_end".to_string());
        assert_eq!(patch.virtual_address, 396158);
        let patch = &config.patches[1];
        assert_eq!(patch.patchfile.filename, "test/bin/mod.o".to_string());
        assert_eq!(patch.start_symbol_name, "start".to_string());
        assert_eq!(patch.end_symbol_name, "end".to_string());
        assert_eq!(patch.virtual_address, 1234);

        // Check modfile list
        assert_eq!(config.modfiles.len(), 0);
        Ok(())
    }

    #[test]
    // This test add a patch that jumps to a minimal mod that saves registers, replaces the
    // overwritten instruction, jumps to a stub function, and then returns to the base game.
    fn minimal_example() -> TestError {
        use sha1::{Digest, Sha1};

        let toml = r#"
            modfiles = ["test/bin/loader_stub.o"]

            [[patch]]
            patchfile = "test/bin/framehook_patch.o"
            start_symbol = "_framehook_patch"
            end_symbol = "_framehook_patch_end"
            virtual_address = 396158"#;

        let config = Configuration::from_toml(toml)?;
        let output = inject(config, xbe::Xbe::new(&fs::read("test/bin/default.xbe")?)?)?;

        // Check that output matches expected rom
        let target_hash = {
            let mut sha1 = Sha1::new();
            sha1.update(&fs::read("test/bin/minimal_example.xbe")?);
            sha1.finalize()
        };
        let actual_hash = {
            let mut sha1 = Sha1::new();
            sha1.update(&output.serialize()?);
            sha1.finalize()
        };

        assert_eq!(target_hash, actual_hash);
        Ok(())
    }

    #[test]
    fn no_panic() -> TestError {
        let xbe = xbe::Xbe::new(&fs::read("test/bin/default.xbe")?)?;
        inject(
            Configuration::from_toml(fs::read_to_string("test/bin/conf.toml").unwrap().as_str())?,
            xbe,
        )?;
        Ok(())
    }

    #[test]
    fn file_offsets() {
        let mut section = SectionInProgress::new("test".to_string());
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        assert_eq!(section.file_offset_start.len(), 2);
        assert_eq!(*section.file_offset_start.get("bytesA").unwrap(), 0);
        assert_eq!(*section.file_offset_start.get("bytesB").unwrap(), 12);
    }

    #[test]
    fn add_bytes() {
        let mut section = SectionInProgress::new("test".to_string());
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        assert_eq!(section.bytes.len(), 20);
        assert_eq!(section.bytes, (0..12).chain(0..8).collect_vec());
    }

    #[test]
    fn relative_update() {
        let mut section = SectionInProgress::new("test".to_string());
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        section.relative_update_u32("bytesB", 0, 0x100).unwrap();
        assert_eq!(
            section.bytes,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 2, 2, 3, 4, 5, 6, 7]
        )
    }
}
