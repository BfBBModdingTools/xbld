use crate::error::{Error, RelocationError, Result};
use crate::Configuration;
use crate::ObjectFile;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use goblin::pe;
use std::collections::hash_map::HashMap;
use std::io::Cursor;
use std::iter::IntoIterator;
use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub(crate) struct SectionInProgress<'a> {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) file_offset_start: HashMap<&'a str, u32>,
    pub(crate) virtual_address: u32,
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
                RelocationError::MissingSectionOffset(name.clone()),
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
pub(crate) struct SectionMap<'a>(HashMap<&'a str, SectionInProgress<'a>>);

impl<'a> Deref for SectionMap<'a> {
    type Target = HashMap<&'a str, SectionInProgress<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for SectionMap<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> IntoIterator for SectionMap<'a> {
    type Item = <HashMap<&'a str, SectionInProgress<'a>> as IntoIterator>::Item;
    type IntoIter = <HashMap<&'a str, SectionInProgress<'a>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> SectionMap<'a> {
    pub(crate) fn from_data(files: &'a [ObjectFile<'_>]) -> Self {
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

    pub(crate) fn get(&self, section: &str) -> Option<&SectionInProgress<'_>> {
        self.0.get(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    pub(crate) fn get_mut(&mut self, section: &str) -> Option<&mut SectionInProgress<'a>> {
        self.0.get_mut(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    pub(crate) fn process_relocations(
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
                            RelocationError::MissingSection(section_name.to_string()),
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
                                RelocationError::MissingSymbol(reloc.symbol_table_index),
                            )
                        })?;
                    let symbol_name = match symbol_name {
                        Some(n) => n,
                        None => symbol.name(&file.coff.strings).map_err(|e| {
                            Error::Relocation(
                                file.filename.to_string(),
                                RelocationError::MissingName(e),
                            )
                        })?,
                    };

                    // Find virtual address of symbol
                    let target_address = *symbol_table.0.get(symbol_name).ok_or_else(|| {
                        Error::Relocation(
                            file.filename.to_string(),
                            RelocationError::MissingAddress(symbol_name.to_string()),
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
pub(crate) struct SymbolTable(HashMap<String, u32>);

impl SymbolTable {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    pub(crate) fn extract_symbols(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xbe::Xbe;
    use itertools::Itertools;
    use std::fs;

    type TestError = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn no_panic() -> TestError {
        let xbe = Xbe::new(&fs::read("test/bin/default.xbe")?)?;
        crate::inject(
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
