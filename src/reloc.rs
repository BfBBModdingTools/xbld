use crate::{xbe, Configuration, ObjectFile};
use anyhow::{bail, Context, Result};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use goblin::pe;
use itertools::Itertools;
use std::{
    collections::HashMap,
    io::Cursor,
    iter::IntoIterator,
    ops::{Deref, DerefMut},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelocationError {
    #[error("Could not find section offset for section '{0}'")]
    SectionOffset(String),
    #[error("Could not find symbol with index '{0}'")]
    SymbolIndex(u32),
    #[error("Could not find the virtual address of symbol '{0}'.")]
    SymbolAddress(String),
}

// TODO: Restructure things to avoid this needing to be exposed for patch
#[derive(Debug)]
pub(crate) struct SectionBuilder<'a> {
    name: String,
    pub(crate) bytes: Vec<u8>,
    file_offset_start: HashMap<&'a str, u32>,
    pub(crate) virtual_address: u32,
}

impl<'a> SectionBuilder<'a> {
    fn new(name: String) -> Self {
        Self {
            name,
            bytes: Vec::new(),
            file_offset_start: HashMap::new(),
            virtual_address: 0,
        }
    }

    /// #Panics
    ///
    /// Panics if the provided filename has already been added once.
    fn add_bytes(&mut self, bytes: &[u8], filename: &'a str) {
        if self.file_offset_start.contains_key(filename) {
            panic!(
                "Attempted to add bytes from file '{}' to section '{}' more than once",
                filename, self.name
            );
        }
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
        let d_start = self
            .file_offset_start
            .get(filename)
            .ok_or_else(|| RelocationError::SectionOffset(name.clone()))?
            + file_section_address;

        // read the current value, so we can add it to the new value
        cur.set_position(d_start as u64);
        let offset = cur.read_u32::<LE>()?;
        cur.set_position(d_start as u64);

        // update data
        cur.write_u32::<LE>(value.wrapping_add(offset))?;
        Ok(())
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

trait RelocExt {
    fn perform(
        &self,
        file: &ObjectFile<'_>,
        symbol_table: &SymbolTable,
        section_data: &mut SectionBuilder<'_>,
    ) -> Result<()>;
}

impl RelocExt for pe::relocation::Relocation {
    fn perform(
        &self,
        file: &ObjectFile<'_>,
        symbol_table: &SymbolTable,
        section_data: &mut SectionBuilder<'_>,
    ) -> Result<()> {
        // Find target symbol and name
        let (symbol_name, symbol) = file
            .coff
            .symbols
            .get(self.symbol_table_index as usize)
            .ok_or(RelocationError::SymbolIndex(self.symbol_table_index))?;
        let symbol_name = symbol_name.map_or_else(|| symbol.name(&file.coff.strings), |s| Ok(s))?;

        // Find virtual address of symbol
        let target_address = *symbol_table
            .0
            .get(symbol_name)
            .ok_or_else(|| RelocationError::SymbolAddress(symbol_name.to_string()))?;

        // We are targeting Xbox so we use x86 relocations
        use pe::relocation::*;
        match self.typ {
            IMAGE_REL_I386_DIR32 => section_data.relative_update_u32(
                file.filename.as_str(),
                self.virtual_address,
                target_address,
            )?,
            IMAGE_REL_I386_REL32 => {
                let sec_address = section_data
                    .file_offset_start
                    .get(file.filename.as_str())
                    .with_context(|| {
                        format!(
                            "Failed to get file start offset for file '{}'",
                            file.filename
                        )
                    })?
                    + self.virtual_address;

                // Calculate relative jump based on distance from the virtual address of the next instruction
                // (AKA the value of the CPU program counter after reading this instruction) and the target
                let from_address =
                    sec_address + section_data.virtual_address + std::mem::size_of::<u32>() as u32;
                section_data.relative_update_i32(
                    file.filename.as_str(),
                    sec_address,
                    target_address as i32 - from_address as i32,
                )?;
            }
            //TODO: Support all relocations
            _ => bail!(
                "Couldn't perform relocation for symbol '{}'. Relocation type {} not supported",
                symbol_name,
                self.typ
            ),
        }
        Ok(())
    }
}

/// Maps from a given section name to it's section data
#[derive(Debug)]
pub(crate) struct SectionMap<'a>(HashMap<&'a str, SectionBuilder<'a>>);

impl<'a> Deref for SectionMap<'a> {
    type Target = HashMap<&'a str, SectionBuilder<'a>>;

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
    type Item = <HashMap<&'a str, SectionBuilder<'a>> as IntoIterator>::Item;
    type IntoIter = <HashMap<&'a str, SectionBuilder<'a>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> SectionMap<'a> {
    pub(crate) fn from_data(files: &'a [ObjectFile<'_>]) -> Self {
        let mut section_map = HashMap::new();
        for file in files.iter() {
            let mut combined_bytes = HashMap::new();
            for sec in file
                .coff
                .sections
                .iter()
                .filter(|s| s.size_of_raw_data != 0)
            {
                let sec_name = match &sec.name {
                    b".text\0\0\0" => ".mtext",
                    b".data\0\0\0" => ".mdata",
                    b".bss\0\0\0\0" => ".mbss",
                    b".rdata\0\0" => ".mrdata",
                    _ => continue,
                };

                let start = sec.pointer_to_raw_data as usize;
                let end = start + sec.size_of_raw_data as usize;
                let data = &file.bytes[start..end];

                combined_bytes
                    .entry(sec_name)
                    .or_insert_with(Vec::default)
                    .append(&mut data.to_owned());
            }

            for (sec_name, bytes) in combined_bytes.into_iter() {
                // TODO: Logging
                println!(
                    "Adding section '{}' from file '{}'; {} bytes.",
                    sec_name,
                    file.filename,
                    bytes.len()
                );

                section_map
                    .entry(sec_name)
                    .or_insert_with(|| SectionBuilder::new(sec_name.to_string()))
                    .add_bytes(&bytes, &file.filename);
            }
        }

        Self(section_map)
    }

    pub(crate) fn assign_addresses(&mut self, xbe: &xbe::Xbe) {
        let mut last_virtual_address = xbe.get_next_virtual_address();

        for (_, sec) in self.iter_mut().sorted_by(|a, b| a.0.cmp(b.0)) {
            sec.virtual_address = last_virtual_address;
            last_virtual_address =
                xbe.get_next_virtual_address_after(last_virtual_address + sec.bytes.len() as u32);
        }
    }

    pub(crate) fn finalize(self, xbe: &mut xbe::Xbe) {
        for sec in self
            .into_iter()
            .map(|(_, sec)| sec)
            .sorted_by(|a, b| a.virtual_address.cmp(&b.virtual_address))
        {
            let flags = xbe::SectionFlags::PRELOAD
                | match sec.name.as_str() {
                    ".mtext" => xbe::SectionFlags::EXECUTABLE,
                    ".mdata" | ".mbss" => xbe::SectionFlags::WRITABLE,
                    _ => xbe::SectionFlags::PRELOAD, //No "zero" value
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
    }

    pub(crate) fn get(&self, section: &str) -> Option<&SectionBuilder<'_>> {
        self.0.get(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    pub(crate) fn get_mut(&mut self, section: &str) -> Option<&mut SectionBuilder<'a>> {
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
                // find data to update
                // TODO: This is assuming 32 bit relocations
                let section_name = section.name()?;
                let section_data = match self.get_mut(section_name) {
                    Some(data) => data,
                    None => {
                        //TODO: Logging
                        println!("WARNING: Skipping section '{}'", section_name);
                        continue;
                    }
                };

                println!(
                    "Beginning relocation processing for section '{}'",
                    section_name
                );

                for reloc in section.relocations(&file.bytes).unwrap_or_default() {
                    reloc
                        .perform(file, symbol_table, section_data)
                        .with_context(|| {
                            format!(
                                "Failed to perform a relocation in section '{}'.",
                                section_name,
                            )
                        })?;
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
    pub(crate) fn new(
        section_map: &SectionMap<'_>,
        config: &Configuration<'_>,
    ) -> anyhow::Result<Self> {
        let mut map = Self(HashMap::new());
        for obj in config
            .patches
            .iter()
            .map(|p| &p.patchfile)
            .chain(config.modfiles.iter())
        {
            map.extract_symbols(section_map, obj, config)
                .with_context(|| {
                    format!(
                        "Couldn't extract symbols from file '{}'",
                        obj.filename.clone()
                    )
                })?;
        }
        Ok(map)
    }

    fn extract_symbols(
        &mut self,
        section_map: &SectionMap<'_>,
        obj: &ObjectFile<'_>,
        config: &Configuration<'_>,
    ) -> Result<()> {
        for (_, _, sym) in obj.coff.symbols.iter() {
            // TODO: set a verbosity level for these messages when logging is implemented.
            match sym.section_number {
                0 => {
                    // TODO: Probably track these external symbols and produce error/warnings if
                    // unresolved
                    println!(
                        "Skipping external symbol '{}' in file '{}'.",
                        sym.name(&obj.coff.strings).unwrap_or(""),
                        obj.filename
                    );
                    continue;
                }
                -2 | -1 => {
                    // TODO: Determine if these symbols are important at all
                    println!(
                        "WARNING: Skipping symbol '{}' in file '{}' with section number {}.",
                        sym.name(&obj.coff.strings).unwrap_or(""),
                        obj.filename,
                        sym.section_number
                    );
                    continue;
                }
                _ => (),
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
                    .name()?,
            ) {
                Some(data) => data,
                None => continue,
            };

            use pe::symbol::*;
            match sym.storage_class {
                IMAGE_SYM_CLASS_EXTERNAL if sym.typ == 0x20 => {
                    let sym_name = sym.name(&obj.coff.strings)?;
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
                IMAGE_SYM_CLASS_FUNCTION => {
                    let sym_name = sym.name(&obj.coff.strings)?;
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
                IMAGE_SYM_CLASS_EXTERNAL if sym.section_number > 0 => {
                    self.0.insert(
                        sym.name(&obj.coff.strings)?.to_owned(),
                        match sec_data.file_offset_start.get(obj.filename.as_str()) {
                            Some(addr) => *addr + sym.value + sec_data.virtual_address,
                            None => continue,
                        },
                    );
                }
                IMAGE_SYM_CLASS_EXTERNAL => {
                    // TODO: Check if this is a link-time symbol necessary for modloader
                    // functionality.

                    // External symbol should be declared in a future file
                    // TODO: Keep up with unresolved externals for errors?
                    continue;
                }
                IMAGE_SYM_CLASS_STATIC => {
                    self.0.insert(
                        sym.name(&obj.coff.strings)?.to_owned(),
                        match sec_data.file_offset_start.get(obj.filename.as_str()) {
                            Some(addr) => *addr + sec_data.virtual_address,
                            None => continue,
                        },
                    );
                }
                IMAGE_SYM_CLASS_FILE => continue,
                _ => bail!("storage_class {} not implemented", sym.storage_class),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn file_offsets() {
        let mut section = SectionBuilder::new("test".to_string());
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        assert_eq!(section.file_offset_start.len(), 2);
        assert_eq!(*section.file_offset_start.get("bytesA").unwrap(), 0);
        assert_eq!(*section.file_offset_start.get("bytesB").unwrap(), 12);
    }

    #[test]
    fn add_bytes() {
        let mut section = SectionBuilder::new("test".to_string());
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        assert_eq!(section.bytes.len(), 20);
        assert_eq!(section.bytes, (0..12).chain(0..8).collect_vec());
    }

    #[test]
    fn relative_update() {
        let mut section = SectionBuilder::new("test".to_string());
        section.add_bytes(&(0..12).collect_vec(), "bytesA");
        section.add_bytes(&(0..8).collect_vec(), "bytesB");

        section.relative_update_u32("bytesB", 0, 0x100).unwrap();
        assert_eq!(
            section.bytes,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 2, 2, 3, 4, 5, 6, 7]
        )
    }
}
