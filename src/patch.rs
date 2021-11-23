use crate::{reloc::SymbolTable, ObjectFile, SectionMap, Xbe};
use anyhow::{bail, Result};
use goblin::pe::symbol::Symbol;
use std::{
    io::{Cursor, Write},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("Symbol '{0}' undefined.")]
    UndefinedSymbol(String),
    #[error("Section Mismatch: Start/End symbol sections differ")]
    SectionMismatch(),
    #[error("Could not locate section '{0}'")]
    MissingSection(String),
    #[error("Virtual address {0} is unused by input XBE")]
    InvalidAddress(u32),
}

#[derive(Debug)]
pub(crate) struct Patch<'a> {
    pub(crate) patchfile: ObjectFile<'a>,
    pub(crate) start_symbol_name: String,
    pub(crate) end_symbol_name: String,
    pub(crate) virtual_address: u32,
}

impl<'a> Patch<'a> {
    pub(crate) fn new(
        path: PathBuf,
        start_symbol_name: String,
        end_symbol_name: String,
        virtual_address: u32,
    ) -> Result<Self> {
        let patchfile = ObjectFile::new(path)?;
        Ok(Self {
            patchfile,
            start_symbol_name,
            end_symbol_name,
            virtual_address,
        })
    }

    pub(crate) fn apply(&self, xbe: &mut Xbe, symbol_table: &SymbolTable) -> Result<()> {
        // find patch symbols
        let start_symbol = self.find_symbol(self.start_symbol_name.as_str())?;
        let end_symbol = self.find_symbol(self.end_symbol_name.as_str())?;
        if start_symbol.section_number != end_symbol.section_number {
            bail!(PatchError::SectionMismatch(),);
        }

        let sec_name = self
            .patchfile
            .coff
            .sections
            .get(start_symbol.section_number as usize - 1)
            .unwrap()
            .name()?;

        // Process Patch Coff (symbols have already been read)
        let mut section_map = SectionMap::from_data(std::slice::from_ref(&self.patchfile));
        section_map
            .get_mut(sec_name)
            .ok_or_else(|| PatchError::MissingSection(sec_name.to_string()))?
            .virtual_address = self.virtual_address;

        section_map.process_relocations(symbol_table, std::slice::from_ref(&self.patchfile))?;

        let xbe_bytes = xbe
            .get_bytes_mut(self.virtual_address..self.virtual_address + 5)
            .ok_or(PatchError::InvalidAddress(self.virtual_address))?;

        let patch_bytes = &section_map
            .get(sec_name)
            .ok_or_else(|| PatchError::MissingSection(sec_name.to_string()))?
            .bytes[start_symbol.value as usize..end_symbol.value as usize];

        let mut c = Cursor::new(xbe_bytes);
        c.write_all(patch_bytes).expect("Failed to apply patch");

        Ok(())
    }

    fn find_symbol(&self, name: &str) -> Result<Symbol> {
        let sym = self
            .patchfile
            .coff
            .symbols
            .iter()
            .find(|(_, n, sym)| {
                n.unwrap_or_else(|| sym.name(&self.patchfile.coff.strings).unwrap_or_default())
                    == name
            })
            .map(|(_, _, sym)| sym)
            .ok_or_else(|| PatchError::UndefinedSymbol(name.to_string()))?;
        Ok(sym)
    }
}
