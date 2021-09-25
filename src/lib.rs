#![warn(rust_2018_idioms)]
pub mod config;
pub mod error;
pub(crate) mod patch;
pub(crate) mod reloc;
pub mod xbe;

use config::Configuration;
use error::{Error, Result};
use goblin::pe::Coff;
use itertools::Itertools;
use reloc::{SectionMap, SymbolTable};
use std::fs;
use xbe::{SectionFlags, Xbe};

#[derive(Debug)]
pub(crate) struct ObjectFile<'a> {
    pub(crate) filename: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) coff: Coff<'a>,
}

impl<'a> ObjectFile<'a> {
    pub(crate) fn new(filename: String) -> Result<Self> {
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

    for (_, sec) in section_map.iter_mut().sorted_by(|a, b| a.0.cmp(b.0)) {
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
    use super::*;

    type TestError = std::result::Result<(), Box<dyn std::error::Error>>;

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
    // This test provides some level of confidence that the unsafe code in the ObjectFile
    // constructor is correct
    fn load_object_file() -> TestError {
        let name = "test/bin/framehook_patch.o";
        let obj = ObjectFile::new("test/bin/framehook_patch.o".to_string())?;
        assert_eq!(obj.filename, name);
        assert_eq!(obj.bytes, std::fs::read(name)?);
        Ok(())
    }
}
