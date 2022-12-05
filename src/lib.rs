#![warn(rust_2018_idioms)]
pub mod config;
pub mod obj;
pub(crate) mod patch;
pub(crate) mod reloc;

use anyhow::{Context, Result};
use config::Configuration;
use reloc::{SectionMap, SymbolTable};
use xbe::Xbe;

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
pub fn inject(config: Configuration, mut xbe: Xbe) -> Result<Xbe> {
    // combine sections
    let mut section_map = SectionMap::from_data(&config.modfiles);

    // Assign virtual addresses
    section_map.assign_addresses(&xbe);

    // build symbol table
    let symbol_table = SymbolTable::new(&section_map, &config)?;

    // process relocations for mods
    section_map.process_relocations(&symbol_table, &config.modfiles)?;

    // apply patches
    for patch in config.patches.iter() {
        patch.apply(&mut xbe, &symbol_table).with_context(|| {
            format!(
                "Failed to apply patch '{}'",
                patch.start_symbol_name.clone()
            )
        })?;
    }

    // insert sections into XBE
    section_map.finalize(&mut xbe);

    // return patched xbe
    Ok(xbe)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use crate::{config::Configuration, inject};

    type TestError = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    // This test add a patch that jumps to a minimal mod that saves registers, replaces the
    // overwritten instruction, jumps to a stub function, and then returns to the base game.
    fn minimal_example() -> TestError {
        use sha1::{Digest, Sha1};

        let toml = r#"
            modfiles = ["loader_stub.o"]

            [[patch]]
            patchfile = "framehook_patch.o"
            start_symbol = "_framehook_patch"
            end_symbol = "_framehook_patch_end"
            virtual_address = 396158"#;

        let config = Configuration::from_toml(toml, Path::new("test/bin/fakefile.toml"))?;
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
}
