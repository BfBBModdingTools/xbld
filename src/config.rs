use std::path::Path;

use crate::{patch::Patch, ObjectFile};
use anyhow::{Context, Result};

#[derive(Debug)]
pub struct Configuration<'a> {
    pub(crate) patches: Vec<Patch<'a>>,
    pub(crate) modfiles: Vec<ObjectFile<'a>>,
}

impl Configuration<'_> {
    /// Reads file located at `path` and parses it as a toml formatted configuation file
    pub fn from_file(path: &Path) -> Result<Self> {
        let conf = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file '{:?}'", path))?;

        Self::from_toml(&conf, path)
    }

    /// Parses `conf` as a toml formatted string and creates a configuration from it. Any paths
    /// within `conf` are treated as relative to the parent of `path`.
    pub fn from_toml(conf: &str, path: &Path) -> Result<Self> {
        // These structs define the format of the config file
        #[derive(serde::Deserialize)]
        struct ConfToml {
            patch: Option<Vec<PatchToml>>,
            modfiles: Option<Vec<String>>,
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
        // TODO: Warning message for empty patch list (mods will be dead code)
        let patches = conf
            .patch
            .unwrap_or_default()
            .into_iter()
            .map(|patch| {
                let mut buf = path.to_path_buf();
                buf.pop();
                buf.push(Path::new(&patch.patchfile));

                Patch::new(
                    buf,
                    patch.start_symbol,
                    patch.end_symbol,
                    patch.virtual_address,
                )
            })
            .collect::<Result<_>>()?;

        // Create mod files from configuration data
        let modfiles = conf
            .modfiles
            .unwrap_or_default()
            .into_iter()
            .map(|mod_path| {
                let mut buf = path.to_path_buf();
                buf.pop();
                buf.push(Path::new(&mod_path));
                println!("{:?}  {:?}", path, mod_path);
                ObjectFile::new(buf)
            })
            .collect::<Result<_>>()?;
        Ok(Self { patches, modfiles })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    type TestError = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn config_parse() -> TestError {
        let toml = r#"
            modfiles = ["loader.o", "mod.o"]

            [[patch]]
            patchfile = "framehook_patch.o"
            start_symbol = "_framehook_patch"
            end_symbol = "_framehook_patch_end"
            virtual_address = 396158"#;

        let config = Configuration::from_toml(toml, Path::new("test/bin/fakefile.toml"))?;

        // Check patch configuration
        assert_eq!(config.patches.len(), 1);
        let patch = &config.patches[0];
        assert_eq!(
            patch.patchfile.path,
            PathBuf::from("test/bin/framehook_patch.o")
        );
        assert_eq!(patch.start_symbol_name, "_framehook_patch".to_string());
        assert_eq!(patch.end_symbol_name, "_framehook_patch_end".to_string());
        assert_eq!(patch.virtual_address, 396158);

        // Check modfile list
        assert_eq!(config.modfiles.len(), 2);
        let modfile = &config.modfiles[0];
        assert_eq!(modfile.path, PathBuf::from("test/bin/loader.o"));
        let modfile = &config.modfiles[1];
        assert_eq!(modfile.path, PathBuf::from("test/bin/mod.o"));
        Ok(())
    }

    #[test]
    fn config_parse_multi_patch() -> TestError {
        let toml = r#"
            modfiles = []

            [[patch]]
            patchfile = "framehook_patch.o"
            start_symbol = "_framehook_patch"
            end_symbol = "_framehook_patch_end"
            virtual_address = 396158

            [[patch]]
            patchfile = "mod.o"
            start_symbol = "start"
            end_symbol = "end"
            virtual_address = 1234"#;

        let config = Configuration::from_toml(toml, Path::new("test/bin/fakefile.toml"))?;

        // Check patch configuration
        assert_eq!(config.patches.len(), 2);
        let patch = &config.patches[0];
        assert_eq!(
            patch.patchfile.path,
            PathBuf::from("test/bin/framehook_patch.o")
        );
        assert_eq!(patch.start_symbol_name, "_framehook_patch".to_string());
        assert_eq!(patch.end_symbol_name, "_framehook_patch_end".to_string());
        assert_eq!(patch.virtual_address, 396158);
        let patch = &config.patches[1];
        assert_eq!(patch.patchfile.path, PathBuf::from("test/bin/mod.o"));
        assert_eq!(patch.start_symbol_name, "start".to_string());
        assert_eq!(patch.end_symbol_name, "end".to_string());
        assert_eq!(patch.virtual_address, 1234);

        // Check modfile list
        assert_eq!(config.modfiles.len(), 0);
        Ok(())
    }
}
