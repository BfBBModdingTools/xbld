//! A custom error type for linker operation
//!

use std::{error, io, result};

pub type Result<T> = result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Io(String, io::Error),
    Goblin(String, goblin::error::Error),
    ConfigParse(toml::de::Error),
    Relocation(String, RelocationError),
    Patch(String, PatchError),
}

impl error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(s, e) => write!(f, "I/O Error '{}'\n{}", s, e),
            Error::Goblin(s, e) => write!(f, "Problem with object file '{}'.\n{}", s, e),
            Error::ConfigParse(e) => writeln!(f, "Problem parsing config file: \n\t{}", e),
            Error::Relocation(s, e) => {
                write!(f, "Could not process relocation in file '{}'.\n{}", s, e)
            }
            Error::Patch(s, e) => write!(f, "Could not apply patch '{}'.\n{}", s, e),
        }
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Self::ConfigParse(e)
    }
}

#[derive(Debug)]
pub enum RelocationError {
    MissingSection(String),
    MissingSectionOffset(String),
    MissingSymbol(u32),
    MissingName(goblin::error::Error),
    MissingAddress(String),
}

impl error::Error for RelocationError {}

impl std::fmt::Display for RelocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelocationError::MissingSection(s) => write!(f, "Could not locate section '{}'", s),
            RelocationError::MissingSectionOffset(s) => {
                write!(f, "Could not locate section offset for section '{}'", s)
            }
            RelocationError::MissingSymbol(i) => {
                write!(f, "Could not locate symbol with index '{}'", i)
            }
            RelocationError::MissingName(e) => {
                write!(f, "Could not find the name of a symbol. {}", e)
            }
            RelocationError::MissingAddress(s) => {
                write!(f, "Could not find the virtual address of symbol '{}'.", s)
            }
        }?;
        write!(f, "\nThis is probably a bug. Please report.")
    }
}

#[derive(Debug)]
pub enum PatchError {
    UndefinedSymbol(String),
    SectionMismatch(),
    MissingSection(String),
    InvalidAddress(u32),
}

impl error::Error for PatchError {}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::UndefinedSymbol(s) => write!(f, "Patch symbol '{}' undefined", s),
            PatchError::SectionMismatch() => write!(
                f,
                "Section Mismatch: Start Symbol is in a different section than End Symbol",
            ),
            PatchError::MissingSection(s) => write!(f, "Could not locate section '{}'", s),
            PatchError::InvalidAddress(a) => write!(
                f,
                "Invalid Address: Virtual address {} is unused by given XBE",
                a
            ),
        }
    }
}
