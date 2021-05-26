//! A custom error type for linker operation
//!

use std::{error, io, result};

#[derive(Debug)]
pub enum Error {
    Io(String, io::Error),
    Goblin(String, goblin::error::Error),
}

impl error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(s, e) => write!(fmt, "Could not read file '{}'\n{}", s, e),
            Error::Goblin(s, e) => write!(fmt, "Problem with object file '{}'.\n{}", s, e),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
