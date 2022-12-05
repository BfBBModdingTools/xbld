use anyhow::Context;
use goblin::pe::Coff;
use log::info;
use std::{fmt::Debug, fs, ops::Deref, path::PathBuf};
use yoke::{Yoke, Yokeable};

/// A parsed coff file paird with it's backing-data and filepath
pub struct ObjectFile {
    pub path: PathBuf,
    coff: Yoke<YokeableCoff<'static>, Box<[u8]>>,
}

impl Debug for ObjectFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectFile")
            .field("path", &self.path)
            .field("coff", &self.coff())
            .finish()
    }
}

impl ObjectFile {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let bytes = fs::read(&path)
            .with_context(|| format!("Failed to read object file '{path:?}'"))?
            .into_boxed_slice();

        info!("Parsing ObjectFile '{path:?}'");
        let coff = Yoke::try_attach_to_cart(bytes, |b| Coff::parse(b).map(|coff| coff.into()))
            .with_context(|| format!("Failed to parse object file '{path:?}'"))?;

        Ok(Self { path, coff })
    }

    #[inline]
    pub fn coff(&self) -> &Coff<'_> {
        self.coff.get()
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        self.coff.backing_cart()
    }
}

#[derive(Yokeable)]
struct YokeableCoff<'a>(Coff<'a>);

impl<'a> Deref for YokeableCoff<'a> {
    type Target = Coff<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<Coff<'a>> for YokeableCoff<'a> {
    fn from(v: Coff<'a>) -> Self {
        Self(v)
    }
}
