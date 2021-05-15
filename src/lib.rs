mod xbe;

use itertools::Itertools;
use std::{
    collections::hash_map::HashMap,
    io::{Cursor, Write},
};

use goblin::pe::{self, relocation::Relocation, section_table::SectionTable, symbol::Symbol, Coff};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use xbe::{Section, SectionFlags, Xbe};

#[derive(Debug, Clone)]
struct SectionInProgress<'a> {
    bytes: Vec<u8>,
    file_offset_start: HashMap<&'a str, u32>,
    virtual_address: u32,
}

impl<'a> SectionInProgress<'a> {
    fn new() -> Self {
        Self {
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
}

struct ObjectFile<'a> {
    bytes: &'a [u8],
    coff: Coff<'a>,
    filename: &'a str,
}

impl<'a> ObjectFile<'a> {
    fn new(bytes: &'a [u8], filename: &'a str) -> Self {
        Self {
            bytes,
            coff: Coff::parse(&bytes)
                .unwrap_or_else(|e| panic!("Failed to parse '{}'. {}", filename, e)),
            filename,
        }
    }
}

struct Patch<'a> {
    patchfile: &'a ObjectFile<'a>,
    start_symbol_name: &'a str,
    end_symbol_name: &'a str,
    virtual_address: u32,
}

impl Patch<'_> {
    pub fn apply(&self, xbe: &mut Xbe, symbol_table: &SymbolTable) {
        // Process Patch Coff (symbols have already been read)
        let mut section_map = SectionMap::from_data(std::slice::from_ref(self.patchfile));
        //TODO: This assumes patch is at beginning of .text
        section_map.0.get_mut(".mtext").unwrap().virtual_address = self.virtual_address;

        process_relocations(
            symbol_table,
            &mut section_map,
            std::slice::from_ref(self.patchfile),
        );

        let xbe_bytes = xbe
            .get_bytes_mut(self.virtual_address..self.virtual_address + 5)
            .unwrap();

        let start_symbol = self.find_symbol(self.start_symbol_name);
        let end_symbol = self.find_symbol(self.end_symbol_name);

        if start_symbol.section_number != end_symbol.section_number {
            panic!("Patch start and end symbol are not in the same section");
        }

        // TODO: HARDEDCODED BADD
        let patch_bytes = &section_map.0.get(".mtext").unwrap().bytes
            [start_symbol.value as usize..end_symbol.value as usize];

        let mut c = Cursor::new(xbe_bytes);
        c.write_all(patch_bytes).expect("Failed to apply patch");
    }

    fn find_symbol(&self, name: &str) -> Symbol {
        let fail = || -> ! {
            panic!(
                "Patch Symbol '{}' is not present in patch file '{}'.",
                self.start_symbol_name, self.patchfile.filename
            );
        };

        self.patchfile
            .coff
            .symbols
            .iter()
            .find(|(_, _, s)| {
                s.name(&self.patchfile.coff.strings)
                    .unwrap_or_else(|_| fail())
                    == name
            })
            .unwrap_or_else(|| fail())
            .2
    }
}

#[derive(Debug, Clone)]
struct SectionBytes<'a> {
    text: Option<&'a [u8]>,
    data: Option<&'a [u8]>,
    bss: Option<&'a [u8]>,
    rdata: Option<&'a [u8]>,
}

impl<'a> SectionBytes<'a> {
    pub fn from_obj(file: &'a ObjectFile) -> Self {
        let mut s = SectionBytes {
            text: None,
            data: None,
            bss: None,
            rdata: None,
        };

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
#[derive(Debug, Clone)]
struct SectionMap<'a>(HashMap<&'a str, SectionInProgress<'a>>);

impl<'a> SectionMap<'a> {
    pub fn from_data(files: &'a [ObjectFile]) -> Self {
        let mut section_map = HashMap::new();
        for file in files.iter() {
            // Extract section data from file
            let section_bytes = SectionBytes::from_obj(file);

            // Combine sections from all files
            if let Some(b) = section_bytes.text {
                if !section_map.contains_key(".mtext") {
                    section_map.insert(".mtext", SectionInProgress::new());
                }
                section_map
                    .get_mut(".mtext")
                    .unwrap()
                    .add_bytes(b, file.filename);
            }
            if let Some(b) = section_bytes.data {
                if !section_map.contains_key(".mdata") {
                    section_map.insert(".mdata", SectionInProgress::new());
                }
                section_map
                    .get_mut(".mdata")
                    .unwrap()
                    .add_bytes(b, file.filename);
            }
            if let Some(b) = section_bytes.bss {
                if !section_map.contains_key(".mbss") {
                    section_map.insert(".mbss", SectionInProgress::new());
                }
                section_map
                    .get_mut(".mbss")
                    .unwrap()
                    .add_bytes(b, file.filename);
            }
            if let Some(b) = section_bytes.rdata {
                if !section_map.contains_key(".mrdata") {
                    section_map.insert(".mrdata", SectionInProgress::new());
                }
                section_map
                    .get_mut(".mrdata")
                    .unwrap()
                    .add_bytes(b, file.filename);
            }
        }
        Self(section_map)
    }

    pub fn get(&self, section: &str) -> Option<&SectionInProgress> {
        self.0.get(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
    }

    pub fn get_mut(&mut self, section: &str) -> Option<&mut SectionInProgress<'a>> {
        self.0.get_mut(match section {
            ".text" => ".mtext",
            ".data" => ".mdata",
            ".bss" => ".mbss",
            ".rdata" => ".mrdata",
            _ => return None,
        })
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

    fn extract_symbols(&mut self, section_map: &SectionMap, obj: &ObjectFile) {
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
                    .unwrap(),
            ) {
                Some(data) => data,
                None => continue,
            };

            match sym.storage_class {
                pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if sym.typ == 0x20 => {
                    self.0.insert(
                        sym.name(&obj.coff.strings).unwrap().to_owned(),
                        match sec_data.file_offset_start.get(obj.filename) {
                            Some(addr) => *addr + sym.value + sec_data.virtual_address,
                            None => {
                                let patch_conf =
                                    String::from_utf8(std::fs::read("bin/patch.conf").unwrap())
                                        .unwrap();
                                let mut split = patch_conf.split(' ');
                                let patchname = split.next().unwrap();
                                //skip end symbol
                                split.next();
                                let address: u32 = split.next().unwrap().parse().unwrap();

                                if sym.name(&obj.coff.strings).unwrap() == patchname {
                                    address
                                } else {
                                    continue;
                                }
                            }
                        },
                    );
                }
                pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if sym.section_number > 0 => {
                    self.0.insert(
                        sym.name(&obj.coff.strings).unwrap().to_owned(),
                        match sec_data.file_offset_start.get(obj.filename) {
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
                        sym.name(&obj.coff.strings).unwrap().to_owned(),
                        match sec_data.file_offset_start.get(obj.filename) {
                            Some(addr) => *addr + sec_data.virtual_address,
                            None => continue,
                        },
                    );
                }
                pe::symbol::IMAGE_SYM_CLASS_FILE => continue,
                _ => todo!("storage_class {} not implemented", sym.storage_class),
            }
        }
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
pub fn inject(patchfiles: &[&str], modfiles: &[&str], input_xbe: &str, output_xbe: &str) {
    let patchbytes: Vec<Vec<u8>> = patchfiles
        .iter()
        .map(|f| std::fs::read(f).unwrap_or_else(|_| panic!("Could not read object file {}", f)))
        .collect();
    let patches: Vec<ObjectFile> = patchfiles
        .iter()
        .zip(patchbytes.iter())
        .map(|(f, b)| ObjectFile::new(b, f))
        .collect();

    let modbytes: Vec<Vec<u8>> = modfiles
        .iter()
        .map(|f| std::fs::read(f).unwrap_or_else(|_| panic!("Could not read object file {}", f)))
        .collect();
    let mods: Vec<ObjectFile> = modfiles
        .iter()
        .zip(modbytes.iter())
        .map(|(f, b)| ObjectFile::new(b, f))
        .collect();

    // combine sections
    let mut section_map = SectionMap::from_data(&mods);

    // Assign virtual addresses
    let mut xbe = Xbe::from_path(input_xbe);
    let mut last_virtual_address = xbe.get_next_virtual_address();

    for (_, sec) in section_map.0.iter_mut() {
        sec.virtual_address = last_virtual_address;
        last_virtual_address =
            xbe.get_next_virtual_address_after(last_virtual_address + sec.bytes.len() as u32);
    }

    // build symbol table
    let mut symbol_table = SymbolTable::new();
    for obj in patches.iter().chain(mods.iter()) {
        symbol_table.extract_symbols(&section_map, obj);
    }
    println!("{:#?}", &symbol_table);

    // process relocations for mods
    process_relocations(&symbol_table, &mut section_map, &mods);

    // read patch config
    let config =
        String::from_utf8(std::fs::read("bin/patch.conf").expect("Could not read config file."))
            .expect("Could not read config file.");
    let patches: Vec<Patch> = config
        .split(' ')
        .tuples()
        .zip(patches.iter())
        .map(
            |((start_symbol_name, end_symbol_name, addr), patchfile)| Patch {
                patchfile,
                start_symbol_name,
                end_symbol_name,
                virtual_address: addr.parse().expect("Malformed address in config"),
            },
        )
        .collect();

    // apply patches
    for patch in &patches {
        patch.apply(&mut xbe, &symbol_table);
    }

    // insert sections into XBE
    // TODO: Sort by virtual address (iterating over HashMap gives non-deterministic results)
    for (name, sec) in section_map.0 {
        xbe.add_section(Section {
            name: name.to_owned() + "\0",
            flags: SectionFlags::PRELOAD
                | match name {
                    ".mtext" => SectionFlags::EXECUTABLE,
                    ".mdata" | ".mbss" => SectionFlags::WRITABLE,
                    _ => SectionFlags::PRELOAD, //No "zero" value
                },
            virtual_size: sec.bytes.len() as u32,
            data: sec.bytes,
            virtual_address: sec.virtual_address,
        })
    }
    xbe.write_to_file(output_xbe);
}

fn process_relocations(
    symbol_table: &SymbolTable,
    section_map: &mut SectionMap,
    files: &[ObjectFile],
) {
    for file in files.iter() {
        for section in file.coff.sections.iter() {
            for reloc in section.relocations(&file.bytes).unwrap_or_default() {
                // find symbol
                println!("{:#?}", (&reloc, &file.filename));

                // We are assuming i386 relocations only (Which is fine for Xbox)
                match reloc.typ {
                    goblin::pe::relocation::IMAGE_REL_I386_DIR32 => {
                        relocation_dir32(file, &reloc, section, symbol_table, section_map)
                    }

                    goblin::pe::relocation::IMAGE_REL_I386_REL32 => {
                        relocation_rel32(file, &reloc, section, symbol_table, section_map)
                    }
                    //TODO: Support all relocations
                    _ => panic!("relocation type {} not supported", reloc.typ),
                }
            }
        }
    }
}

fn relocation_dir32(
    file: &ObjectFile,
    reloc: &Relocation,
    section: &SectionTable,
    symbol_table: &SymbolTable,
    section_map: &mut SectionMap,
) {
    let symbol = match file.coff.symbols.get(reloc.symbol_table_index as usize) {
        None => return,
        Some(symbol) => symbol.1,
    };

    let symbol_name = symbol.name(&file.coff.strings).unwrap();

    // Find virtual address of symbol
    let symb_addr = match symbol_table.0.get(symbol_name) {
        Some(addr) => *addr,
        _ => return,
    };

    // find data to update
    // TODO: This is assuming 32 bit relocations
    // TODO: handle section_number -1 and 0
    let sec_data = section_map
        .get_mut(section.name().unwrap())
        .unwrap_or_else(|| panic!("Could not find section .m{}", section.name().unwrap()));

    // TODO: I'm pretty sure there's a bug here. We need to add the offset for this file
    // TODO: Testing needed!
    let d_start = sec_data.file_offset_start.get(file.filename).unwrap() + reloc.virtual_address;
    let mut cur = std::io::Cursor::new(&mut sec_data.bytes);
    cur.set_position(d_start as u64);
    let offset = cur.read_u32::<LE>().unwrap();
    cur.set_position(d_start as u64);

    // update data
    cur.write_u32::<LE>(symb_addr + offset).unwrap();
}

fn relocation_rel32(
    file: &ObjectFile,
    reloc: &Relocation,
    section: &SectionTable,
    symbol_table: &SymbolTable,
    section_map: &mut SectionMap,
) {
    let symbol = match file.coff.symbols.get(reloc.symbol_table_index as usize) {
        None => return,
        Some(symbol) => symbol.1,
    };

    let symbol_name = symbol.name(&file.coff.strings).unwrap();

    // Find virtual address of symbol
    let symb_addr = match symbol_table.0.get(symbol_name) {
        Some(addr) => *addr,
        _ => return,
    };

    // find data to update
    let sec_data = section_map
        .get_mut(section.name().unwrap())
        .unwrap_or_else(|| panic!("Could not find section .m{}", section.name().unwrap()));

    let sec_addr = sec_data
        .file_offset_start
        .get(file.filename)
        .expect("Failed to get file start information to process a relocation.")
        + reloc.virtual_address;

    let mut cur = std::io::Cursor::new(&mut sec_data.bytes);
    cur.set_position(sec_addr as u64);
    let target_address = cur.read_u32::<LE>().unwrap() + symb_addr;
    let from_address = sec_addr + sec_data.virtual_address + 5;

    // update data
    cur.set_position(sec_addr as u64);
    cur.write_u32::<LE>((target_address as i32 - from_address as i32) as u32)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::{inject, SectionInProgress};

    #[test]
    fn no_panic() {
        inject(
            &["bin/framehook_patch.o"],
            &["bin/loader.o", "bin/mod.o"],
            "bin/default.xbe",
            "bin/output.xbe",
        );
    }

    #[test]
    fn file_offsets() {
        let bytes_a: Vec<u8> = (0u8..12u8).collect();
        let bytes_b: Vec<u8> = (0u8..8u8).collect();
        let mut section = SectionInProgress::new();
        section.add_bytes(&bytes_a, "bytesA");
        section.add_bytes(&bytes_b, "bytesB");

        assert_eq!(section.file_offset_start.len(), 2);
        assert_eq!(*section.file_offset_start.get("bytesA").unwrap(), 0);
        assert_eq!(*section.file_offset_start.get("bytesB").unwrap(), 12);
    }

    #[test]
    fn add_bytes() {
        let bytes_a: Vec<u8> = (0u8..12u8).collect();
        let bytes_b: Vec<u8> = (0u8..8u8).collect();
        let mut combined = bytes_a.clone();
        combined.append(&mut bytes_b.clone());

        let mut section = SectionInProgress::new();
        section.add_bytes(&bytes_a, "bytesA");
        section.add_bytes(&bytes_b, "bytesB");

        assert_eq!(section.bytes.len(), 20);
        assert_eq!(section.bytes, combined);
    }
}
