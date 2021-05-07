mod xbe;

use std::collections::hash_map::HashMap;

use goblin::pe;
use goblin::pe::Coff;

use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use xbe::{Section, SectionFlags, Xbe};

// The plan:
//
// Determine virtual address start and size for every section
//
// Determine the virtual address of every symbol, stored in a
// hashtable of symbol name and address
//
// Perform all relocations

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

#[test]
fn tmptest() {
    inject(
        &["bin/framehook_patch.o"],
        &["bin/loader.o", "bin/mod.o"],
        "bin/default.xbe",
        "bin/output.xbe",
    );
}

pub fn inject(_patchfiles: &[&str], modnames: &[&str], input_xbe: &str, output_xbe: &str) {
    let mut bytes = Vec::with_capacity(modnames.len());
    let mut coffs = Vec::with_capacity(modnames.len());

    // Parse files
    // TODO: Write these as one loop? (lifetimes are tricky)
    for n in modnames.iter() {
        bytes.push(std::fs::read(n).expect("Could not read object file"));
    }

    for b in bytes.iter() {
        coffs.push(Coff::parse(b).expect("Could not parse file (Make sure COFF format is used)"));
    }

    // Need to:
    //  - separate patch files from other object files
    //      - patch files should be able to reference symbols in mod files, but mod files
    //        should never be able to use symbols in patch files
    //  - combine .text, .data, .bss, .rdata of each non-patch file
    //      - have start offsets within the sections for each file
    //  - assign virtual address ranges to each combined section
    //  - build combined symbol table
    //  - process base game patch files
    //  - process relocations within each file
    //  - insert sections into xbe

    // combine sections
    let mut section_map = SectionMap::from_data(&bytes, &coffs, modnames);

    // Assign virtual addresses
    let mut xbe = Xbe::from_path(input_xbe);
    let mut last_virtual_address = xbe.get_next_virtual_address();

    for (_, sec) in section_map.0.iter_mut() {
        sec.virtual_address = last_virtual_address;
        last_virtual_address =
            xbe.get_next_virtual_address_after(last_virtual_address + sec.bytes.len() as u32);
    }

    // build symbol table
    let symbol_table = SymbolTable::from_section_map(&mut section_map, &coffs, modnames);

    // process relocations
    process_relocations(&symbol_table, &mut section_map, &bytes, &coffs, modnames);

    // insert sections into XBE
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

#[derive(Debug, Clone)]
struct SectionBytes<'a> {
    text: Option<&'a [u8]>,
    data: Option<&'a [u8]>,
    bss: Option<&'a [u8]>,
    rdata: Option<&'a [u8]>,
}

impl<'a> SectionBytes<'a> {
    pub fn from_coff(coff: &'a Coff, coff_bytes: &'a [u8]) -> Self {
        let mut s = SectionBytes {
            text: None,
            data: None,
            bss: None,
            rdata: None,
        };

        for sec in coff.sections.iter().filter(|s| s.size_of_raw_data != 0) {
            let start = sec.pointer_to_raw_data as usize;
            let end = start + sec.size_of_raw_data as usize;
            let data = &coff_bytes[start..end];
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
    pub fn from_data(bytes: &[Vec<u8>], coffs: &[Coff], files: &[&'a str]) -> Self {
        let mut section_map = HashMap::new();
        for ((bytes, coff), file) in bytes.iter().zip(coffs.iter()).zip(files.iter()) {
            // Extract section data from file
            let section_bytes = SectionBytes::from_coff(coff, bytes);

            // Combine sections from all files
            if let Some(b) = section_bytes.text {
                if !section_map.contains_key(".mtext") {
                    section_map.insert(".mtext", SectionInProgress::new());
                }
                section_map.get_mut(".mtext").unwrap().add_bytes(b, file);
            }
            if let Some(b) = section_bytes.data {
                if !section_map.contains_key(".mdata") {
                    section_map.insert(".mdata", SectionInProgress::new());
                }
                section_map.get_mut(".mdata").unwrap().add_bytes(b, file);
            }
            if let Some(b) = section_bytes.bss {
                if !section_map.contains_key(".mbss") {
                    section_map.insert(".mbss", SectionInProgress::new());
                }
                section_map.get_mut(".mbss").unwrap().add_bytes(b, file);
            }
            if let Some(b) = section_bytes.rdata {
                if !section_map.contains_key(".mrdata") {
                    section_map.insert(".mrdata", SectionInProgress::new());
                }
                section_map.get_mut(".mrdata").unwrap().add_bytes(b, file);
            }
        }
        Self(section_map)
    }
}

/// Maps from a given symbol name to its virtual address
// TODO: Remove heap allocation (String)
#[derive(Debug, Clone)]
struct SymbolTable(HashMap<String, u32>);

impl SymbolTable {
    pub fn from_section_map(section_map: &mut SectionMap, coffs: &[Coff], files: &[&str]) -> Self {
        let mut symbol_table = HashMap::new();
        let section_map = &mut section_map.0;
        for (coff, file) in coffs.iter().zip(files.iter()) {
            for (_, _, symbol) in coff.symbols.iter() {
                // Get section data from table
                let sec_data = match coff
                    .sections
                    .get(symbol.section_number as usize - 1)
                    .and_then(|s| s.name().ok())
                {
                    Some(".text") => section_map
                        .get_mut(".mtext")
                        .expect("Could not find section .mtext"),
                    Some(".data") => section_map
                        .get_mut(".mdata")
                        .expect("Could not find section .mdata"),
                    Some(".bss") => section_map
                        .get_mut(".mbss")
                        .expect("Could not find section .mbss"),
                    Some(".mrdata") => section_map
                        .get_mut(".mrdata")
                        .expect("Could not find section .mrdata"),
                    _ => continue,
                };

                match symbol.storage_class {
                    pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if symbol.typ == 0x20 => {
                        if symbol.section_number == 0 {
                            // External function
                            continue;
                        }
                        symbol_table.insert(
                            symbol.name(&coff.strings).unwrap().to_owned(),
                            match sec_data.file_offset_start.get(file) {
                                Some(addr) => *addr + symbol.value,
                                None => continue,
                            },
                        );
                    }
                    pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if symbol.section_number > 0 => {
                        symbol_table.insert(
                            symbol.name(&coff.strings).unwrap().to_owned(),
                            match sec_data.file_offset_start.get(file) {
                                Some(addr) => *addr + symbol.value,
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
                        symbol_table.insert(
                            symbol.name(&coff.strings).unwrap().to_owned(),
                            match sec_data.file_offset_start.get(file) {
                                Some(addr) => *addr,
                                None => continue,
                            },
                        );
                    }
                    pe::symbol::IMAGE_SYM_CLASS_FILE => continue,
                    _ => todo!("storage_class {} not implemented", symbol.storage_class),
                }
            }
        }
        Self(symbol_table)
    }
}

fn process_relocations(
    symbol_table: &SymbolTable,
    section_map: &mut SectionMap,
    bytes: &[Vec<u8>],
    coffs: &[Coff],
    files: &[&str],
) {
    let symbol_table = &symbol_table.0;
    let section_map = &mut section_map.0;
    for ((bytes, coff), file) in bytes.iter().zip(coffs.iter()).zip(files.iter()) {
        for section in coff.sections.iter() {
            for reloc in section.relocations(&bytes).unwrap_or_default() {
                // find symbol
                let symbol = match coff.symbols.get(reloc.symbol_table_index as usize) {
                    None => continue,
                    Some(symbol) => symbol.1,
                };

                let symbol_name = symbol.name(&coff.strings).unwrap();

                // Find virtual address of symbol
                let symb_addr = match symbol_table.get(symbol_name) {
                    Some(addr) => *addr,
                    _ => continue,
                };

                // find data to update
                // TODO: This is assuming 32 bit relocations
                // TODO: handle section_number -1 and 0
                let sec_data = match &section.name {
                    b".text\0\0\0" => section_map
                        .get_mut(".mtext")
                        .expect("Could not find section .mtext"),
                    b".data\0\0\0" => section_map
                        .get_mut(".mdata")
                        .expect("Could not find section .mdata"),
                    b".bss\0\0\0\0" => section_map
                        .get_mut(".mbss")
                        .expect("Could not find section .mbss"),
                    b".rdata\0\0" => section_map
                        .get_mut(".mrdata")
                        .expect("Could not find section .mrdata"),
                    _ => continue,
                };

                // TODO: I'm pretty sure there's a bug here. We need to add the offset for this file
                // TODO: Testing needed!
                let d_start = sec_data.file_offset_start.get(file).unwrap() + reloc.virtual_address;
                let mut cur = std::io::Cursor::new(&mut sec_data.bytes);
                cur.set_position(d_start as u64);
                let offset = cur.read_u32::<LE>().unwrap();
                cur.set_position(d_start as u64);

                // update data
                cur.write_u32::<LE>(symb_addr + offset).unwrap();
            }
        }
    }
}

mod tests {
    #[test]
    fn file_offsets() {
        let bytes_a = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8];
        let bytes_b = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8];
        let mut section = crate::SectionInProgress::new();
        section.add_bytes(&bytes_a, "bytesA");
        section.add_bytes(&bytes_b, "bytesB");

        assert_eq!(section.file_offset_start.len(), 2);
        assert_eq!(*section.file_offset_start.get("bytesA").unwrap(), 0);
        assert_eq!(*section.file_offset_start.get("bytesB").unwrap(), 12);
    }

    #[test]
    fn add_bytes() {
        let bytes_a = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8];
        let bytes_b = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8];
        let mut combined = bytes_a.clone();
        combined.append(&mut bytes_b.clone());

        let mut section = crate::SectionInProgress::new();
        section.add_bytes(&bytes_a, "bytesA");
        section.add_bytes(&bytes_b, "bytesB");

        assert_eq!(section.bytes.len(), 20);
        assert_eq!(section.bytes, combined);
    }
}
