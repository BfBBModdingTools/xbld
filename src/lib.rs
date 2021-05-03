pub mod xbe;

use std::collections::hash_map::HashMap;

use goblin::pe;
use goblin::pe::{relocation::Relocations, Coff};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use xbe::{Section, SectionFlags, XBE};

// The plan:
//
// Determine virtual address start and size for every section
//
// Determine the virtual address of every symbol, stored in a
// hashtable of symbol name and address
//
// Perform all relocations

#[test]
fn test() {
    let mut xbe = XBE::new("bin/default.xbe");
    let bytes = std::fs::read("bin/mod.o").expect("Could not read object file");
    let coff =
        Coff::parse(&bytes).expect("Could not parse object file (make sure it's COFF format");

    // Create sections at correct addresses
    let (secs, sec_starts) = initialize_sections(&mut xbe, &coff, &bytes);

    // create symbol table
    let symbol_table = make_symbol_table(&coff, &sec_starts);

    // evaluate relocations
    evaluate_relocations(&mut xbe, &coff, secs, &symbol_table);
}

fn initialize_sections<'a>(
    xbe: &XBE,
    coff: &'a Coff,
    bytes: &'a Vec<u8>,
) -> (
    Vec<(Section, Result<Relocations<'a>, goblin::error::Error>)>,
    HashMap<usize, u32>,
) {
    let mut secs = vec![];
    let mut sec_starts = HashMap::new();
    let mut next_virtual_addr = xbe.get_next_virtual_address();
    for i in 0..coff.header.number_of_sections as usize {
        let sec = match coff.sections.get(i) {
            None => continue,
            Some(sec) => sec,
        };

        // Skip if there's no data (externals) for now
        if sec.size_of_raw_data == 0 {
            continue;
        }

        // Find the sections we're interested in
        let (name, flags) = match String::from_utf8(sec.name.to_vec()).as_deref() {
            Ok(".text\0\0\0") => (".mtext\0", SectionFlags::PRELOAD | SectionFlags::EXECUTABLE),
            Ok(".data\0\0\0") => (".mdata\0", SectionFlags::PRELOAD | SectionFlags::WRITABLE),
            Ok(".bss\0\0\0\0") => (".mbss\0", SectionFlags::PRELOAD | SectionFlags::WRITABLE),
            Ok(".rdata\0\0") => (".mrdata\0", SectionFlags::PRELOAD),
            _ => continue,
        };

        let start = sec.pointer_to_raw_data as usize;
        let end = start + sec.size_of_raw_data as usize;
        let data = bytes[start..end].to_owned();

        sec_starts.insert(i, next_virtual_addr);

        secs.push((
            Section {
                name: name.to_owned(),
                flags,
                data,
                virtual_address: next_virtual_addr,
                virtual_size: sec.size_of_raw_data,
            },
            sec.relocations(&bytes),
        ));
        next_virtual_addr += sec.size_of_raw_data;
        next_virtual_addr += (0x20 - next_virtual_addr % 0x20) % 0x20;
    }
    (secs, sec_starts)
}

fn make_symbol_table(coff: &Coff, sec_starts: &HashMap<usize, u32>) -> HashMap<String, u32> {
    // TODO: a lot (implement all the other relevant Storage Classes)
    let mut symbol_table = HashMap::new();
    for (_index, _name, symbol) in coff.symbols.iter() {
        match symbol.storage_class {
            pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if symbol.typ == 0x20 => {
                symbol_table.insert(
                    symbol.name(&coff.strings).unwrap().to_owned(),
                    match sec_starts.get(&(symbol.section_number as usize - 1)) {
                        Some(addr) => *addr + symbol.value,
                        None => continue,
                    },
                );
            }
            pe::symbol::IMAGE_SYM_CLASS_EXTERNAL if symbol.section_number > 0 => {
                symbol_table.insert(
                    symbol.name(&coff.strings).unwrap().to_owned(),
                    match sec_starts.get(&(symbol.section_number as usize - 1)) {
                        Some(addr) => *addr + symbol.value,
                        None => continue,
                    },
                );
            }
            pe::symbol::IMAGE_SYM_CLASS_EXTERNAL => {
                // TODO: Resolve virtual address for externals
                symbol_table.insert(symbol.name(&coff.strings).unwrap().to_owned(), 0);
            }
            pe::symbol::IMAGE_SYM_CLASS_STATIC => {
                symbol_table.insert(
                    symbol.name(&coff.strings).unwrap().to_owned(),
                    match sec_starts.get(&(symbol.section_number as usize - 1)) {
                        Some(addr) => *addr,
                        None => continue,
                    },
                );
            }
            pe::symbol::IMAGE_SYM_CLASS_FILE => continue,
            _ => todo!("storage_class {} not implemented", symbol.storage_class),
        }
    }
    symbol_table
}

fn evaluate_relocations(
    xbe: &mut XBE,
    coff: &pe::Coff,
    secs: Vec<(Section, Result<Relocations, goblin::error::Error>)>,
    symbol_table: &HashMap<String, u32>,
) {
    for (mut sec, relocs) in secs {
        let relocs = relocs.unwrap_or_else(|_| goblin::pe::relocation::Relocations::default());

        for reloc in relocs {
            // find symbol
            let symbol = match coff.symbols.get(reloc.symbol_table_index as usize) {
                None => continue,
                Some(symbol) => symbol.1,
            };

            // Find virtual address of symbol
            let symb_addr = match symbol_table.get(symbol.name(&coff.strings).unwrap()) {
                Some(addr) => *addr,
                _ => continue,
            };

            // find data to update
            // TODO: This is assuming 32 bit relocations
            let d_start = reloc.virtual_address as usize;
            let mut cur = std::io::Cursor::new(&mut sec.data);
            cur.set_position(d_start as u64);
            let offset = cur.read_u32::<LE>().unwrap();
            cur.set_position(d_start as u64);

            // update data
            cur.write_u32::<LE>(symb_addr + offset).unwrap();
        }

        xbe.add_section(sec)
    }
}
