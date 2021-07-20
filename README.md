# BfBB Linker

This repository contains a WIP linker for injecting code into existing executables for the Microsoft Xbox. It takes COFF format object files as input. The project is currently only tested with SpongeBob SquarePants: Battle for Bikini Bottom (2003). It is intended to be usable for any xbox executable (XBE), but likely currently makes assumptions that won't be compatible with some executables.

The linker works by taking the .text, .data, .rdata, and .bss sections from it's input files and placing them into new .mtext, .mdata, .mrdata, and .mbss sections at the end of the executable. Patches can be defined to overwrite parts of existing sections to be able to hook into the new code. Various parts of the XBE's headers have to be updated to account for the new sections.

The project is still in very early development and not yet intended for actual use. The CLI is not yet completely implemented or decided on and is currently undocumented.

## Features

### Current

- Inject patches that overwrite existing code or data, and define symbols for them.
- Add custom code and data at the end of an XBE.

## Building

### Requirements

- [Rust](https://www.rust-lang.org/tools/install)

### Compiling

- Running 'cargo build' from the project root should "just work".

## Contributions

- If you have suggestions about the project feel free to open an [Issue](https://www.github.com/BfBBModdingTools/bfbb_linker/issues) to start discussion. PRs will always be considered as well.
