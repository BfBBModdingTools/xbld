use std::{env, process};

fn main() {
    let config = match parse_config(env::args().collect()) {
        Ok(c) => c,
        Err(ParseError::HelpRequested) => {
            println!("Usage: {} [--] OUTPUT\n", env::args().next().unwrap());
            println!("  --help        Show this help page");
            println!("  -p, --patches List of patches to be applied");
            println!("  -m, --mods    List of mods to be injected");
            println!("  -i, --input   Base XBE file to inject code into");
            process::exit(0);
        }
        Err(ParseError::MissingArgument(e)) => {
            println!("Missing Argument: \n\t{}", e);
            process::exit(1);
        }
    };
    println!("{:?}", &config);

    bfbb_linker::inject(config);
}

#[derive(Debug, Clone, Copy)]
enum ParseError {
    HelpRequested,
    MissingArgument(&'static str),
}

fn parse_config(args: Vec<String>) -> Result<bfbb_linker::Configuration, ParseError> {
    // TODO: Implment switch alternatives for flags
    const FLAG_HELP: &str = "--help";
    const FLAG_PATCHES: &str = "--patches";
    const FLAG_MODS: &str = "--mods";
    const FLAG_INPUT_XBE: &str = "--input";

    let mut patchfiles: Option<Vec<String>> = None;
    let mut modfiles: Option<Vec<String>> = None;
    let mut input_xbe: Option<String> = None;
    let mut output_xbe: Option<String> = None;

    // Skip over this program's name
    let mut arg_iter = args.into_iter();
    while let Some(next) = arg_iter.next() {
        match next.as_str() {
            FLAG_PATCHES => {
                patchfiles = Some(
                    arg_iter
                        .next()
                        .unwrap()
                        .split(':')
                        .map(|s| s.to_string())
                        .collect(),
                )
            }
            FLAG_MODS => {
                modfiles = Some(
                    arg_iter
                        .next()
                        .unwrap()
                        .split(':')
                        .map(|s| s.to_string())
                        .collect(),
                )
            }
            FLAG_INPUT_XBE => input_xbe = Some(arg_iter.next().unwrap()),
            FLAG_HELP => return Err(ParseError::HelpRequested),
            s => output_xbe = Some(s.to_owned()),
        }
    }

    // Unwrap parameters
    let patchfiles = match patchfiles {
        Some(p) => p,
        None => return Err(ParseError::MissingArgument("Patch file(s) are required.")),
    };
    let modfiles = match modfiles {
        Some(m) => m,
        None => return Err(ParseError::MissingArgument("Mod files(s) are required.")),
    };
    let input_xbe = match input_xbe {
        Some(i) => i,
        None => return Err(ParseError::MissingArgument("Input XBE is required.")),
    };
    let output_xbe = match output_xbe {
        Some(o) => o,
        None => return Err(ParseError::MissingArgument("Output XBE is required")),
    };

    Ok(bfbb_linker::Configuration {
        patchfiles,
        modfiles,
        input_xbe,
        output_xbe,
    })
}
