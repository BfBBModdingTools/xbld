use bfbb_linker::{config::Configuration, error::Error, xbe};
use clap::{App, Arg};
use std::{env, process};
use const_format::formatcp;

struct Cli {
    config: String,
    input_path: String,
    output_path: String,
}

fn main() {
    let cli = parse_args();

    if let Err(e) = do_injection(&cli) {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn do_injection(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::from_toml(
        std::fs::read_to_string(&cli.config)
            .map_err(|e| Error::Io(cli.config.clone(), e))?
            .as_str(),
    )?;
    let xbe: xbe::Xbe =
        bfbb_linker::inject(config, xbe::Xbe::new(&std::fs::read(&cli.input_path)?)?)?;
    std::fs::write(&cli.output_path, xbe.serialize()?)?;

    Ok(())
}

fn parse_args() -> Cli {
    const CONFIG: &str = "CONFIG";
    const INPUT: &str = "INPUT";
    const OUTPUT: &str = "OUTPUT";
    let matches = App::new("BfBB Linker")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A linker for patching and injecting cutom code into an XBE binary.")
        .arg(Arg::from_usage(formatcp!(
            "<{}> 'Config file specifying code to be injected",
            CONFIG
        )))
        .arg(Arg::from_usage(formatcp!(
            "<{}> 'XBE Binary to inject into'",
            INPUT
        )))
        .arg(Arg::from_usage(formatcp!(
            "<{}> 'File path to write output to'",
            OUTPUT
        )))
        .get_matches();

    Cli {
        config: matches.value_of(CONFIG).unwrap().to_string(),
        input_path: matches.value_of(INPUT).unwrap().to_string(),
        output_path: matches.value_of(OUTPUT).unwrap().to_string(),
    }
}
