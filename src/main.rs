use std::path::PathBuf;

use anyhow::{Context, Result};
use bfbb_linker::config::Configuration;
use clap::{App, Arg};
use const_format::formatcp;

use env_logger::Builder;
use log::LevelFilter;

struct Cli {
    config_path: PathBuf,
    input_path: String,
    output_path: String,
}

fn main() -> Result<()> {
    let cli = parse_args();

    do_injection(&cli)
}

fn do_injection(cli: &Cli) -> Result<()> {
    let config = Configuration::from_file(&cli.config_path)
        .with_context(|| format!("Failed to parse config file '{:?}'", &cli.config_path))?;
    let xbe: xbe::Xbe =
        bfbb_linker::inject(config, xbe::Xbe::new(&std::fs::read(&cli.input_path)?)?)?;
    std::fs::write(&cli.output_path, xbe.serialize()?)?;

    Ok(())
}

fn parse_args() -> Cli {
    const CONFIG: &str = "CONFIG";
    const INPUT: &str = "INPUT";
    const OUTPUT: &str = "OUTPUT";
    const VERBOSITY: &str = "verbosity";
    const QUIET: &str = "quiet";
    let matches = App::new("BfBB Linker")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A linker for patching and injecting custom code into an XBE binary.")
        .args_from_usage(formatcp!(
            "<{CONFIG}> 'Config file specifying code to be injected'
            <{INPUT}> 'XBE Binary to inject into'
            <{OUTPUT}> 'File path to write output to'
            -q, --{QUIET}  'Silence all output'",
        ))
        .arg(
            Arg::with_name(VERBOSITY)
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
        .get_matches();

    Builder::new()
        .filter_level(if matches.is_present(QUIET) {
            LevelFilter::Off
        } else {
            match matches.occurrences_of(VERBOSITY) {
                0 => LevelFilter::Warn,
                1 => LevelFilter::Info,
                2 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            }
        })
        .format_timestamp(None)
        .init();

    Cli {
        config_path: matches.value_of(CONFIG).unwrap().into(),
        input_path: matches.value_of(INPUT).unwrap().to_string(),
        output_path: matches.value_of(OUTPUT).unwrap().to_string(),
    }
}
