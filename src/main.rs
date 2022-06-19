use std::path::PathBuf;

use anyhow::{Context, Result};
use bfbb_linker::config::Configuration;
use clap::Parser;
use log::LevelFilter;

#[derive(Debug, Parser)]
#[clap(name = "BfBB Linker")]
#[clap(about, author, version)]
struct Cli {
    #[clap(value_parser)]
    /// Config file specifying code to be injected
    config: PathBuf,
    #[clap(value_parser)]
    /// XBE Binary to inject into
    input: PathBuf,
    #[clap(value_parser)]
    /// File path to write output to
    output: PathBuf,
    #[clap(short, long)]
    /// Silence all output
    quiet: bool,
    #[clap(short, long)]
    #[clap(action = clap::ArgAction::Count)]
    /// Increase message verbosity
    verbosity: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(if cli.quiet {
            LevelFilter::Off
        } else {
            match cli.verbosity {
                0 => LevelFilter::Warn,
                1 => LevelFilter::Info,
                2 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            }
        })
        .format_timestamp(None)
        .init();

    do_injection(&cli)
}

fn do_injection(cli: &Cli) -> Result<()> {
    let config = Configuration::from_file(&cli.config)
        .with_context(|| format!("Failed to parse config file '{:?}'", &cli.config))?;
    let xbe: xbe::Xbe = bfbb_linker::inject(config, xbe::Xbe::new(&std::fs::read(&cli.input)?)?)?;
    std::fs::write(&cli.output, xbe.serialize()?)?;

    Ok(())
}
