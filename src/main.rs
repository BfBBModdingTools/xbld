use bfbb_linker::{
    error::{CliError, Error, Result},
    xbe,
};
use std::{env, process};

struct Cli<'a> {
    config: bfbb_linker::Configuration<'a>,
    input_path: String,
    output_path: String,
}

fn main() {
    let cli = match parse_args(env::args()) {
        Ok(c) => c,
        Err(e @ Error::Cli(CliError::HelpRequested)) => {
            println!("{}", e);
            process::exit(0)
        }
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1)
        }
    };

    let xbe: xbe::Xbe = bfbb_linker::inject(cli.config, xbe::Xbe::from_path(cli.input_path))
        .unwrap_or_else(|e| {
            eprint!("{}", e);
            process::exit(1);
        });
    xbe.write_to_file(cli.output_path);
}

fn parse_args<'a, I>(mut args: I) -> Result<Cli<'a>>
where
    I: Iterator<Item = std::string::String>,
{
    // TODO: Implment switch alternatives for flags
    const FLAG_HELP: &str = "--help";
    const FLAG_CONFIG: &str = "--config";
    const FLAG_INPUT_XBE: &str = "--input";

    let mut config: Option<String> = None;
    let mut input_xbe: Option<String> = None;
    let mut output_xbe: Option<String> = None;

    // Skip over this program's name
    args.next();
    while let Some(next) = args.next() {
        match next.as_str() {
            FLAG_CONFIG => config = Some(args.next().unwrap()),
            FLAG_INPUT_XBE => input_xbe = Some(args.next().unwrap()),
            FLAG_HELP => return Err(Error::Cli(CliError::HelpRequested)),
            s => output_xbe = Some(s.to_owned()),
        }
    }

    // Unwrap parameters
    let config = config.ok_or(Error::Cli(CliError::MissingArgument(
        "Config file is required.",
    )))?;
    let config = std::fs::read_to_string(config.as_str()).map_err(|e| Error::Io(config, e))?;

    let input_path = input_xbe.ok_or(Error::Cli(CliError::MissingArgument(
        "Input XBE is required.",
    )))?;
    let output_path = output_xbe.ok_or(Error::Cli(CliError::MissingArgument(
        "Output XBE is required",
    )))?;

    let config = bfbb_linker::Configuration::from_toml(config.as_str())?;
    Ok(Cli {
        config,
        input_path,
        output_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli() {
        let args = vec![
            "program_name".to_string(),
            "--config".to_string(),
            "test/bin/conf.toml".to_string(),
            "--input".to_string(),
            "test/bin/default.xbe".to_string(),
            "bin/output.xbe".to_string(),
        ];
        let c = parse_args(args.into_iter());

        assert!(c.is_ok());
    }
}
