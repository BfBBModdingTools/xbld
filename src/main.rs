use bfbb_linker::error::{Error, ParseError, Result};
use serde::Deserialize;
use std::{env, process};

fn main() {
    let config = match parse_config(env::args()) {
        Ok(c) => c,
        Err(e @ Error::Config(_)) => {
            eprintln!("{}", e);
            process::exit(0)
        }
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1)
        }
    };
    println!("{:?}", &config);

    match bfbb_linker::inject(config) {
        Ok(_) => {}
        Err(e) => eprint!("{}", e),
    }
}

fn parse_config<'a, I>(args: I) -> Result<bfbb_linker::Configuration<'a>>
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
    let mut arg_iter = args.into_iter();
    while let Some(next) = arg_iter.next() {
        match next.as_str() {
            FLAG_CONFIG => config = Some(arg_iter.next().unwrap()),
            FLAG_INPUT_XBE => input_xbe = Some(arg_iter.next().unwrap()),
            FLAG_HELP => return Err(Error::Config(ParseError::HelpRequested)),
            s => output_xbe = Some(s.to_owned()),
        }
    }

    #[derive(Deserialize)]
    struct Conf {
        patch: Vec<Inner>,
        modfiles: Vec<String>,
    }

    #[derive(Deserialize)]
    struct Inner {
        patchfile: String,
        start_symbol: String,
        end_symbol: String,
        virtual_address: u32,
    }

    // Unwrap parameters
    let config = config.ok_or(Error::Config(ParseError::MissingArgument(
        "Config file is required.",
    )))?;
    let config: Conf = toml::from_str(
        std::fs::read_to_string(config.as_str())
            .map_err(|e| Error::Io(config, e))?
            .as_str(),
    )
    .map_err(|e| Error::Config(ParseError::ConfigParse(e)))?;
    let input_xbe = input_xbe.ok_or(Error::Config(ParseError::MissingArgument(
        "Input XBE is required.",
    )))?;
    let output_xbe = output_xbe.ok_or(Error::Config(ParseError::MissingArgument(
        "Output XBE is required",
    )))?;

    Ok(bfbb_linker::Configuration {
        patches: config
            .patch
            .into_iter()
            .map(|p| {
                bfbb_linker::Patch::new(
                    p.patchfile,
                    p.start_symbol,
                    p.end_symbol,
                    p.virtual_address,
                )
            })
            .collect::<std::result::Result<_, _>>()?,
        modfiles: config
            .modfiles
            .into_iter()
            .map(bfbb_linker::ObjectFile::new)
            .collect::<std::result::Result<_, _>>()?,
        input_xbe,
        output_xbe,
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
            "bin/conf.toml".to_string(),
            "--input".to_string(),
            "bin/default.xbe".to_string(),
            "bin/output.xbe".to_string(),
        ];
        let c = parse_config(args.into_iter());

        assert!(c.is_ok());
        let c = c.unwrap();
        assert_eq!(c.patches.len(), 1);
        assert_eq!(c.modfiles.len(), 1);
        assert_eq!(c.input_xbe, "bin/default.xbe".to_string());
        assert_eq!(c.output_xbe, "bin/output.xbe".to_string());
    }
}
