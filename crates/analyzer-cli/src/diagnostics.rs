//! Render structured parser errors in English while preserving arguments and values.
use clap::error::{ContextKind, ContextValue, ErrorKind};
use std::{fmt::Write, process::ExitCode};

fn context(error: &clap::Error, kind: ContextKind) -> String {
    error.get(kind).map(ToString::to_string).unwrap_or_default()
}

pub fn render(error: &clap::Error) -> String {
    let arg = context(error, ContextKind::InvalidArg);
    let value = context(error, ContextKind::InvalidValue);
    let mut out = String::from("Error: ");
    match error.kind() {
        ErrorKind::MissingRequiredArgument => {
            out.push_str("Missing the following required arguments or inputs:\n");
            if let Some(ContextValue::Strings(args)) = error.get(ContextKind::InvalidArg) {
                for arg in args {
                    let _ = writeln!(out, "  {arg}");
                }
            }
        }
        ErrorKind::UnknownArgument => {
            let _ = writeln!(out, "Unrecognized argument \"{arg}\".");
        }
        ErrorKind::InvalidSubcommand => {
            let subcommand = context(error, ContextKind::InvalidSubcommand);
            let _ = writeln!(out, "Unrecognized command \"{subcommand}\".");
        }
        ErrorKind::MissingSubcommand => {
            out.push_str("Please specify a subcommand to run.\n");
        }
        ErrorKind::InvalidValue if value.is_empty() => {
            let _ = writeln!(out, "Argument \"{arg}\" needs a value.");
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let _ = writeln!(out, "Invalid value \"{value}\" for argument \"{arg}\".");
            if ["--limit", "--max-file-mb", "--max-records"]
                .iter()
                .any(|name| arg.starts_with(name))
            {
                out.push_str("  This argument requires a non-negative integer.\n");
            }
        }
        ErrorKind::ArgumentConflict => {
            let prior = context(error, ContextKind::PriorArg);
            if arg == prior {
                let _ = writeln!(out, "Argument \"{arg}\" cannot be repeated.");
            } else {
                let _ = writeln!(out, "Argument \"{arg}\" cannot be combined with \"{prior}\".");
            }
        }
        ErrorKind::NoEquals => {
            let _ = writeln!(out, "Assign a value to \"{arg}\" with an equals sign, for example --arg=value.");
        }
        ErrorKind::TooManyValues => {
            let _ = writeln!(out, "Argument \"{arg}\" received an extra value \"{value}\".");
        }
        ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            let expected = if error.kind() == ErrorKind::TooFewValues {
                context(error, ContextKind::MinValues)
            } else {
                context(error, ContextKind::ExpectedNumValues)
            };
            let actual = context(error, ContextKind::ActualNumValues);
            let _ = writeln!(
                out,
                "Argument \"{arg}\" requires {expected} values, but {actual} were provided."
            );
        }
        ErrorKind::InvalidUtf8 => out.push_str("Command line arguments contain invalid UTF-8 text.\n"),
        ErrorKind::Io => out.push_str("Failed to read or write command line data.\n"),
        ErrorKind::Format => out.push_str("Failed to generate command line output.\n"),
        _ => out.push_str("Unable to parse command line arguments; check the argument names and input format.\n"),
    }
    for (kind, label) in [
        (ContextKind::ValidValue, "possible values"),
        (ContextKind::ValidSubcommand, "possible commands"),
        (ContextKind::SuggestedArg, "did you mean the argument"),
        (ContextKind::SuggestedSubcommand, "did you mean the command"),
        (ContextKind::SuggestedValue, "did you mean the value"),
    ] {
        let value = context(error, kind);
        if !value.is_empty() {
            let _ = writeln!(out, "  {label}: {value}");
        }
    }
    let usage = context(error, ContextKind::Usage);
    if !usage.is_empty() {
        // Clap generates usage text in English; user-supplied values pass through as-is.
        let _ = writeln!(out, "\n{usage}");
    }
    out.push_str("\nFor more details and examples, add -h or --help to the current command.\n");
    out
}

pub fn report(error: clap::Error) -> ExitCode {
    let code = error.exit_code() as u8;
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        if let Err(error) = error.print() {
            eprintln!("Error: failed to display help or version information: {error}");
            return ExitCode::FAILURE;
        }
    } else {
        eprint!("{}", render(&error));
    }
    ExitCode::from(code)
}
