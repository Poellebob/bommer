use std::ffi::OsString;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Help,
    Version,
    Scan,
    Doctor,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CliError {
    UnknownCommand(OsString),
    UnsupportedArgument(OsString),
}

impl Request {
    pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let request = match args.next().as_deref() {
            None => Self::Help,
            Some(value) if value == "help" || value == "--help" || value == "-h" => Self::Help,
            Some(value) if value == "version" || value == "--version" => Self::Version,
            Some(value) if value == "scan" => Self::Scan,
            Some(value) if value == "doctor" => Self::Doctor,
            Some(value) => return Err(CliError::UnknownCommand(value.to_owned())),
        };
        if let Some(argument) = args.next() {
            return Err(CliError::UnsupportedArgument(argument));
        }
        Ok(request)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(command) => write!(f, "unknown command: {command:?}"),
            Self::UnsupportedArgument(argument) => {
                write!(
                    f,
                    "argument not supported by the Rust scaffold: {argument:?}"
                )
            }
        }
    }
}

impl std::error::Error for CliError {}
