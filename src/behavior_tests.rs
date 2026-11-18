use crate::cli::{CliError, Request};
use crate::model::{CommandError, CommandSpec, Name, NameError};

#[test]
fn distinguishes_commands_and_rejects_unknown_input() {
    let cases = [
        (vec!["scan"], Ok(Request::Scan)),
        (vec!["doctor"], Ok(Request::Doctor)),
        (
            vec!["invent"],
            Err(CliError::UnknownCommand("invent".into())),
        ),
        (
            vec!["scan", "--unexpected"],
            Err(CliError::UnsupportedArgument("--unexpected".into())),
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(Request::parse(input.into_iter().map(Into::into)), expected);
    }
}

#[test]
fn inventory_names_cannot_escape_the_artifact_namespace() {
    let cases = [
        ("", Err(NameError::Empty)),
        ("../host", Err(NameError::InvalidCharacters)),
        ("a/b", Err(NameError::InvalidCharacters)),
        ("-host", Err(NameError::InvalidCharacters)),
    ];
    for (input, expected) in cases {
        assert_eq!(Name::new(input.into()), expected);
    }
    let input = "application_2-prod";
    assert_eq!(
        Name::new(input.into()).unwrap().as_str(),
        "application_2-prod"
    );
}

#[test]
fn command_construction_preserves_literal_arguments() {
    let executable = std::ffi::OsString::from("scanner");
    let arguments = vec!["a b".into(), "$(touch unexpected)".into(), "*.json".into()];
    let command = CommandSpec::new(executable, arguments).unwrap();
    assert_eq!(command.executable(), "scanner");
    assert_eq!(
        command.arguments(),
        &["a b", "$(touch unexpected)", "*.json"]
    );
}

#[test]
fn commands_require_an_executable() {
    let executable = std::ffi::OsString::new();
    let arguments = vec!["scan".into()];
    assert!(matches!(
        CommandSpec::new(executable, arguments),
        Err(CommandError::EmptyExecutable)
    ));
}
