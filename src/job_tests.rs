use crate::job::{Name, NameError};

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
