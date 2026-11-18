use std::io::{self, Write};
use std::sync::OnceLock;

use jsonschema::Retrieve;
use serde_json::json;

use crate::bom::document::Document;
use crate::bom::schemas::{DenyRetrieval, ResourceRefused};
use crate::bom::{ValidationError, Validator};
use crate::json::{DecodeError, decode};

fn validator() -> &'static Validator {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| Validator::new().expect("embedded schemas compile offline"))
}

#[test]
fn accepts_both_versions_and_counts_components() {
    for (input, version, count) in [
        (
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":2.0,"components":[{"type":"library","name":"lib"},{"type":"cryptographic-asset","name":"AES","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"ae"}}}]}"#,
            "1.6",
            2,
        ),
        (
            r#"{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[{"type":"cryptographic-asset","name":"AES","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"algorithmFamily":"AES"}}}]}"#,
            "1.7",
            1,
        ),
    ] {
        let summary = validator().validate(input.as_bytes(), true).unwrap();
        assert_eq!(summary.spec_version(), version);
        assert_eq!(summary.component_count(), count);
    }
}

#[test]
fn duplicate_keys_are_typed_and_escape_aware() {
    for input in [
        r#"{"name":null,"name":"safe"}"#,
        r#"{"outer":[{"name":"secret","na\u006de":"safe"}]}"#,
        r#"{"outer":{"\u006eame":1,"name":2}}"#,
    ] {
        assert_eq!(
            decode(input.as_bytes()),
            Err(DecodeError::DuplicateKey {
                key: "name".to_owned()
            })
        );
        assert!(
            matches!(validator().validate(input.as_bytes(), false), Err(ValidationError::Decode(DecodeError::DuplicateKey { key })) if key == "name")
        );
    }
    assert_eq!(
        decode(br#"{"a":1,"b":{"a":2},"c":{"a":3}}"#).unwrap(),
        json!({"a":1,"b":{"a":2},"c":{"a":3}})
    );
}

#[test]
fn rejects_trailing_documents_and_malformed_json() {
    for input in ["{} {}", "{} null", "{} garbage", "null true"] {
        assert_eq!(
            decode(input.as_bytes()),
            Err(DecodeError::MultipleDocuments)
        );
    }
    for input in [
        "",
        "{",
        "[",
        r#"{"x":1,}"#,
        "[1,]",
        "[1 2]",
        r#"{"x" 1}"#,
        "01",
        "1e",
        "NaN",
        r#""\uD800""#,
        "\"unterminated",
        "[truefalse]",
        "[\u{b}]",
        r#"{"x":}"#,
    ] {
        assert!(
            matches!(
                decode(input.as_bytes()),
                Err(DecodeError::InvalidJson { .. })
            ),
            "{input:?}"
        );
    }
    assert!(matches!(
        decode(b"\"\xff\""),
        Err(DecodeError::InvalidJson { .. })
    ));
    assert_eq!(
        decode(b" \n [true, false, null, -1.5e2, \"a\\\"b\"]\t").unwrap(),
        json!([true, false, null, -150.0, "a\"b"])
    );
}

#[test]
fn depth_limit_is_explicit_and_exceeds_serde_default() {
    let accepted = format!("{}0{}", "[".repeat(512), "]".repeat(512));
    assert!(decode(accepted.as_bytes()).is_ok());
    let rejected = format!("{}0{}", "[".repeat(513), "]".repeat(513));
    assert_eq!(
        decode(rejected.as_bytes()),
        Err(DecodeError::DepthExceeded { limit: 512 })
    );
    let rejected = format!("{}{}", "[".repeat(514), "]".repeat(514));
    assert_eq!(
        decode(rejected.as_bytes()),
        Err(DecodeError::DepthExceeded { limit: 512 })
    );
}

#[test]
fn validates_schema_defined_component_nesting_beyond_128_json_levels() {
    for spec in ["1.6", "1.7"] {
        let input = format!(
            "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"{spec}\",\"version\":1,\"components\":[{}{}{}]}}",
            r#"{"type":"cryptographic-asset","name":"ancestor","components":["#.repeat(70),
            r#"{"type":"cryptographic-asset","name":"leaf"}"#,
            "]}".repeat(70),
        );
        let summary = validator().validate(input.as_bytes(), true).unwrap();
        assert_eq!(summary.spec_version(), spec);
        assert_eq!(summary.component_count(), 71);
    }
}

#[test]
fn distinguishes_document_header_errors() {
    assert!(matches!(
        validator().validate(b"[]", false),
        Err(ValidationError::NotObject)
    ));
    assert!(matches!(
        validator().validate(br#"{"specVersion":"1.6"}"#, false),
        Err(ValidationError::InvalidBomFormat)
    ));
    assert!(
        matches!(validator().validate(br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#, false), Err(ValidationError::UnsupportedSpecVersion { version }) if version == "1.5")
    );
    assert!(matches!(
        validator().validate(br#"{"bomFormat":"CycloneDX","specVersion":1.6}"#, false),
        Err(ValidationError::UnsupportedSpecVersion { .. })
    ));
}

#[test]
fn native_empty_inventories_are_allowed_but_external_ones_are_not() {
    for spec in ["1.6", "1.7"] {
        for extra in [
            json!({}),
            json!({"components":[]}),
            json!({"metadata":{"component":{"type":"application","name":"root"}}}),
        ] {
            let mut input = json!({"bomFormat":"CycloneDX","specVersion":spec,"version":1});
            input
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let bytes = serde_json::to_vec(&input).unwrap();
            assert_eq!(
                validator()
                    .validate(&bytes, false)
                    .unwrap()
                    .component_count(),
                0
            );
            assert!(matches!(
                validator().validate(&bytes, true),
                Err(ValidationError::EmptyExternalInventory)
            ));
        }
        let missing = json!({"bomFormat":"CycloneDX","specVersion":spec,"components":[{"type":"library","name":"x"}]});
        let bytes = serde_json::to_vec(&missing).unwrap();
        assert!(validator().validate(&bytes, false).is_ok());
        assert!(matches!(
            validator().validate(&bytes, true),
            Err(ValidationError::MissingDocumentVersion)
        ));
        for version in [json!(0), json!(-1), json!(1.5), json!("1"), json!(null)] {
            let mut input = missing.clone();
            input["version"] = version;
            let bytes = serde_json::to_vec(&input).unwrap();
            for external in [false, true] {
                assert!(matches!(
                    validator().validate(&bytes, external),
                    Err(ValidationError::SchemaViolation { .. })
                ));
            }
        }
    }
}

#[test]
fn external_inventory_requires_top_level_components_even_with_nested_inventory() {
    for spec in ["1.6", "1.7"] {
        for components in [None, Some(json!([]))] {
            let mut input = json!({
                "bomFormat":"CycloneDX", "specVersion":spec, "version":1,
                "metadata":{"component":{
                    "type":"application", "name":"root",
                    "components":[{"type":"library","name":"nested"}]
                }}
            });
            if let Some(components) = components {
                input["components"] = components;
            }
            let bytes = serde_json::to_vec(&input).unwrap();
            let summary = validator().validate(&bytes, false).unwrap();
            assert_eq!(summary.spec_version(), spec);
            assert_eq!(summary.component_count(), 1);
            assert!(matches!(
                validator().validate(&bytes, true),
                Err(ValidationError::EmptyExternalInventory)
            ));
        }
    }
}

#[test]
fn enforces_full_embedded_schemas_including_external_definitions_and_formats() {
    for spec in ["1.6", "1.7"] {
        for invalid in [
            json!({"surprise":true}),
            json!({"serialNumber":"not-a-uuid"}),
            json!({"metadata":{"timestamp":"yesterday"}}),
            json!({"components":[{"type":"imaginary","name":"x"}]}),
            json!({"components":[{"type":"library"}]}),
            json!({"components":[{"type":"library","name":42}]}),
            json!({"components":[{"type":"library","name":"x","surprise":true}]}),
            json!({"components":[{"type":"library","name":"x","licenses":[{"license":{"id":"not-an-SPDX-license"}}]}]}),
            json!({"signature":{"algorithm":"invalid","value":"abc"}}),
            json!({"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{}}]}),
            json!({"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"invalid"}}]}),
            json!({"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"invalid"}}}]}),
        ] {
            let mut input = json!({"bomFormat":"CycloneDX","specVersion":spec});
            input
                .as_object_mut()
                .unwrap()
                .extend(invalid.as_object().unwrap().clone());
            let result = validator().validate(&serde_json::to_vec(&input).unwrap(), false);
            assert!(
                matches!(result, Err(ValidationError::SchemaViolation { instance_path, schema_path, .. }) if !schema_path.is_empty() && (instance_path.is_empty() || instance_path.starts_with('/'))),
                "{input}"
            );
        }
    }
    for field in ["algorithmFamily", "ellipticCurve"] {
        let input = json!({"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{field:"invalid"}}}]});
        assert!(matches!(
            validator().validate(&serde_json::to_vec(&input).unwrap(), false),
            Err(ValidationError::SchemaViolation { .. })
        ));
    }
}

#[test]
fn schema_selection_ignores_instance_schema_and_never_contacts_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for uri in [
        format!("http://{}/evil.json", listener.local_addr().unwrap()),
        "https://attacker.invalid/schema.json".to_owned(),
        "file:///etc/passwd".to_owned(),
        "http://cyclonedx.org/schema/bom-1.5.schema.json".to_owned(),
    ] {
        for spec in ["1.6", "1.7"] {
            let input = json!({"$schema":uri,"bomFormat":"CycloneDX","specVersion":spec});
            assert!(
                validator()
                    .validate(&serde_json::to_vec(&input).unwrap(), false)
                    .is_ok()
            );
            let input = json!({"$schema":uri,"bomFormat":"CycloneDX","specVersion":spec,"components":[{"type":"cryptographic-asset","name":"AES","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"algorithmFamily":"AES"}}}]});
            let result = validator().validate(&serde_json::to_vec(&input).unwrap(), false);
            if spec == "1.7" {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(ValidationError::SchemaViolation { .. })
                ));
            }
        }
    }
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn retriever_denies_all_nonregistered_resources() {
    for uri in [
        "http://127.0.0.1:1/evil.json",
        "https://attacker.invalid/schema.json",
        "file:///etc/passwd",
        "http://cyclonedx.org/schema/bom-1.5.schema.json",
    ] {
        let error = DenyRetrieval
            .retrieve(&jsonschema::Uri::parse(uri.to_owned()).unwrap())
            .unwrap_err();
        assert_eq!(error.downcast_ref::<ResourceRefused>().unwrap().uri, uri);
        assert!(
            jsonschema::options()
                .with_retriever(DenyRetrieval)
                .build(&json!({"$ref":uri}))
                .is_err()
        );
    }
}

#[test]
fn counts_schema_component_locations_not_component_shaped_values() {
    for spec in ["1.6", "1.7"] {
        let input = json!({
            "bomFormat":"CycloneDX", "specVersion":spec, "version":1,
            "metadata":{
                "component":{"type":"application","name":"root","components":[
                    {"type":"library","name":"child","components":[{"type":"library","name":"grandchild"}]}
                ]},
                "tools":{"components":[{"type":"application","name":"tool"}]}
            },
            "components":[{"type":"library","name":"lib","pedigree":{
                "ancestors":[{"type":"library","name":"ancestor"}],
                "descendants":[{"type":"library","name":"descendant"}],
                "variants":[{"type":"library","name":"variant"}]
            }}],
            "formulation":[{"components":[{"type":"application","name":"builder"}]}],
            "annotations":[{"subjects":["lib"],"annotator":{"component":{"type":"application","name":"annotator"}},"timestamp":"2025-01-01T00:00:00Z","text":"review"}],
            "properties":[{"name":"components","value":"[{\"type\":\"library\",\"name\":\"fake\"}]"}]
        });
        assert_eq!(
            validator()
                .validate(&serde_json::to_vec(&input).unwrap(), true)
                .unwrap()
                .component_count(),
            9
        );
    }
}

#[test]
fn native_writer_produces_valid_inventory_and_keeps_graph_and_properties() {
    let document = Document::new(
        vec![json!({"type":"library","bom-ref":"lib","name":"example","version":"2"})],
        vec![json!({"ref":"lib","dependsOn":[]})],
        vec![json!({"name":"bommer:source","value":"fixture"})],
    )
    .with_metadata_component(json!({
        "type":"application", "bom-ref":"root", "name":"fixture-app", "version":"3"
    }));
    let mut bytes = Vec::new();
    document.write(&mut bytes).unwrap();
    let summary = validator().validate(&bytes, false).unwrap();
    assert_eq!(summary.spec_version(), "1.6");
    assert_eq!(summary.component_count(), 1);
    let output: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(output["version"], 1);
    assert_eq!(
        output["dependencies"],
        json!([{"ref":"lib","dependsOn":[]}])
    );
    assert_eq!(
        output["properties"],
        json!([{"name":"bommer:source","value":"fixture"}])
    );
    assert_eq!(
        output["metadata"]["component"],
        json!({"type":"application","bom-ref":"root","name":"fixture-app","version":"3"})
    );
    let mut bytes = Vec::new();
    Document::new(vec![], vec![], vec![])
        .write(&mut bytes)
        .unwrap();
    assert_eq!(
        validator()
            .validate(&bytes, false)
            .unwrap()
            .component_count(),
        0
    );
}

#[test]
fn native_writer_propagates_io_errors() {
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test writer",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        Document::new(vec![], vec![], vec![])
            .write(&mut FailingWriter)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}
