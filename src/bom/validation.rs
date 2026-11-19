use crate::bom::schemas;
use crate::json;

#[derive(Debug)]
pub(crate) struct DocumentSummary {
    pub(crate) version: String,
    pub(crate) component_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidationError {
    #[error("cannot decode BOM: {0}")]
    Decode(#[from] json::DecodeError),
    #[error("unsupported CycloneDX specVersion {version:?}")]
    UnsupportedSpecificationVersion { version: String },
    #[error("BOM does not conform to the CycloneDX schema at {instance_path}")]
    SchemaViolation {
        instance_path: String,
        schema_path: String,
        #[source]
        source: Box<jsonschema::ValidationError<'static>>,
    },
    #[error("cannot compile embedded BOM schemas: {0}")]
    Schema(#[from] schemas::SchemaError),
    #[error("BOM must be a JSON object")]
    NotObject,
    #[error("bomFormat must explicitly be CycloneDX")]
    InvalidBomFormat,
    #[error("external BOM must explicitly declare a positive document version")]
    MissingDocumentVersion,
    #[error("external BOM contains no inventory components")]
    EmptyExternalInventory,
}

pub(crate) struct Validator {
    version_1_6: schemas::CompiledSchema,
    version_1_7: schemas::CompiledSchema,
}

impl Validator {
    pub(crate) fn new() -> Result<Self, ValidationError> {
        Ok(Self {
            version_1_6: schemas::CompiledSchema::new("1.6")?,
            version_1_7: schemas::CompiledSchema::new("1.7")?,
        })
    }

    pub(crate) fn validate(
        &self,
        bytes: &[u8],
        external: bool,
    ) -> Result<DocumentSummary, ValidationError> {
        let document = json::decode(bytes)?;
        let object = document.as_object().ok_or(ValidationError::NotObject)?;
        if object.get("bomFormat").and_then(serde_json::Value::as_str) != Some("CycloneDX") {
            return Err(ValidationError::InvalidBomFormat);
        }

        let version = object
            .get("specVersion")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let schema = match version {
            "1.6" => &self.version_1_6,
            "1.7" => &self.version_1_7,
            _ => {
                return Err(ValidationError::UnsupportedSpecificationVersion {
                    version: version.to_owned(),
                });
            }
        };
        if external && !object.contains_key("version") {
            return Err(ValidationError::MissingDocumentVersion);
        }

        schema
            .validate(&document)
            .map_err(|source| ValidationError::SchemaViolation {
                instance_path: source.instance_path.to_string(),
                schema_path: source.schema_path.to_string(),
                source,
            })?;
        if external
            && object
                .get("components")
                .and_then(serde_json::Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            return Err(ValidationError::EmptyExternalInventory);
        }

        let component_count = schema.component_count(&document);
        Ok(DocumentSummary {
            version: version.to_owned(),
            component_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::OnceLock;

    use serde_json::json;

    use crate::bom::validation::{ValidationError, Validator};

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

            assert_eq!(summary.version, version);
            assert_eq!(summary.component_count, count);
        }
    }

    #[test]
    fn validates_schema_defined_component_nesting_beyond_128_json_levels() {
        for specification_version in ["1.6", "1.7"] {
            let input = format!(
                "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"{specification_version}\",\"version\":1,\"components\":[{}{}{}]}}",
                r#"{"type":"cryptographic-asset","name":"ancestor","components":["#.repeat(70),
                r#"{"type":"cryptographic-asset","name":"leaf"}"#,
                "]}".repeat(70),
            );

            let summary = validator().validate(input.as_bytes(), true).unwrap();

            assert_eq!(summary.version, specification_version);
            assert_eq!(summary.component_count, 71);
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
            matches!(validator().validate(br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#, false), Err(ValidationError::UnsupportedSpecificationVersion { version }) if version == "1.5")
        );
        assert!(matches!(
            validator().validate(br#"{"bomFormat":"CycloneDX","specVersion":1.6}"#, false),
            Err(ValidationError::UnsupportedSpecificationVersion { .. })
        ));
    }

    #[test]
    fn native_empty_inventories_are_allowed_but_external_ones_are_not() {
        for specification_version in ["1.6", "1.7"] {
            for extra in [
                json!({}),
                json!({"components":[]}),
                json!({"metadata":{"component":{"type":"application","name":"root"}}}),
            ] {
                let mut input = json!({"bomFormat":"CycloneDX","specVersion":specification_version,"version":1});
                input
                    .as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                let bytes = serde_json::to_vec(&input).unwrap();

                assert_eq!(
                    validator().validate(&bytes, false).unwrap().component_count,
                    0
                );
                assert!(matches!(
                    validator().validate(&bytes, true),
                    Err(ValidationError::EmptyExternalInventory)
                ));
            }

            let missing = json!({"bomFormat":"CycloneDX","specVersion":specification_version,"components":[{"type":"library","name":"x"}]});
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
        for specification_version in ["1.6", "1.7"] {
            for components in [None, Some(json!([]))] {
                let mut input = json!({
                    "bomFormat":"CycloneDX", "specVersion":specification_version, "version":1,
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

                assert_eq!(summary.version, specification_version);
                assert_eq!(summary.component_count, 1);
                assert!(matches!(
                    validator().validate(&bytes, true),
                    Err(ValidationError::EmptyExternalInventory)
                ));
            }
        }
    }

    #[test]
    fn enforces_full_embedded_schemas_including_external_definitions_and_formats() {
        for specification_version in ["1.6", "1.7"] {
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
                let mut input =
                    json!({"bomFormat":"CycloneDX","specVersion":specification_version});
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
            for specification_version in ["1.6", "1.7"] {
                let input = json!({"$schema":uri,"bomFormat":"CycloneDX","specVersion":specification_version});
                assert!(
                    validator()
                        .validate(&serde_json::to_vec(&input).unwrap(), false)
                        .is_ok()
                );

                let input = json!({"$schema":uri,"bomFormat":"CycloneDX","specVersion":specification_version,"components":[{"type":"cryptographic-asset","name":"AES","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"algorithmFamily":"AES"}}}]});
                let result = validator().validate(&serde_json::to_vec(&input).unwrap(), false);

                if specification_version == "1.7" {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(
                        result,
                        Err(ValidationError::SchemaViolation { .. })
                    ));
                }
            }
        }

        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn counts_schema_component_locations_not_component_shaped_values() {
        for specification_version in ["1.6", "1.7"] {
            let input = json!({
                "bomFormat":"CycloneDX", "specVersion":specification_version, "version":1,
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
                    .component_count,
                9
            );
        }
    }
}
