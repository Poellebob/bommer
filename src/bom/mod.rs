pub(crate) mod document;
pub(crate) mod schemas;

use crate::json;

#[derive(Debug)]
pub(crate) struct DocumentSummary {
    version: String,
    component_count: usize,
}

impl DocumentSummary {
    pub(crate) fn spec_version(&self) -> &str {
        &self.version
    }

    pub(crate) fn component_count(&self) -> usize {
        self.component_count
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidationError {
    #[error("cannot decode BOM: {0}")]
    Decode(#[from] json::DecodeError),
    #[error("unsupported CycloneDX specVersion {version:?}")]
    UnsupportedSpecVersion { version: String },
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
    v1_6: schemas::CompiledSchema,
    v1_7: schemas::CompiledSchema,
}

impl Validator {
    pub(crate) fn new() -> Result<Self, ValidationError> {
        Ok(Self {
            v1_6: schemas::CompiledSchema::new("1.6")?,
            v1_7: schemas::CompiledSchema::new("1.7")?,
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
            "1.6" => &self.v1_6,
            "1.7" => &self.v1_7,
            _ => {
                return Err(ValidationError::UnsupportedSpecVersion {
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
