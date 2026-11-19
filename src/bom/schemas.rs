use jsonschema::{Draft, Resource, Retrieve, Uri};
use serde_json::Value;

const RESOURCES: [(&str, &str); 5] = [
    (
        "http://cyclonedx.org/schema/bom-1.6.schema.json",
        include_str!("../../schemas/bom-1.6.schema.json"),
    ),
    (
        "http://cyclonedx.org/schema/bom-1.7.schema.json",
        include_str!("../../schemas/bom-1.7.schema.json"),
    ),
    (
        "http://cyclonedx.org/schema/spdx.schema.json",
        include_str!("../../schemas/spdx.schema.json"),
    ),
    (
        "http://cyclonedx.org/schema/jsf-0.82.schema.json",
        include_str!("../../schemas/jsf-0.82.schema.json"),
    ),
    (
        "http://cyclonedx.org/schema/cryptography-defs.schema.json",
        include_str!("../../schemas/cryptography-defs.schema.json"),
    ),
];

#[derive(Debug, thiserror::Error)]
#[error("schema resource is not embedded: {uri}")]
pub(crate) struct ResourceRefused {
    pub(crate) uri: String,
}

pub(crate) struct DenyRetrieval;

impl Retrieve for DenyRetrieval {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(ResourceRefused {
            uri: uri.to_string(),
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SchemaError {
    #[error("invalid embedded schema JSON")]
    Decode(#[from] serde_json::Error),
    #[error("invalid embedded schema resource")]
    Resource(#[from] jsonschema::ReferencingError),
    #[error("cannot compile embedded schema")]
    Compile(#[from] Box<jsonschema::ValidationError<'static>>),
}

pub(crate) struct CompiledSchema {
    validator: jsonschema::Validator,
    document: Value,
}

impl CompiledSchema {
    pub(crate) fn new(version: &str) -> Result<Self, SchemaError> {
        let mut options = jsonschema::options()
            .with_draft(Draft::Draft7)
            .should_validate_formats(true)
            .with_retriever(DenyRetrieval);
        for (uri, text) in RESOURCES {
            let value = serde_json::from_str(text)?;
            options = options.with_resource(uri, Resource::from_contents(value)?);
        }

        let text = if version == "1.6" {
            RESOURCES[0].1
        } else {
            RESOURCES[1].1
        };
        let document = serde_json::from_str(text)?;
        let validator = options
            .build(&document)
            .map_err(|error| SchemaError::Compile(Box::new(error.to_owned())))?;

        Ok(Self {
            validator,
            document,
        })
    }

    pub(crate) fn validate(
        &self,
        document: &Value,
    ) -> Result<(), Box<jsonschema::ValidationError<'static>>> {
        self.validator
            .validate(document)
            .map_err(|error| Box::new(error.to_owned()))
    }

    pub(crate) fn component_count(&self, document: &Value) -> usize {
        // A set avoids double-counting a location described by multiple schema branches.
        let mut components = std::collections::HashSet::new();
        let mut pending = vec![(document, &self.document, String::new())];
        while let Some((value, schema, path)) = pending.pop() {
            if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
                if reference == "#/definitions/component" && path != "/metadata/component" {
                    components.insert(path.clone());
                }
                if let Some(pointer) = reference.strip_prefix('#')
                    && let Some(definition) = self.document.pointer(pointer)
                {
                    pending.push((value, definition, path));
                }
                continue;
            }

            if let (Some(object), Some(properties)) = (value.as_object(), schema.get("properties"))
            {
                for (key, child) in object {
                    if let Some(property) = properties.get(key) {
                        let escaped = key.replace('~', "~0").replace('/', "~1");
                        pending.push((child, property, format!("{path}/{escaped}")));
                    }
                }
            }
            if let (Some(array), Some(items)) = (value.as_array(), schema.get("items")) {
                for (index, child) in array.iter().enumerate() {
                    pending.push((child, items, format!("{path}/{index}")));
                }
            }

            for keyword in ["allOf", "anyOf", "oneOf"] {
                if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
                    for branch in branches {
                        pending.push((value, branch, path.clone()));
                    }
                }
            }
        }

        components.len()
    }
}
