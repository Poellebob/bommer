use std::io::{self, Write};

use serde_json::{Value, json};

#[derive(Debug)]
pub(crate) struct Document {
    value: Value,
}

impl Document {
    /// Construct a native 1.6 inventory. Callers supply schema-valid records;
    /// the scan validates the complete serialized document before publication.
    pub(crate) fn new(
        components: Vec<Value>,
        dependencies: Vec<Value>,
        properties: Vec<Value>,
    ) -> Self {
        Self {
            value: json!({
                "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": components,
                "dependencies": dependencies,
                "properties": properties,
            }),
        }
    }

    pub(crate) fn with_metadata_component(mut self, component: Value) -> Self {
        self.value["metadata"] = json!({ "component": component });
        self
    }

    pub(crate) fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut *writer, &self.value).map_err(|error| {
            io::Error::new(
                error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
                error,
            )
        })?;
        writer.write_all(b"\n")
    }
}
