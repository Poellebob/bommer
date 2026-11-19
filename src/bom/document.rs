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

#[cfg(test)]
mod tests {

    use crate::bom::document::Document;
    use crate::bom::validation::Validator;
    use serde_json::json;
    use std::io::{self, Write};
    use std::sync::OnceLock;
    fn validator() -> &'static Validator {
        static VALIDATOR: OnceLock<Validator> = OnceLock::new();

        VALIDATOR.get_or_init(|| Validator::new().expect("embedded schemas compile offline"))
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

        assert_eq!(summary.version, "1.6");
        assert_eq!(summary.component_count, 1);

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
            validator().validate(&bytes, false).unwrap().component_count,
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
}
