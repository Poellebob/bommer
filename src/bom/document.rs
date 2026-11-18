#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecVersion {
    V1_6,
    V1_7,
}

#[derive(Debug)]
pub(crate) struct Document {
    version: SpecVersion,
    components: Vec<Component>,
}

#[derive(Debug)]
pub(crate) struct Component {
    reference: String,
    name: String,
    version: Option<String>,
}

// Native document construction will be added with the first native collector.
