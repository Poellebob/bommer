use crate::model::{InventoryKind, Job, Name};

#[derive(Debug, Default)]
pub(crate) struct Selection {
    kind: Option<InventoryKind>,
    application: Option<Name>,
}

impl Selection {
    pub(crate) fn new(kind: Option<InventoryKind>, application: Option<Name>) -> Self {
        Self { kind, application }
    }
}

#[derive(Debug)]
pub(crate) struct Plan {
    jobs: Vec<Job>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PlanError {
    UnknownApplication { name: Name },
    EmptySelection,
    ArtifactCollision { name: String },
}
