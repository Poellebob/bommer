use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FailureKind {
    Cancelled,
    Timeout,
    ProcessExit,
    OutputLimit,
    Spawn,
    Io,
    Validation,
    Collection,
}

#[derive(Debug, Serialize)]
pub(crate) struct Failure {
    kind: FailureKind,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
}

impl Failure {
    pub(crate) fn new(kind: FailureKind) -> Self {
        Self {
            kind,
            exit_code: None,
            stream: None,
            limit: None,
        }
    }

    pub(crate) fn exited(code: Option<i32>) -> Self {
        Self {
            exit_code: code,
            ..Self::new(FailureKind::ProcessExit)
        }
    }

    pub(crate) fn limited(stream: &'static str, limit: usize) -> Self {
        Self {
            stream: Some(stream),
            limit: Some(limit),
            ..Self::new(FailureKind::OutputLimit)
        }
    }
}
