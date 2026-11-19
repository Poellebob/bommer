use std::path::Path;

// JSON strings cannot represent arbitrary Unix path bytes. Reserved prefixes keep
// the tagged hex form distinguishable from literal UTF-8 paths with the same text.
pub(crate) fn path_text(path: &Path) -> String {
    match path.to_str() {
        Some(text)
            if text.starts_with("bommer:unix-bytes:") || text.starts_with("bommer:utf8:") =>
        {
            format!("bommer:utf8:{text}")
        }
        Some(text) => text.into(),
        None => format!(
            "bommer:unix-bytes:{}",
            hex::encode(path.as_os_str().as_encoded_bytes())
        ),
    }
}
