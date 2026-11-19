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

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use crate::path_encoding::path_text;

    #[test]
    fn utf8_paths_preserve_text_except_reserved_prefixes() {
        for (path, expected) in [
            ("", ""),
            ("/tmp/a b", "/tmp/a b"),
            ("relative/path", "relative/path"),
            ("bommer:unix-bytes:ff", "bommer:utf8:bommer:unix-bytes:ff"),
            ("bommer:utf8:literal", "bommer:utf8:bommer:utf8:literal"),
            ("/bommer:unix-bytes:ff", "/bommer:unix-bytes:ff"),
        ] {
            assert_eq!(path_text(Path::new(path)), expected);
        }
        assert_eq!(path_text(Path::new("/tmp/\u{e6}")), "/tmp/\u{e6}");
    }

    #[test]
    fn non_utf8_paths_encode_every_byte_without_loss() {
        let path = Path::new(OsStr::from_bytes(b"/tmp/\xff\xfe"));
        let encoded = path_text(path);

        assert_eq!(encoded, "bommer:unix-bytes:2f746d702ffffe");
        assert_eq!(
            hex::decode(encoded.strip_prefix("bommer:unix-bytes:").unwrap()).unwrap(),
            path.as_os_str().as_bytes()
        );
        assert_ne!(path_text(Path::new(&encoded)), encoded);
    }
}
