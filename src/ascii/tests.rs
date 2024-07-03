use super::AsciiStr;

#[test]
fn invalid_ascii_string() {
    assert!(
        AsciiStr::try_from_str("💀").is_none(),
        "AsciiStr with non-ASCII string should have failed"
    );
}
