use super::AsciiStr;

#[test]
fn invalid_ascii_string() {
    AsciiStr::try_from("💀").expect_err("AsciiStr with non-ASCII string should have failed");
}
