use super::*;
use crate::AsciiStr;

fn force_ascii(value: &str) -> AsciiStr {
    value
        .try_into()
        .expect("ASCII conversion should not have failed")
}

#[test]
fn invalid_privilege_level_none() {
    let level = PrivilegeLevel::of(42);
    assert!(level.is_none());
}

// TODO: move to root?
#[test]
fn invalid_ascii_string() {
    AsciiStr::try_from("💀").expect_err("AsciiStr with non-ASCII string should have failed");
}

#[test]
fn client_information_long_username() {
    let username = [0x41u8; 512]; // AAA...AAA
    ClientInformation::new(
        core::str::from_utf8(&username).unwrap(),
        force_ascii("tcp49"),
        force_ascii("127.0.0.1"),
    )
    .expect_err("username should be too long");
}

#[test]
fn arguments_two_required() {
    let argument_array = [
        Argument::new(force_ascii("service"), force_ascii("test"), true)
            .expect("argument should be valid"),
        Argument::new(force_ascii("random-argument"), force_ascii(""), true)
            .expect("argument should be valid"),
    ];

    let arguments = Arguments::try_from(&argument_array[..])
        .expect("argument array -> Arguments conversion should have worked");

    let mut buffer = [0u8; 40];

    // ensure header information is serialized correctly
    arguments
        .serialize_header(&mut buffer)
        .expect("header serialization should succeed");
    assert_eq!(buffer[..3], [2, 12, 16]);

    arguments
        .serialize_body(&mut buffer)
        .expect("body serialization should succeed");
    assert_eq!(&buffer[..28], b"service=testrandom-argument=");
}

#[test]
fn arguments_one_optional() {
    let arguments_array = [Argument::new(
        force_ascii("optional-arg"),
        force_ascii("unimportant"),
        false,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::try_from(&arguments_array[..])
        .expect("argument construction should have succeeded");

    let mut buffer = [0u8; 30];
    arguments
        .serialize_header(&mut buffer)
        .expect("header serialization should succeed");
    assert_eq!(buffer[..2], [1, 24]);

    arguments
        .serialize_body(&mut buffer)
        .expect("body serialization should succeed");
    assert_eq!(&buffer[..24], b"optional-arg*unimportant");
}
