use super::*;
use crate::ascii::assert_ascii;
use crate::protocol::{Argument, Arguments};

#[test]
fn invalid_privilege_level_none() {
    let level = PrivilegeLevel::of(42);
    assert!(level.is_none());
}

#[test]
fn client_information_long_username() {
    let username = [0x41u8; 512]; // AAA...AAA
    let client_information = UserInformation::new(
        core::str::from_utf8(&username).unwrap(),
        assert_ascii("tcp49"),
        assert_ascii("127.0.0.1"),
    );

    assert!(client_information.is_none(), "username should be too long");
}

#[test]
fn arguments_two_required() {
    let mut argument_array = [
        Argument::new(assert_ascii("service"), assert_ascii("test"), true)
            .expect("argument should be valid"),
        Argument::new(assert_ascii("random-argument"), assert_ascii(""), true)
            .expect("argument should be valid"),
    ];

    let arguments = Arguments::try_from_full_slice(argument_array.as_mut_slice())
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
    let mut arguments_array = [Argument::new(
        assert_ascii("optional-arg"),
        assert_ascii("unimportant"),
        false,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::try_from_full_slice(arguments_array.as_mut_slice())
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
