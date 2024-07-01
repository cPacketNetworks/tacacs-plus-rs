use super::*;
use crate::types::force_ascii;

#[test]
fn invalid_privilege_level_none() {
    let level = PrivilegeLevel::of(42);
    assert!(level.is_none());
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
    let mut argument_array = [
        Argument::new(force_ascii("service"), force_ascii("test"), true)
            .expect("argument should be valid"),
        Argument::new(force_ascii("random-argument"), force_ascii(""), true)
            .expect("argument should be valid"),
    ];

    let arguments = Arguments::try_from_slicevec(argument_array.as_mut_slice().into())
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
        force_ascii("optional-arg"),
        force_ascii("unimportant"),
        false,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::try_from_slicevec(arguments_array.as_mut_slice().into())
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
