use super::*;
use crate::AsciiStr;

#[test]
fn arguments_two_required() {
    let mut argument_array = [
        Argument::new(AsciiStr::assert("service"), AsciiStr::assert("test"), true)
            .expect("argument should be valid"),
        Argument::new(
            AsciiStr::assert("random-argument"),
            AsciiStr::assert(""),
            true,
        )
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
        AsciiStr::assert("optional-arg"),
        AsciiStr::assert("unimportant"),
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
