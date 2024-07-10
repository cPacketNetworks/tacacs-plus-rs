use super::*;
use crate::AsciiStr;

#[test]
fn arguments_two_required() {
    let argument_array = [
        Argument::new(AsciiStr::assert("service"), AsciiStr::assert("test"), true)
            .expect("argument should be valid"),
        Argument::new(
            AsciiStr::assert("random-argument"),
            AsciiStr::assert(""),
            true,
        )
        .expect("argument should be valid"),
    ];

    let arguments = Arguments::new(&argument_array)
        .expect("argument array -> Arguments conversion should have worked");

    let mut buffer = [0u8; 40];

    // ensure header information is serialized correctly
    let header_serialized_len = arguments.serialize_count_and_lengths(&mut buffer);
    assert_eq!(buffer[..header_serialized_len], [2, 12, 16]);

    let body_serialized_len = arguments.serialize_encoded_values(&mut buffer);
    assert_eq!(
        &buffer[..body_serialized_len],
        b"service=testrandom-argument="
    );
}

#[test]
fn arguments_one_optional() {
    let arguments_array = [Argument::new(
        AsciiStr::assert("optional-arg"),
        AsciiStr::assert("unimportant"),
        false,
    )
    .expect("argument should be valid")];

    let arguments =
        Arguments::new(&arguments_array).expect("argument construction should have succeeded");

    let mut buffer = [0u8; 30];
    let header_serialized_len = arguments.serialize_count_and_lengths(&mut buffer);
    assert_eq!(buffer[..header_serialized_len], [1, 24]);

    let body_serialized_len = arguments.serialize_encoded_values(&mut buffer);
    assert_eq!(&buffer[..body_serialized_len], b"optional-arg*unimportant");
}
