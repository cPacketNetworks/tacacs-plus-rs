use super::*;
use crate::FieldText;

#[test]
fn arguments_two_required() {
    let argument_array = [
        Argument::new(
            FieldText::assert("service"),
            FieldText::assert("test"),
            true,
        )
        .expect("argument should be valid"),
        Argument::new(
            FieldText::assert("random-argument"),
            FieldText::assert(""),
            true,
        )
        .expect("argument should be valid"),
    ];

    let arguments = Arguments::new(&argument_array)
        .expect("argument array -> Arguments conversion should have worked");

    let mut buffer = [0u8; 40];

    // ensure header information is serialized correctly
    let header_serialized_len = arguments
        .serialize_count_and_lengths(&mut buffer)
        .expect("buffer should be big enough for argument lengths");
    assert_eq!(buffer[..header_serialized_len], [2, 12, 16]);

    let body_serialized_len = arguments
        .serialize_encoded_values(&mut buffer)
        .expect("buffer should be large enough for argument values");
    assert_eq!(
        &buffer[..body_serialized_len],
        b"service=testrandom-argument="
    );
}

#[test]
fn arguments_one_optional() {
    let arguments_array = [Argument::new(
        FieldText::assert("optional-arg"),
        FieldText::assert("unimportant"),
        false,
    )
    .expect("argument should be valid")];

    let arguments =
        Arguments::new(&arguments_array).expect("argument construction should have succeeded");

    let mut buffer = [0u8; 30];
    let header_serialized_len = arguments
        .serialize_count_and_lengths(&mut buffer)
        .expect("buffer should be large enough to hold argument lengths");
    assert_eq!(buffer[..header_serialized_len], [1, 24]);

    let body_serialized_len = arguments
        .serialize_encoded_values(&mut buffer)
        .expect("buffer should be large enough for argument values");
    assert_eq!(&buffer[..body_serialized_len], b"optional-arg*unimportant");
}

#[test]
fn construct_and_serialize_valid_optional_argument() {
    let argument = Argument::new(
        FieldText::assert("valid name with other symbols: !@#$%^&()"),
        FieldText::assert("ASCII-value (with space)"),
        false,
    )
    .expect("argument should be valid");
    let argument_len = argument.encoded_length() as usize;

    let mut buffer = [0xffu8; 70];
    argument
        .serialize(&mut buffer)
        .expect("argument serialization should succeed");

    assert_eq!(
        &buffer[..argument_len],
        b"valid name with other symbols: !@#$%^&()*ASCII-value (with space)"
    );
}

#[test]
fn argument_name_contains_equals_delimiter() {
    assert_eq!(
        Argument::new(
            FieldText::assert("= <-- shouldn't be there"),
            FieldText::assert("value doesn't matter"),
            true,
        ),
        Err(InvalidArgument::NameContainsDelimiter)
    );
}

#[test]
fn argument_name_contains_star_delimiter() {
    assert_eq!(
        Argument::new(
            FieldText::assert("what even is this: *"),
            FieldText::assert("no one will see this"),
            false,
        ),
        Err(InvalidArgument::NameContainsDelimiter)
    );
}

#[test]
fn argument_total_length_too_big() {
    let long_value = [b'?'; 256];

    assert_eq!(
        Argument::new(
            FieldText::assert("that's some name you've got"),
            long_value.as_slice().try_into().unwrap(),
            true
        ),
        Err(InvalidArgument::TooLong)
    );
}

#[test]
fn deserialize_empty_string() {
    assert_eq!(
        Argument::deserialize(b""),
        Err(InvalidArgument::NoDelimiter)
    );
}

#[test]
fn deserialize_just_delimiter() {
    assert_eq!(Argument::deserialize(b"="), Err(InvalidArgument::EmptyName));
}

#[test]
fn deserialize_both_delims_equals_first() {
    assert_eq!(
        Argument::deserialize(b"name=1*2"),
        Ok(Argument {
            name: FieldText::assert("name"),
            value: FieldText::assert("1*2"),
            required: true
        })
    );
}

#[test]
fn deserialize_both_delims_star_first() {
    assert_eq!(
        Argument::deserialize(b"optional*and=stuff"),
        Ok(Argument {
            name: FieldText::assert("optional"),
            value: FieldText::assert("and=stuff"),
            required: false
        })
    );
}

#[cfg(feature = "std")]
#[test]
fn argument_to_owned_impl() {
    use std::string::String;

    let argument_unowned =
        Argument::new(FieldText::assert("name"), FieldText::assert("value"), true)
            .expect("argument should have been valid");

    assert_eq!(
        argument_unowned.to_owned(),
        ArgumentOwned {
            name: String::from("name"),
            value: String::from("value"),
            required: true
        }
    );
}
