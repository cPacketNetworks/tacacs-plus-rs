use tinyvec::SliceVec;

use super::*;
use crate::protocol::{
    common::{
        AuthenticationContext, AuthenticationMethod, AuthenticationType, ClientInformation,
        PrivilegeLevel, Service,
    },
    Serialize,
};
use crate::types::force_ascii;

#[test]
fn serialize_request_no_arguments() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::of(1).unwrap(),
        authentication_type: AuthenticationType::Ascii,
        service: Service::Enable,
    };

    let client_information =
        ClientInformation::new("testuser", force_ascii("tcp49"), force_ascii("127.0.0.1"))
            .expect("client information should have been valid");

    let mut empty_arguments = [];

    let request = Request {
        method: AuthenticationMethod::Enable,
        authentication_context,
        client_information,
        arguments: Arguments::try_from_full_slice(empty_arguments.as_mut_slice())
            .expect("empty argument list should be valid"),
    };

    let mut buffer = [0u8; 40];
    request
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should have been big enough");

    assert_eq!(
        buffer[..30],
        [
            0x04, // authentication method: enable
            1,    // privilege level: 1
            0x01, // authentication type: ASCII
            0x02, // authentication service: enable
            8,    // user length
            5,    // port length
            9,    // remote address length
            0,    // argument count (no arguments supplied)
            0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72, // user: testuser
            0x74, 0x63, 0x70, 0x34, 0x39, // port: tcp49
            0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31 // remote address: 127.0.0.1
        ]
    );
}

#[test]
fn serialize_authorization_request_one_argument() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::of(15).expect("15 should be a valid privilege level"),
        authentication_type: AuthenticationType::MsChapV2,
        service: Service::FwProxy,
    };

    let client_information =
        ClientInformation::new("testuser", force_ascii("ttyAMA0"), force_ascii("127.1.2.2"))
            .expect("client information should have been valid");

    let mut argument_array = [Argument::new(
        force_ascii("service"),
        force_ascii("serialization-test"),
        true,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::try_from_full_slice(argument_array.as_mut_slice())
        .expect("single argument array should be valid");

    let request = Request {
        method: AuthenticationMethod::TacacsPlus,
        authentication_context,
        client_information,
        arguments,
    };

    let mut buffer = [0u8; 60];
    request
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be large enough");

    assert!(buffer.starts_with(&[
        0x06, // authentication method: TACACS+
        15,   // privilege level
        0x06, // authentication type: MSChapV2
        0x09, // authentication service: FWPROXY
        8,    // user length
        7,    // port length
        9,    // remote address length
        1,    // one argument
        26,   // argument 1 length
        0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72, // user: testuser
        0x74, 0x74, 0x79, 0x41, 0x4d, 0x41, 0x30, // port: ttyAMA0
        0x31, 0x32, 0x37, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x32, // remote address
        // service argument key-value pair
        0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3d, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x69,
        0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x74, 0x65, 0x73, 0x74
    ]));
}

#[test]
fn deserialize_reply_two_arguments() {
    let raw_bytes = [
        0x01, // status: add
        2,    // two arguments
        0, 5, // server message length
        0, 5,  // data length
        13, // argument 1 length
        13, // argument 2 length
        0x68, 0x65, 0x6c, 0x6c, 0x6f, // server message
        0x77, 0x6f, 0x72, 0x6c, 0x64, // data
        // argument 1
        0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3d, 0x67, 0x72, 0x65, 0x65, 0x74,
        // argument 2
        0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x2a, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
    ];

    let mut expected_arguments = [
        Argument::new(force_ascii("service"), force_ascii("greet"), true).unwrap(),
        Argument::new(force_ascii("person"), force_ascii("world!"), false).unwrap(),
    ];

    let expected = Reply {
        status: Status::PassAdd,
        server_message: force_ascii("hello"),
        data: b"world",
        arguments: Arguments::try_from_full_slice(expected_arguments.as_mut_slice())
            .expect("argument construction shouldn't have failed"),
    };

    let mut parsed_argument_space: [Argument; 2] = Default::default();

    assert_eq!(
        expected,
        Reply::deserialize_from_buffer(&raw_bytes, parsed_argument_space.as_mut_slice()).unwrap()
    );
}
