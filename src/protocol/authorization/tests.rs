use super::*;
use crate::ascii::assert_ascii;
use crate::protocol::{
    AuthenticationContext, AuthenticationMethod, AuthenticationService, AuthenticationType,
    HeaderInfo, MajorVersion, MinorVersion, Packet, PacketFlags, PrivilegeLevel, Serialize,
    UserInformation, Version,
};

#[test]
fn serialize_request_no_arguments() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::of(1).unwrap(),
        authentication_type: AuthenticationType::Ascii,
        service: AuthenticationService::Enable,
    };

    let user_information =
        UserInformation::new("testuser", assert_ascii("tcp49"), assert_ascii("127.0.0.1"))
            .expect("client information should have been valid");

    let mut empty_arguments = [];

    let request = Request {
        method: AuthenticationMethod::Enable,
        authentication_context,
        user_information,
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
fn serialize_request_one_argument() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::of(15).expect("15 should be a valid privilege level"),
        authentication_type: AuthenticationType::MsChapV2,
        service: AuthenticationService::FwProxy,
    };

    let user_information = UserInformation::new(
        "testuser",
        assert_ascii("ttyAMA0"),
        assert_ascii("127.1.2.2"),
    )
    .expect("client information should have been valid");

    let mut argument_array = [Argument::new(
        assert_ascii("service"),
        assert_ascii("serialization-test"),
        true,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::try_from_full_slice(argument_array.as_mut_slice())
        .expect("single argument array should be valid");

    let request = Request {
        method: AuthenticationMethod::TacacsPlus,
        authentication_context,
        user_information,
        arguments,
    };

    let mut buffer = [0u8; 60];
    let serialized_length = request
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be large enough");

    assert_eq!(
        buffer[..serialized_length],
        [
            0x06, // authentication method: TACACS+
            15,   // privilege level
            0x06, // authentication type: MSCHAPv2
            0x09, // authentication service: firewall proxy
            8,    // user length
            7,    // port length
            9,    // remote address length
            1,    // one argument
            26,   // argument 1 length
            0x74, 0x65, 0x73, 0x74, 0x75, 0x73, 0x65, 0x72, // user: testuser
            0x74, 0x74, 0x79, 0x41, 0x4d, 0x41, 0x30, // port: ttyAMA0
            0x31, 0x32, 0x37, 0x2e, 0x31, 0x2e, 0x32, 0x2e, 0x32, // remote address
            // service argument key-value pair
            0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3d, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c,
            0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x74, 0x65, 0x73, 0x74
        ]
    );
}

#[test]
fn serialize_full_request_packet() {
    let header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::Default),
        sequence_number: 1,
        flags: PacketFlags::Unencrypted,
        session_id: 578263403,
    };

    let mut arguments =
        [Argument::new(assert_ascii("service"), assert_ascii("fulltest"), true).unwrap()];

    let body = Request {
        method: AuthenticationMethod::Kerberos5,
        authentication_context: AuthenticationContext {
            privilege_level: PrivilegeLevel::of(14).unwrap(),
            authentication_type: AuthenticationType::NotSet,
            service: AuthenticationService::Enable,
        },
        user_information: UserInformation::new(
            "requestor",
            assert_ascii("tcp23"),
            assert_ascii("127.254.1.2"),
        )
        .unwrap(),
        arguments: Arguments::try_from_full_slice(arguments.as_mut_slice()).unwrap(),
    };

    let packet = Packet::new(header, body).expect("packet construction should have succeeded");

    let mut buffer = [0x43; 70];
    let serialized_length = packet
        .serialize_into_buffer(buffer.as_mut_slice())
        .expect("packet serialization should have succeeded");

    assert_eq!(
        buffer[..serialized_length],
        [
            // HEADER
            0xc << 4, // version
            2,        // authorization packet
            1,        // sequence number
            1,        // unencrypted flag set
            // session id
            0x22,
            0x77,
            0x99,
            0x6b,
            // body length
            0,
            0,
            0,
            50,
            // BODY
            2,  // authentication method: Kerberos 5
            14, // privilege level
            0,  // authentication type: not set
            2,  // authentication service: enable
            9,  // user length
            5,  // port length
            11, // remote address length
            1,  // argument count
            16, // argument 1 length
            // user
            0x72,
            0x65,
            0x71,
            0x75,
            0x65,
            0x73,
            0x74,
            0x6f,
            0x72,
            // port
            0x74,
            0x63,
            0x70,
            0x32,
            0x33,
            // remote address
            0x31,
            0x32,
            0x37,
            0x2e,
            0x32,
            0x35,
            0x34,
            0x2e,
            0x31,
            0x2e,
            0x32,
            // argument 1: service
            0x73,
            0x65,
            0x72,
            0x76,
            0x69,
            0x63,
            0x65,
            0x3d,
            0x66,
            0x75,
            0x6c,
            0x6c,
            0x74,
            0x65,
            0x73,
            0x74
        ]
    );
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
        Argument::new(assert_ascii("service"), assert_ascii("greet"), true).unwrap(),
        Argument::new(assert_ascii("person"), assert_ascii("world!"), false).unwrap(),
    ];

    let expected = Reply {
        status: Status::PassAdd,
        server_message: assert_ascii("hello"),
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

#[test]
fn deserialize_full_reply_packet() {
    let raw_packet = [
        0xc << 4,    // major/minor version
        0x2,         // type: authorization
        4,           // sequence number
        0x01 | 0x04, // both flags set
        // session id
        0x5,
        0x88,
        0x96,
        0x74,
        // body length
        0,
        0,
        0,
        45,
        // BODY
        0x10, // status: fail
        1,    // argument count
        // server message length
        0,
        23,
        // data length
        0,
        4,
        // argument length
        11,
        // server message
        0x73,
        0x6f,
        0x6d,
        0x65,
        0x74,
        0x68,
        0x69,
        0x6e,
        0x67,
        0x20,
        0x77,
        0x65,
        0x6e,
        0x74,
        0x20,
        0x77,
        0x72,
        0x6f,
        0x6e,
        0x67,
        0x20,
        0x3a,
        0x28,
        // data
        0x88,
        0x88,
        0x88,
        0x88,
        // argument 1
        0x73,
        0x65,
        0x72,
        0x76,
        0x69,
        0x63,
        0x65,
        0x3d,
        0x6e,
        0x61,
        0x68,
    ];

    let mut expected_arguments =
        [Argument::new(assert_ascii("service"), assert_ascii("nah"), true).unwrap()];

    let expected_header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::Default),
        sequence_number: 4,
        flags: PacketFlags::Unencrypted | PacketFlags::SingleConnection,
        session_id: 92837492,
    };

    let expected_body = Reply {
        status: Status::Fail,
        server_message: assert_ascii("something went wrong :("),
        data: b"\x88\x88\x88\x88",
        arguments: Arguments::try_from_full_slice(expected_arguments.as_mut_slice()).unwrap(),
    };

    let expected_packet = Packet::new(expected_header, expected_body).unwrap();

    let mut parsed_arguments_space: [Argument<'_>; 1] = Default::default();

    assert_eq!(
        expected_packet,
        Packet::<Reply>::deserialize_from_buffer(
            &raw_packet,
            parsed_arguments_space.as_mut_slice()
        )
        .expect("packet parsing should have succeeded")
    );
}
