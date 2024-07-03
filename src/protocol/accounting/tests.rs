use super::*;
use crate::ascii::assert_ascii;
use crate::protocol::{
    Argument, AuthenticationContext, AuthenticationMethod, AuthenticationService,
    AuthenticationType, HeaderFlags, HeaderInfo, MajorVersion, MinorVersion, Packet,
    PrivilegeLevel, UserInformation, Version,
};

#[test]
fn serialize_request_body_with_argument() {
    let mut argument_array =
        [
            Argument::new(assert_ascii("service"), assert_ascii("tacacs-test"), true)
                .expect("argument should be valid"),
        ];

    let arguments = Arguments::try_from_full_slice(argument_array.as_mut_slice())
        .expect("argument array should be valid");

    let request = Request {
        flags: Flags::StartRecord,
        authentication_method: AuthenticationMethod::Guest,
        authentication: AuthenticationContext {
            privilege_level: PrivilegeLevel::of(0).unwrap(),
            authentication_type: AuthenticationType::Ascii,
            service: AuthenticationService::Login,
        },
        user_information: UserInformation::new(
            "guest",
            assert_ascii("tty0"),
            assert_ascii("127.10.0.100"),
        )
        .unwrap(),
        arguments,
    };

    let mut buffer = [0u8; 50];
    request
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should have been large enough");

    assert_eq!(
        buffer,
        [
            0x02, // just start flag set
            0x08, // Guest authentication method
            0,    // privilege level 0 (minimum)
            0x01, // ASCII authentication type
            0x01, // authentication service: login
            5,    // user length
            4,    // port length
            12,   // remote address length
            1,    // argument count
            19,   // argument 1 length
            0x67, 0x75, 0x65, 0x73, 0x74, // user: guest
            0x74, 0x74, 0x79, 0x30, // port: tty0
            // remote address: 127.10.0.100
            0x31, 0x32, 0x37, 0x2e, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x30, 0x30,
            // required argument: service=tacacs-test
            0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3d, 0x74, 0x61, 0x63, 0x61, 0x63, 0x73,
            0x2d, 0x74, 0x65, 0x73, 0x74
        ]
    );
}

#[test]
fn serialize_full_request_packet() {
    let mut arguments = [
        Argument::new(assert_ascii("task_id"), assert_ascii("1234"), true).unwrap(),
        Argument::new(assert_ascii("service"), assert_ascii("fullpacket"), true).unwrap(),
    ];

    let body = Request {
        flags: Flags::WatchdogNoUpdate,
        authentication_method: AuthenticationMethod::NotSet,
        authentication: AuthenticationContext {
            privilege_level: PrivilegeLevel::of(10).unwrap(),
            authentication_type: AuthenticationType::NotSet,
            service: AuthenticationService::Pt,
        },
        user_information: UserInformation::new(
            "secret",
            assert_ascii("tty6"),
            assert_ascii("10.10.10.10"),
        )
        .unwrap(),
        arguments: Arguments::try_from_full_slice(arguments.as_mut_slice()).unwrap(),
    };

    let header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::V1),
        sequence_number: 1,
        flags: HeaderFlags::empty(),
        session_id: 298734923,
    };

    let packet = Packet::new(header, body).expect("packet construction should have succeeded");

    let mut buffer = [0xff; 100];
    let packet_size = packet
        .serialize_into_buffer(buffer.as_mut_slice())
        .expect("packet serialization failed");

    assert_eq!(
        buffer[..packet_size],
        [
            // HEADER
            (0xc << 4) | 0x1, // version
            0x3,              // accounting packet
            1,                // sequence number
            0,                // no flags set
            // session id
            0x11,
            0xce,
            0x55,
            0x4b,
            // length
            0,
            0,
            0,
            62,
            // BODY
            0x08, // watchdog flag set (no update)
            0x00, // authentication method: not set
            10,   // privilege level
            0x00, // authentication type: not set
            0x05, // authentication service: PT
            6,    // user length
            4,    // port length
            11,   // remote address length
            2,    // argument count
            12,   // argument 1 length
            18,   // argument 2 length
            // user
            0x73,
            0x65,
            0x63,
            0x72,
            0x65,
            0x74,
            // port
            0x74,
            0x74,
            0x79,
            0x36,
            // remote address
            0x31,
            0x30,
            0x2e,
            0x31,
            0x30,
            0x2e,
            0x31,
            0x30,
            0x2e,
            0x31,
            0x30,
            // argument 1 (task_id)
            0x74,
            0x61,
            0x73,
            0x6b,
            0x5f,
            0x69,
            0x64,
            0x3d,
            0x31,
            0x32,
            0x33,
            0x34,
            // argument 2 (service)
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
            0x70,
            0x61,
            0x63,
            0x6b,
            0x65,
            0x74
        ]
    );
}

#[test]
fn deserialize_reply_all_fields() {
    let body_raw = [
        0, 47, // server message length
        0, 2,    // data length,
        0x02, // status: error
        // server message
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, // end server message
        // data
        0xa4, 0x42,
    ];

    assert_eq!(
        Reply {
            status: Status::Error,
            server_message: AsciiStr::try_from_bytes([b'A'; 47].as_slice()).unwrap(),
            data: &[0xa4, 0x42]
        },
        body_raw.as_slice().try_into().unwrap()
    );
}
