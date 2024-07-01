use tinyvec::SliceVec;

use super::common::{
    Argument, Arguments, AuthenticationContext, AuthenticationType, ClientInformation,
    PrivilegeLevel, Service,
};
use super::*;
use crate::types::force_ascii;

#[test]
fn serialize_authentication_start_with_header() {
    let header = HeaderInfo {
        minor_version: MinorVersion::V1,
        sequence_number: 1,
        flags: HeaderFlags::SingleConnection,
        session_id: 123456,
    };

    let mut body = authentication::Start::new(
        authentication::Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(0).unwrap(),
            authentication_type: AuthenticationType::Pap,
            service: Service::Ppp,
        },
        ClientInformation::new("startup", force_ascii("49"), force_ascii("192.168.23.10")).unwrap(),
    );

    body.set_data("E".as_bytes()).unwrap();

    let packet = Packet::new(header, body).expect("packet construction should have succeeded");

    let mut buffer = [42; 100];
    packet
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should have been large enough for packet");

    assert_eq!(
        buffer[..43],
        [
            // HEADER
            (0xc << 4) | 0x1, // major/minor version (default)
            0x01,             // authentication
            1,                // sequence number
            0x04,             // single connection flag set
            // TODO: format :(
            0x0,
            0x1,
            0xe2,
            0x40, // session id
            0,
            0,
            0,
            31, // length
            // BODY
            0x01, // action: login
            0,    // privilege level 0
            0x02, // authentication type: PAP
            0x03, // authentication service: PPP
            7,    // user length
            2,    // port length
            13,   // remote address length
            1,    // data length
            // user
            0x73,
            0x74,
            0x61,
            0x72,
            0x74,
            0x75,
            0x70,
            // port
            0x34,
            0x39,
            // remote address
            0x31,
            0x39,
            0x32,
            0x2e,
            0x31,
            0x36,
            0x38,
            0x2e,
            0x32,
            0x33,
            0x2e,
            0x31,
            0x30,
            // data
            0x45
        ]
    );
}

#[test]
fn serialize_authentication_start_version_mismatch() {
    let header = HeaderInfo {
        minor_version: MinorVersion::V1,
        sequence_number: 3,
        flags: HeaderFlags::Unencrypted,
        session_id: 9128374,
    };

    let body = authentication::Start::new(
        authentication::Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(2).unwrap(),
            // ascii requires v0/default, but we set v1 above so this fails
            authentication_type: AuthenticationType::Ascii,
            service: Service::Login,
        },
        ClientInformation::new("bad", force_ascii("49"), force_ascii("::1")).unwrap(),
    );

    assert!(
        Packet::new(header, body).is_none(),
        "packet construction should have failed"
    );
}

#[test]
fn deserialize_authorization_reply_with_header() {
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
        [Argument::new(force_ascii("service"), force_ascii("nah"), true).unwrap()];

    let expected_header = HeaderInfo {
        minor_version: MinorVersion::Default,
        sequence_number: 4,
        flags: HeaderFlags::Unencrypted | HeaderFlags::SingleConnection,
        session_id: 92837492,
    };

    let expected_body = authorization::Reply {
        status: authorization::Status::Fail,
        server_message: force_ascii("something went wrong :("),
        data: b"\x88\x88\x88\x88",
        arguments: Arguments::try_from_slicevec(expected_arguments.as_mut_slice().into()).unwrap(),
    };

    let expected_packet = Packet::new(expected_header, expected_body).unwrap();

    let mut parsed_arguments_space: [Argument<'_>; 1] = Default::default();

    assert_eq!(
        expected_packet,
        Packet::<authorization::Reply>::deserialize_from_buffer(
            &raw_packet,
            SliceVec::try_from_slice_len(parsed_arguments_space.as_mut_slice(), 0).unwrap()
        )
        .expect("packet parsing should have succeeded")
    );
}
