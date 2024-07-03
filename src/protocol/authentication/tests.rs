use super::*;
use crate::ascii::assert_ascii;
use crate::protocol::{
    AuthenticationContext, AuthenticationService, AuthenticationType, HeaderInfo, MajorVersion,
    MinorVersion, Packet, PacketFlags, PrivilegeLevel, UserInformation, Version,
};

#[test]
fn serialize_start_no_data() {
    let start_body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(3).expect("privilege level 3 should be valid"),
            authentication_type: AuthenticationType::Pap,
            service: AuthenticationService::Ppp,
        },
        UserInformation::new("authtest", assert_ascii("serial"), assert_ascii("serial"))
            .expect("user information should be valid"),
        None,
    )
    .expect("start construction should have succeeded");

    let mut buffer = [0xffu8; 28];
    start_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be large enough to accommodate start packet");

    assert_eq!(
        buffer,
        [
            0x01, // action: login
            3,    // privilege level
            0x02, // authentication type: PAP
            0x03, // authentication service: PPP
            8,    // user length
            6,    // port length
            6,    // remote address length
            0,    // data length (0 since there's no data)
            0x61, 0x75, 0x74, 0x68, 0x74, 0x65, 0x73, 0x74, // user: authtest
            0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, // port: serial
            0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, // remote address: serial
        ]
    );
}

#[test]
fn serialize_start_with_data() {
    let start_body = Start::new(
        Action::ChangePassword,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(4).expect("privilege level 4 should be valid"),
            authentication_type: AuthenticationType::MsChap,
            service: AuthenticationService::X25,
        },
        UserInformation::new("authtest2", assert_ascii("49"), assert_ascii("10.0.2.24"))
            .expect("user information should be valid"),
        Some("some test data with ✨ unicode ✨".as_bytes()),
    )
    .expect("start construction should have succeeded");

    let mut buffer = [0xff; 80];
    let serialized_length = start_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be long enough");

    assert_eq!(
        buffer[..serialized_length],
        [
            0x02, // action: change password
            4,    // privilege level
            0x05, // authentication type: MSCHAP
            0x07, // authentication service: X25
            9,    // user length
            2,    // port length
            9,    // remote address length
            35,   // data length
            0x61, 0x75, 0x74, 0x68, 0x74, 0x65, 0x73, 0x74, 0x32, // user: authtest2
            0x34, 0x39, // port: 49
            0x31, 0x30, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x32, 0x34, // remote address
            // supplied data (UTF-8 encoded, as a proxy for arbitrary binary data)
            0x73, 0x6f, 0x6d, 0x65, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61, 0x74, 0x61,
            0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0xe2, 0x9c, 0xa8, 0x20, 0x75, 0x6e, 0x69, 0x63,
            0x6f, 0x64, 0x65, 0x20, 0xe2, 0x9c, 0xa8
        ]
    );
}

#[test]
fn serialize_start_data_too_long() {
    let long_data = [0x2a; 256];
    let start_body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(5).expect("privilege level 5 should be valid"),
            authentication_type: AuthenticationType::Ascii,
            service: AuthenticationService::Nasi,
        },
        UserInformation::new(
            "invalid",
            assert_ascii("theport"),
            assert_ascii("somewhere"),
        )
        .expect("user information should be valid"),
        Some(&long_data),
    );

    assert!(
        start_body.is_none(),
        "data should have been too long to construct start"
    );
}

#[test]
fn serialize_full_start_packet() {
    let header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::V1),
        sequence_number: 1,
        flags: PacketFlags::SingleConnection,
        session_id: 123456,
    };

    let body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(0).unwrap(),
            authentication_type: AuthenticationType::Pap,
            service: AuthenticationService::Ppp,
        },
        UserInformation::new("startup", assert_ascii("49"), assert_ascii("192.168.23.10")).unwrap(),
        Some(b"E"),
    )
    .expect("start construction should have succeeded");

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
            // session ID
            0x0,
            0x1,
            0xe2,
            0x40,
            // length
            0,
            0,
            0,
            31,
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
fn serialize_full_start_packet_version_mismatch() {
    let header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::V1),
        sequence_number: 3,
        flags: PacketFlags::Unencrypted,
        session_id: 9128374,
    };

    let body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(2).unwrap(),
            // ascii requires v0/default, but we set v1 above so this fails
            authentication_type: AuthenticationType::Ascii,
            service: AuthenticationService::Login,
        },
        UserInformation::new("bad", assert_ascii("49"), assert_ascii("::1")).unwrap(),
        None,
    )
    .expect("packet construction should have succeeded");

    assert!(
        Packet::new(header, body).is_none(),
        "packet construction should have failed"
    );
}

#[test]
fn deserialize_reply_pass_both_data_fields() {
    let packet_data = [
        0x01, // status: pass
        0,    // no flags set
        0, 16, // server message length
        0, 4, // data length
        // server message: "login successful" (without quotes)
        0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66, 0x75,
        0x6c, // end server message
        0x12, 0x77, 0xfa, 0xcc, // data: some random bytes for good measure
        0xde, // extra byte for good measure; should still be valid
    ];

    let parsed_reply =
        Reply::try_from(packet_data.as_slice()).expect("reply packet should be valid");

    assert_eq!(
        parsed_reply,
        Reply {
            status: Status::Pass,
            server_message: assert_ascii("login successful"),
            data: b"\x12\x77\xfa\xcc",
            no_echo: false
        }
    );
}

#[test]
fn deserialize_reply_bad_server_message_length() {
    let packet_data = [
        0x02, // status: fail
        0,    // no flags set
        13, 37, // way too large server length
        0, 0, // data length shouldn't matter
        // server message: "something's wrong"
        0x73, 0x6f, 0x6d, 0x65, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x27, 0x73, 0x20, 0x77, 0x72, 0x6f,
        0x6e, 0x67,
    ];

    // guard on specific error flavor
    assert_eq!(
        Reply::try_from(packet_data.as_slice()),
        Err(DeserializeError::UnexpectedEnd)
    );
}

#[test]
fn deserialize_reply_shorter_than_header() {
    let packet_data = [
        0x03, // status: getdata
        1,    // noecho flag set
        0, 0, // server message length (not there)
        0, // oops lost a byte!
    ];

    Reply::try_from(packet_data.as_slice())
        .expect_err("header shouldn't be long enough to be valid");
}

#[test]
fn deserialize_reply_bad_status() {
    let packet_data = [
        42, // invalid status
        0,  // no flags set
        0, 1, // server message length
        0, 0,    // data length
        0x41, // server message: "a"
    ];

    assert_eq!(
        Reply::try_from(packet_data.as_slice()),
        Err(DeserializeError::InvalidWireBytes)
    );
}

#[test]
fn deserialize_reply_bad_flags() {
    let packet_data = [
        0x07, // status: error
        2,    // invalid flags value: (should just be 0 or 1)
        0, 0, // server message length
        0, 1,    // data length
        b'*', // data
    ];

    assert_eq!(
        Reply::try_from(packet_data.as_slice()),
        Err(DeserializeError::InvalidWireBytes)
    );
}

#[test]
fn deserialize_reply_full_packet() {
    let raw_packet = [
        // HEADER
        (0xc << 4) | 1, // version
        1,              // authentication packet
        4,              // sequence number
        1,              // unencrypted flag set
        // session id
        0x3a,
        0x9b,
        0x95,
        0xb1,
        // packet body length
        0,
        0,
        0,
        22,
        // BODY
        6, // status: restart
        0, // no flags set
        // server message length
        0,
        9,
        // data length
        0,
        7,
        // server message
        0x74,
        0x72,
        0x79,
        0x20,
        0x61,
        0x67,
        0x61,
        0x69,
        0x6e,
        // data
        1,
        1,
        2,
        3,
        5,
        8,
        13,
    ];

    let expected_header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::V1),
        sequence_number: 4,
        flags: PacketFlags::Unencrypted,
        session_id: 983274929,
    };

    let expected_body = Reply {
        status: Status::Restart,
        server_message: assert_ascii("try again"),
        data: &[1, 1, 2, 3, 5, 8, 13],
        no_echo: false,
    };

    let expected_packet = Packet::new(expected_header, expected_body)
        .expect("packet construction should have succeeded");

    assert_eq!(raw_packet.as_slice().try_into(), Ok(expected_packet));
}

#[test]
fn deserialize_reply_type_mismatch() {
    let raw_packet = [
        // HEADER
        0xc << 4, // version
        2,        // authorization packet!
        2,        // sequence number
        0,        // no flags set
        // session id
        0xf7,
        0x23,
        0x98,
        0x93,
        // body length
        0,
        0,
        0,
        6,
        // BODY
        1, // status: pass
        0, // no flags set
        // server message length
        0,
        0,
        // data length
        0,
        0,
    ];

    assert_eq!(
        Packet::<Reply>::try_from(raw_packet.as_slice()),
        Err(DeserializeError::InvalidWireBytes)
    );
}

#[test]
fn serialize_continue_no_data() {
    let continue_body =
        Continue::new(None, None, false).expect("continue construction should have succeeded");

    let mut buffer = [0xff; 5];
    continue_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be large enough");

    assert_eq!(
        buffer,
        [
            0, 0, // user message length
            0, 0, // data length
            0  // flags (abort not set)
        ]
    );
}

#[test]
fn serialize_continue_both_valid_data_fields() {
    let user_message = b"secure-password";
    let user_message_length = user_message.len();
    let data = b"\x12\x34\x45\x78";
    let data_length = data.len();

    let continue_body = Continue::new(Some(user_message), Some(data), true)
        .expect("continue construction should have succeeded");

    let mut buffer = [0xff; 30];
    continue_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be big enough");

    // field lengths
    assert_eq!(buffer[..2], (user_message_length as u16).to_be_bytes());
    assert_eq!(buffer[2..4], (data_length as u16).to_be_bytes());

    // abort flag (set)
    assert_eq!(buffer[4], 1);

    // data/message fields
    assert_eq!(&buffer[5..5 + user_message_length], user_message);
    assert_eq!(
        &buffer[5 + user_message_length..5 + user_message_length + data_length],
        data
    );
}

#[test]
fn serialize_continue_only_data_field() {
    let data = b"textand\x2abinary\x11";
    let data_length = data.len();

    let continue_body = Continue::new(None, Some(data), false)
        .expect("continue construction should have succeeded");

    let mut buffer = [0xff; 40];
    continue_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be large enough");

    // user message length
    assert_eq!(buffer[..2], [0, 0]);

    // data length
    assert_eq!(buffer[2..4], 15_u16.to_be_bytes());

    // abort flag (unset)
    assert_eq!(buffer[4], 0);

    // actual data
    assert_eq!(&buffer[5..5 + data_length], data);
}

#[test]
fn serialize_continue_full_packet() {
    let header = HeaderInfo {
        version: Version::of(MajorVersion::TheOnlyVersion, MinorVersion::Default),
        sequence_number: 49,
        flags: PacketFlags::SingleConnection,
        session_id: 856473784,
    };

    let body = Continue::new(
        Some(b"this is a message"),
        Some(&[64, 43, 2, 255, 2]),
        false,
    )
    .expect("continue construction should have worked");

    let packet = Packet::new(header, body).expect("packet construction should have worked");

    let mut buffer = [0x64; 50];
    let serialized_length = packet
        .serialize_into_buffer(buffer.as_mut_slice())
        .expect("packet serialization should succeed");

    assert_eq!(
        buffer[..serialized_length],
        [
            // HEADER
            0xc << 4, // version
            1,        // authentication packet
            49,       // sequence number
            4,        // single connection flag set
            // session id
            0x33,
            0xc,
            0xc0,
            0xb8,
            // body length
            0,
            0,
            0,
            27,
            // BODY
            // user message length
            0,
            17,
            // data length
            0,
            5,
            // abort flag unset
            0,
            // user message
            0x74,
            0x68,
            0x69,
            0x73,
            0x20,
            0x69,
            0x73,
            0x20,
            0x61,
            0x20,
            0x6d,
            0x65,
            0x73,
            0x73,
            0x61,
            0x67,
            0x65,
            // data
            64,
            43,
            2,
            255,
            2
        ]
    );
}
