use super::*;
use crate::protocol::{
    AuthenticationContext, AuthenticationService, AuthenticationType, HeaderInfo, MajorVersion,
    MinorVersion, Packet, PacketFlags, PrivilegeLevel, UserInformation, Version,
};
use crate::FieldText;

use tinyvec::array_vec;

#[test]
fn serialize_start_no_data() {
    let start_body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::new(3).expect("privilege level 3 should be valid"),
            authentication_type: AuthenticationType::Pap,
            service: AuthenticationService::Ppp,
        },
        UserInformation::new(
            "authtest",
            FieldText::assert("serial"),
            FieldText::assert("serial"),
        )
        .expect("user information should be valid"),
        None,
    )
    .expect("start construction should have succeeded");

    let mut buffer = [0xffu8; 28];
    start_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be large enough to accommodate start packet");

    let mut expected = array_vec!([u8; 30]);
    expected.extend_from_slice(&[
        0x01, // action: login
        3,    // privilege level
        0x02, // authentication type: PAP
        0x03, // authentication service: PPP
        8,    // user length
        6,    // port length
        6,    // remote address length
        0,    // data length (0 since there's no data)
    ]);

    // user information
    expected.extend_from_slice(b"authtest");
    expected.extend_from_slice(b"serial"); // port
    expected.extend_from_slice(b"serial"); // remote address

    assert_eq!(buffer, expected.as_slice());
}

#[test]
fn serialize_start_with_data() {
    let start_body = Start::new(
        #[allow(deprecated)]
        Action::SendAuth,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::new(4).expect("privilege level 4 should be valid"),
            authentication_type: AuthenticationType::MsChap,
            service: AuthenticationService::X25,
        },
        UserInformation::new(
            "authtest2",
            FieldText::assert("49"),
            FieldText::assert("10.0.2.24"),
        )
        .expect("user information should be valid"),
        Some("some test data with ✨ unicode ✨".as_bytes()),
    )
    .expect("start construction should have succeeded");

    let mut buffer = [0xff; 80];
    let serialized_length = start_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be long enough");

    let mut expected = array_vec!([u8; 80]);
    expected.extend_from_slice(&[
        0x04, // action: sendauth
        4,    // privilege level
        0x05, // authentication type: MSCHAP
        0x07, // authentication service: X25
        9,    // user length
        2,    // port length
        9,    // remote address length
        35,   // data length
    ]);

    // user information
    expected.extend_from_slice(b"authtest2");
    expected.extend_from_slice(b"49");
    expected.extend_from_slice(b"10.0.2.24");

    // data (with some unicode, as proxy for arbitrary binary data)
    expected.extend_from_slice("some test data with ✨ unicode ✨".as_bytes());

    assert_eq!(&buffer[..serialized_length], expected.as_slice());
}

#[test]
fn serialize_start_data_too_long() {
    let long_data = [0x2a; 256];
    let start_body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::new(5).expect("privilege level 5 should be valid"),
            authentication_type: AuthenticationType::Ascii,
            service: AuthenticationService::Nasi,
        },
        UserInformation::new(
            "invalid",
            FieldText::assert("theport"),
            FieldText::assert("somewhere"),
        )
        .expect("user information should be valid"),
        Some(&long_data),
    );

    assert_eq!(start_body, Err(BadStart::DataTooLong),);
}

#[test]
fn serialize_full_start_packet() {
    let session_id = 123457;
    let header = HeaderInfo {
        // note that minor version 1 is required for PAP
        version: Version(MajorVersion::RFC8907, MinorVersion::V1),
        sequence_number: 1,
        flags: PacketFlags::SINGLE_CONNECTION,
        session_id,
    };

    let body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::new(0).unwrap(),
            authentication_type: AuthenticationType::Pap,
            service: AuthenticationService::Ppp,
        },
        UserInformation::new(
            "startup",
            FieldText::assert("49"),
            FieldText::assert("192.168.23.10"),
        )
        .unwrap(),
        Some(b"E"),
    )
    .expect("start construction should have succeeded");

    let packet = Packet::new(header, body);

    let mut buffer = [42; 50];
    packet
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should have been large enough for packet");

    let mut expected = array_vec!([u8; 50]);

    // HEADER
    expected.extend_from_slice(&[
        (0xc << 4) | 0x1, // major/minor version (default)
        0x01,             // authentication
        1,                // sequence number
        0x04,             // single connection flag set
    ]);
    expected.extend_from_slice(session_id.to_be_bytes().as_slice());
    expected.extend_from_slice(31_u32.to_be_bytes().as_slice()); // body length

    // BODY
    expected.extend_from_slice(&[
        0x01, // action: login
        0,    // privilege level 0
        0x02, // authentication type: PAP
        0x03, // authentication service: PPP
        7,    // user length
        2,    // port length
        13,   // remote address length
        1,    // data length
    ]);

    // user information
    expected.extend_from_slice(b"startup");
    expected.extend_from_slice(b"49"); // port
    expected.extend_from_slice(b"192.168.23.10"); // remote address

    // data
    expected.push(b'E');

    assert_eq!(&buffer[..43], expected.as_slice());
}

#[test]
fn deserialize_reply_pass_both_data_fields() {
    let mut packet_data = array_vec!([u8; 40]);

    packet_data.extend_from_slice(&[
        0x01, // status: pass
        0,    // no flags set
        0, 16, // server message length
        0, 4, // data length
    ]);

    // server message
    packet_data.extend_from_slice(b"login successful");

    // data
    packet_data.extend_from_slice(&[0x12, 0x77, 0xfa, 0xcc]);

    // extra byte that is not part of packet
    packet_data.push(0xde);

    assert_eq!(
        Reply::try_from(packet_data.as_slice()),
        Ok(Reply {
            status: Status::Pass,
            server_message: FieldText::assert("login successful"),
            data: b"\x12\x77\xfa\xcc",
            flags: ReplyFlags::empty()
        })
    );
}

#[test]
fn deserialize_reply_bad_server_message_length() {
    let mut packet_data = array_vec!([u8; 30]);

    packet_data.extend_from_slice(&[
        0x02, // status: fail
        0,    // no flags set
        13, 37, // server length - way too large
        0, 0, // arbitrary data length - shouldn't matter
    ]);
    packet_data.extend_from_slice(b"something's wrong"); // server message

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
        b'a', // server message
    ];

    assert_eq!(
        Reply::try_from(packet_data.as_slice()),
        Err(DeserializeError::InvalidStatus(42))
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
        Err(DeserializeError::InvalidBodyFlags(2))
    );
}

#[test]
fn deserialize_reply_full_packet() {
    let session_id: u32 = 983274929;
    let mut raw_packet = array_vec!([u8; 40]);

    // HEADER
    raw_packet.extend_from_slice(&[
        (0xc << 4) | 1, // version (minor v1)
        1,              // authentication packet
        4,              // sequence number
        1,              // unencrypted flag set
    ]);
    raw_packet.extend_from_slice(session_id.to_be_bytes().as_slice());
    raw_packet.extend_from_slice(22_u32.to_be_bytes().as_slice()); // body length

    // BODY
    raw_packet.extend_from_slice(&[
        6, // status: restart
        0, // no flags set
        0, 9, // server message length
        0, 7, // data length
    ]);

    raw_packet.extend_from_slice(b"try again"); // server message
    raw_packet.extend_from_slice(&[1, 1, 2, 3, 5, 8, 13]); // data

    let expected_header = HeaderInfo {
        version: Version(MajorVersion::RFC8907, MinorVersion::V1),
        sequence_number: 4,
        flags: PacketFlags::UNENCRYPTED,
        session_id,
    };

    let expected_body = Reply {
        status: Status::Restart,
        server_message: FieldText::assert("try again"),
        data: &[1, 1, 2, 3, 5, 8, 13],
        flags: ReplyFlags::empty(),
    };

    let expected_packet = Packet::new(expected_header, expected_body);

    assert_eq!(raw_packet.as_slice().try_into(), Ok(expected_packet));
}

#[test]
fn deserialize_reply_type_mismatch() {
    let raw_packet = [
        // HEADER
        0xc << 4, // version
        2,        // authorization packet! (incorrect)
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
        Err(DeserializeError::PacketTypeMismatch {
            expected: PacketType::Authentication,
            actual: PacketType::Authorization
        })
    );
}

#[test]
fn serialize_continue_no_data() {
    let continue_body = Continue::new(None, None, ContinueFlags::empty())
        .expect("continue construction should have succeeded");

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

    let continue_body = Continue::new(Some(user_message), Some(data), ContinueFlags::ABORT)
        .expect("continue construction should have succeeded");

    let mut buffer = [0xff; 30];
    continue_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be big enough");

    // field lengths
    assert_eq!(
        buffer[..2],
        u16::try_from(user_message_length).unwrap().to_be_bytes()
    );
    assert_eq!(
        buffer[2..4],
        u16::try_from(data_length).unwrap().to_be_bytes()
    );

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

    let continue_body = Continue::new(None, Some(data), ContinueFlags::empty())
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
    let session_id = 856473784;
    let header = HeaderInfo {
        version: Version(MajorVersion::RFC8907, MinorVersion::Default),
        sequence_number: 49,
        flags: PacketFlags::SINGLE_CONNECTION,
        session_id,
    };

    let body = Continue::new(
        Some(b"this is a message"),
        Some(&[64, 43, 2, 255, 2]),
        ContinueFlags::empty(),
    )
    .expect("continue construction should have worked");

    let packet = Packet::new(header, body);

    let mut buffer = [0x64; 50];
    let serialized_length = packet
        .serialize_into_buffer(buffer.as_mut_slice())
        .expect("packet serialization should succeed");

    let mut expected = array_vec!([u8; 50]);

    // HEADER
    expected.extend_from_slice(&[
        // HEADER
        0xc << 4, // version
        1,        // authentication packet
        49,       // sequence number
        4,        // single connection flag set
    ]);
    expected.extend_from_slice(session_id.to_be_bytes().as_slice());
    expected.extend_from_slice(27_u32.to_be_bytes().as_slice()); // body length

    // BODY
    expected.extend_from_slice(&[
        0, 17, // user message length
        0, 5, // data length
        0, // no flags set
    ]);

    expected.extend_from_slice(b"this is a message"); // user message
    expected.extend_from_slice(&[64, 43, 2, 255, 2]); // data

    assert_eq!(&buffer[..serialized_length], expected.as_slice());
}
