use super::*;

use crate::protocol::common::{
    AuthenticationContext, AuthenticationType, ClientInformation, PrivilegeLevel, Service,
};
use crate::types::force_ascii;

#[test]
fn serialize_authentication_start_no_data() {
    let start_body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(3).expect("privilege level 3 should be valid"),
            authentication_type: AuthenticationType::Pap,
            service: Service::Ppp,
        },
        ClientInformation::new("authtest", force_ascii("serial"), force_ascii("serial"))
            .expect("client information should be valid"),
    );

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
fn serialize_authentication_start_with_data() {
    let mut start_body = Start::new(
        Action::ChangePassword,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(4).expect("privilege level 4 should be valid"),
            authentication_type: AuthenticationType::MsChap,
            service: Service::X25,
        },
        ClientInformation::new("authtest2", force_ascii("49"), force_ascii("10.0.2.24"))
            .expect("client information should be valid"),
    );

    start_body
        .set_data("some test data with ✨ unicode ✨".as_bytes())
        .expect("data should be of valid length");

    let mut buffer = [0xff; 80];
    start_body
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should be long enough");

    assert!(buffer.starts_with(&[
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
        0x73, 0x6f, 0x6d, 0x65, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20,
        0x77, 0x69, 0x74, 0x68, 0x20, 0xe2, 0x9c, 0xa8, 0x20, 0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64,
        0x65, 0x20, 0xe2, 0x9c, 0xa8
    ]));
}

#[test]
fn serialize_authentication_start_data_too_long() {
    let mut start_body = Start::new(
        Action::SendAuth,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(5).expect("privilege level 5 should be valid"),
            authentication_type: AuthenticationType::Ascii,
            service: Service::Nasi,
        },
        ClientInformation::new("invalid", force_ascii("theport"), force_ascii("somewhere"))
            .expect("client information should be valid"),
    );

    let long_data = [0x2a; 256];
    start_body
        .set_data(&long_data)
        .expect_err("data should be too long");
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
    ];

    let parsed_reply =
        Reply::try_from(packet_data.as_slice()).expect("reply packet should be valid");

    assert_eq!(
        parsed_reply,
        Reply {
            status: Status::Pass,
            server_message: b"login successful",
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

    Reply::try_from(packet_data.as_slice()).expect_err("server message length should be invalid");
}

#[test]
fn serialize_authentication_continue_no_data() {
    let continue_body = Continue::new();

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
fn serialize_authentication_continue_both_valid_data_fields() {
    let mut continue_body = Continue::new();
    continue_body.abort = true;

    let user_message = b"secure-password";
    let user_message_length = user_message.len();
    let data = b"\x12\x34\x45\x78";
    let data_length = data.len();

    continue_body
        .set_user_message(user_message)
        .expect("user message should be valid");
    continue_body.set_data(data).expect("data should be valid");

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
fn serialize_authentication_continue_only_data_field() {
    let mut continue_body = Continue::new();

    let data = b"textand\x2abinary\x11";
    let data_length = data.len();

    continue_body.set_data(data).expect("data should be valid");

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
