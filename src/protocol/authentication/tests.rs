use super::*;

use crate::protocol::common::{
    AuthenticationContext, AuthenticationType, ClientInformation, PrivilegeLevel, SerializeError,
    Service,
};

#[test]
fn serialize_authentication_start_no_data() {
    let start_body = Start::new(
        Action::Login,
        AuthenticationContext {
            privilege_level: PrivilegeLevel::of(3).expect("privilege level 3 should be valid"),
            authentication_type: AuthenticationType::Pap,
            service: Service::Ppp,
        },
        ClientInformation::new("authtest", "serial", "serial")
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
        ClientInformation::new("authtest2", "49", "10.0.2.24")
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
        ClientInformation::new("invalid", "theport", "somewhere")
            .expect("client information should be valid"),
    );

    let long_data = [0x2a; 256];
    start_body
        .set_data(&long_data)
        .expect_err("data should be too long");
}
