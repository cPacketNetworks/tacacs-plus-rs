use super::Request;
use crate::protocol::common::{
    Arguments, AuthenticationContext, AuthenticationMethod, AuthenticationType, ClientInformation,
    PrivilegeLevel, Service,
};

#[test]
fn serialize_request_no_arguments() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::of(1).unwrap(),
        authentication_type: AuthenticationType::Ascii,
        service: Service::Enable,
    };

    let client_information = ClientInformation::new("testuser", "tcp49", "127.0.0.1")
        .expect("client information should have been valid");

    let request = Request {
        method: AuthenticationMethod::Enable,
        authentication_context,
        client_information,
        arguments: Default::default(),
    };

    let mut buf = [0u8; 30];
    request
        .serialize_into_buffer(buf.as_mut())
        .expect("buffer should have been big enough");

    assert_eq!(
        buf,
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
