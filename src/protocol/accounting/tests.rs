use super::*;
use crate::protocol::common::{
    Argument, AuthenticationContext, AuthenticationMethod, AuthenticationType, ClientInformation,
    PrivilegeLevel, Service,
};
use crate::types::force_ascii;

#[test]
fn serialize_accounting_packet_with_argument() {
    let mut argument_array =
        [
            Argument::new(force_ascii("service"), force_ascii("tacacs-test"), true)
                .expect("argument should be valid"),
        ];

    let arguments = argument_array
        .as_mut_slice()
        .try_into()
        .expect("argument array should be valid");

    let request = Request {
        flags: AccountingFlags::StartRecord,
        authentication_method: AuthenticationMethod::Guest,
        authentication: AuthenticationContext {
            privilege_level: PrivilegeLevel::of(0).unwrap(),
            authentication_type: AuthenticationType::Ascii,
            service: Service::Login,
        },
        client_information: ClientInformation::new(
            "guest",
            force_ascii("tty0"),
            force_ascii("127.10.0.100"),
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
            // remote IP address: 127.10.0.100
            0x31, 0x32, 0x37, 0x2e, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x30, 0x30,
            // required argument: service=tacacs-test
            0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3d, 0x74, 0x61, 0x63, 0x61, 0x63, 0x73,
            0x2d, 0x74, 0x65, 0x73, 0x74
        ]
    );
}
