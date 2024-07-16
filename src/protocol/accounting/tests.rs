use super::*;
use crate::protocol::{
    Argument, AuthenticationContext, AuthenticationMethod, AuthenticationService,
    AuthenticationType, HeaderInfo, MajorVersion, MinorVersion, Packet, PacketFlags,
    PrivilegeLevel, UserInformation, Version,
};
use crate::FieldText;

use tinyvec::array_vec;

#[test]
fn serialize_request_body_with_argument() {
    let argument_array = [Argument::new(
        FieldText::assert("service"),
        FieldText::assert("tacacs-test"),
        true,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::new(&argument_array).expect("argument array should be valid");

    let request = Request {
        flags: Flags::StartRecord,
        authentication_method: AuthenticationMethod::Guest,
        authentication: AuthenticationContext {
            privilege_level: PrivilegeLevel::new(0).unwrap(),
            authentication_type: AuthenticationType::Ascii,
            service: AuthenticationService::Login,
        },
        user_information: UserInformation::new(
            "guest",
            FieldText::assert("tty0"),
            FieldText::assert("127.10.0.100"),
        )
        .unwrap(),
        arguments,
    };

    let mut buffer = [0u8; 50];
    request
        .serialize_into_buffer(&mut buffer)
        .expect("buffer should have been large enough");

    let mut expected = array_vec!([u8; 50]);
    expected.extend_from_slice(&[
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
    ]);

    expected.extend_from_slice(b"guest"); // user
    expected.extend_from_slice(b"tty0"); // port
    expected.extend_from_slice(b"127.10.0.100"); // remote address
    expected.extend_from_slice(b"service=tacacs-test"); // argument

    assert_eq!(buffer, expected.as_slice());
}

#[test]
fn serialize_full_request_packet() {
    let arguments_array = [
        Argument::new(
            FieldText::assert("task_id"),
            FieldText::assert("1234"),
            true,
        )
        .unwrap(),
        Argument::new(
            FieldText::assert("service"),
            FieldText::assert("fullpacket"),
            true,
        )
        .unwrap(),
    ];

    let arguments = Arguments::new(&arguments_array)
        .expect("Arguments construction shouldn't fail; length is short enough");

    let body = Request {
        flags: Flags::WatchdogNoUpdate,
        authentication_method: AuthenticationMethod::NotSet,
        authentication: AuthenticationContext {
            privilege_level: PrivilegeLevel::new(10).unwrap(),
            authentication_type: AuthenticationType::NotSet,
            service: AuthenticationService::Pt,
        },
        user_information: UserInformation::new(
            "secret",
            FieldText::assert("tty6"),
            FieldText::assert("10.10.10.10"),
        )
        .unwrap(),
        arguments,
    };

    let session_id = 298734923;
    let header = HeaderInfo::new(Default::default(), 1, PacketFlags::empty(), session_id);

    let packet = Packet::new(header, body);

    let mut buffer = [0xff; 100];
    let packet_size = packet
        .serialize_into_buffer(buffer.as_mut_slice())
        .expect("packet serialization failed");

    let mut expected = array_vec!([u8; 100]);

    // HEADER
    expected.extend_from_slice(&[
        (0xc << 4), // version
        0x3,        // accounting packet
        1,          // sequence number
        0,          // no flags set
    ]);
    expected.extend_from_slice(session_id.to_be_bytes().as_slice());
    expected.extend_from_slice(62_u32.to_be_bytes().as_slice()); // body length

    // BODY
    expected.extend_from_slice(&[
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
    ]);

    // user information
    expected.extend_from_slice(b"secret");
    expected.extend_from_slice(b"tty6"); // port
    expected.extend_from_slice(b"10.10.10.10"); // remote address

    // arguments
    expected.extend_from_slice(b"task_id=1234");
    expected.extend_from_slice(b"service=fullpacket");

    assert_eq!(&buffer[..packet_size], expected.as_slice());
}

#[test]
fn deserialize_reply_all_fields() {
    let mut body_raw = array_vec!([u8; 60]);

    body_raw.extend_from_slice(&[
        0, 47, // server message length
        0, 2,    // data length,
        0x02, // status: error
    ]);

    let server_message = [b'A'; 47];
    body_raw.extend_from_slice(&server_message);

    // data
    body_raw.extend_from_slice(&[0xa4, 0x42]);

    assert_eq!(
        Ok(Reply {
            status: Status::Error,
            server_message: FieldText::try_from(server_message.as_slice()).unwrap(),
            data: &[0xa4, 0x42]
        }),
        body_raw.as_slice().try_into()
    );
}

#[test]
fn deserialize_full_reply_packet() {
    let session_id: u32 = 49241163;

    let mut raw_packet = array_vec!([u8; 40]);

    // HEADER
    raw_packet.extend_from_slice(&[
        (0xc << 4) | 1, // version
        3,              // accounting packet
        2,              // sequence number
        5,              // both unencrypted and single connection flags set
    ]);
    raw_packet.extend_from_slice(session_id.to_be_bytes().as_slice());
    raw_packet.extend_from_slice(25_u32.to_be_bytes().as_slice());

    // BODY
    raw_packet.extend_from_slice(&[
        0, 5, // server message length
        0, 15, // data length
        2,  // status: error
    ]);

    raw_packet.extend_from_slice(b"hello"); // server message
    raw_packet.extend_from_slice(b"fifteen letters"); // data

    let expected_header = HeaderInfo {
        version: Version(MajorVersion::RFC8907, MinorVersion::V1),
        sequence_number: 2,
        flags: PacketFlags::all(),
        session_id,
    };

    let expected_body = Reply {
        status: Status::Error,
        server_message: FieldText::assert("hello"),
        data: b"fifteen letters",
    };

    let expected_packet = Packet::new(expected_header, expected_body);

    assert_eq!(raw_packet.as_slice().try_into(), Ok(expected_packet));
}
