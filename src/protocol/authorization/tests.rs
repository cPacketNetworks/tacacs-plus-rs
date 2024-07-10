use super::*;
use crate::protocol::{
    AuthenticationContext, AuthenticationMethod, AuthenticationService, AuthenticationType,
    HeaderInfo, MajorVersion, MinorVersion, Packet, PacketFlags, PrivilegeLevel, Serialize,
    UserInformation, Version,
};
use crate::AsciiStr;

use tinyvec::array_vec;

#[test]
fn serialize_request_no_arguments() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::of(1).unwrap(),
        authentication_type: AuthenticationType::Ascii,
        service: AuthenticationService::Enable,
    };

    let user_information = UserInformation::new(
        "testuser",
        AsciiStr::assert("tcp49"),
        AsciiStr::assert("127.0.0.1"),
    )
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

    let mut expected = array_vec!([u8; 40]);
    expected.extend_from_slice(&[
        0x04, // authentication method: enable
        1,    // privilege level: 1
        0x01, // authentication type: ASCII
        0x02, // authentication service: enable
        8,    // user length
        5,    // port length
        9,    // remote address length
        0,    // argument count (no arguments supplied)
    ]);

    expected.extend_from_slice(b"testuser"); // user
    expected.extend_from_slice(b"tcp49"); // port
    expected.extend_from_slice(b"127.0.0.1"); // remote address

    assert_eq!(&buffer[..30], expected.as_slice());
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
        AsciiStr::assert("ttyAMA0"),
        AsciiStr::assert("127.1.2.2"),
    )
    .expect("client information should have been valid");

    let mut argument_array = [Argument::new(
        AsciiStr::assert("service"),
        AsciiStr::assert("serialization-test"),
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

    let mut expected = array_vec!([u8; 60]);
    expected.extend_from_slice(&[
        0x06, // authentication method: TACACS+
        15,   // privilege level
        0x06, // authentication type: MSCHAPv2
        0x09, // authentication service: firewall proxy
        8,    // user length
        7,    // port length
        9,    // remote address length
        1,    // one argument
        26,   // argument 1 length
    ]);

    // user information
    expected.extend_from_slice(b"testuser");
    expected.extend_from_slice(b"ttyAMA0");
    expected.extend_from_slice(b"127.1.2.2");

    // service argument
    expected.extend_from_slice(b"service=serialization-test");

    assert_eq!(&buffer[..serialized_length], expected.as_slice());
}

#[test]
fn serialize_full_request_packet() {
    let session_id: u32 = 578263403;
    let header = HeaderInfo {
        version: Version::of(MajorVersion::RFC8907, MinorVersion::Default),
        sequence_number: 1,
        flags: PacketFlags::Unencrypted,
        session_id,
    };

    let mut arguments = [Argument::new(
        AsciiStr::assert("service"),
        AsciiStr::assert("fulltest"),
        true,
    )
    .unwrap()];

    let body = Request {
        method: AuthenticationMethod::Kerberos5,
        authentication_context: AuthenticationContext {
            privilege_level: PrivilegeLevel::of(14).unwrap(),
            authentication_type: AuthenticationType::NotSet,
            service: AuthenticationService::Enable,
        },
        user_information: UserInformation::new(
            "requestor",
            AsciiStr::assert("tcp23"),
            AsciiStr::assert("127.254.1.2"),
        )
        .unwrap(),
        arguments: Arguments::try_from_full_slice(arguments.as_mut_slice()).unwrap(),
    };

    let packet = Packet::new(header, body).expect("packet construction should have succeeded");

    let mut buffer = [0x43; 70];
    let serialized_length = packet
        .serialize_into_buffer(buffer.as_mut_slice())
        .expect("packet serialization should have succeeded");

    let mut expected = array_vec!([u8; 70]);

    // HEADER
    expected.extend_from_slice(&[
        0xc << 4, // version
        2,        // authorization packet
        1,        // sequence number
        1,        // unencrypted flag set
    ]);

    expected.extend_from_slice(session_id.to_be_bytes().as_slice());
    expected.extend_from_slice(50_u32.to_be_bytes().as_slice()); // body length

    // BODY
    expected.extend_from_slice(&[
        2,  // authentication method: Kerberos 5
        14, // privilege level
        0,  // authentication type: not set
        2,  // authentication service: enable
        9,  // user length
        5,  // port length
        11, // remote address length
        1,  // argument count
        16, // argument 1 length
    ]);

    // user information
    expected.extend_from_slice(b"requestor");
    expected.extend_from_slice(b"tcp23");
    expected.extend_from_slice(b"127.254.1.2");

    // service argument
    expected.extend_from_slice(b"service=fulltest");

    assert_eq!(&buffer[..serialized_length], expected.as_slice());
}

#[test]
fn deserialize_reply_two_arguments() {
    let mut raw_bytes = array_vec!([u8; 50]);
    raw_bytes.extend_from_slice(&[
        0x01, // status: pass/add
        2,    // two arguments
        0, 5, // server message length
        0, 5,  // data length
        13, // argument 1 length
        13, // argument 2 length
    ]);

    raw_bytes.extend_from_slice(b"hello"); // server message
    raw_bytes.extend_from_slice(b"world"); // data

    // arguments
    raw_bytes.extend_from_slice(b"service=greet");
    raw_bytes.extend_from_slice(b"person*world!");

    let mut expected_arguments = [
        Argument::new(AsciiStr::assert("service"), AsciiStr::assert("greet"), true).unwrap(),
        Argument::new(
            AsciiStr::assert("person"),
            AsciiStr::assert("world!"),
            false,
        )
        .unwrap(),
    ];

    let expected = Reply {
        status: Status::PassAdd,
        server_message: AsciiStr::assert("hello"),
        data: b"world",
        arguments: Arguments::try_from_full_slice(expected_arguments.as_mut_slice())
            .expect("argument construction shouldn't have failed"),
    };

    let mut parsed_argument_space: [Argument; 2] = Default::default();

    assert_eq!(
        Ok(expected),
        Reply::deserialize_from_buffer(raw_bytes.as_slice(), parsed_argument_space.as_mut_slice())
    );
}

#[test]
fn deserialize_full_reply_packet() {
    let mut raw_packet = array_vec!([u8; 60]);

    let session_id: u32 = 92837492;

    // HEADER
    raw_packet.extend_from_slice(&[
        0xc << 4,    // major/minor version
        0x2,         // type: authorization
        4,           // sequence number
        0x01 | 0x04, // both flags set
    ]);

    raw_packet.extend_from_slice(session_id.to_be_bytes().as_slice());
    raw_packet.extend_from_slice(45_u32.to_be_bytes().as_slice()); // body length

    // BODY
    raw_packet.extend_from_slice(&[
        0x10, // status: fail
        1,    // argument count
        0, 23, // server message length
        0, 4,  // data length
        11, // argument length
    ]);

    raw_packet.extend_from_slice(b"something went wrong :("); // server message
    raw_packet.extend_from_slice(&[0x88; 4]); // data
    raw_packet.extend_from_slice(b"service=nah");

    let mut expected_arguments =
        [Argument::new(AsciiStr::assert("service"), AsciiStr::assert("nah"), true).unwrap()];

    let expected_header = HeaderInfo {
        version: Version::of(MajorVersion::RFC8907, MinorVersion::Default),
        sequence_number: 4,
        flags: PacketFlags::Unencrypted | PacketFlags::SingleConnection,
        session_id: 92837492,
    };

    let expected_body = Reply {
        status: Status::Fail,
        server_message: AsciiStr::assert("something went wrong :("),
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
