use super::*;
use crate::protocol::{
    Arguments, AuthenticationContext, AuthenticationMethod, AuthenticationService,
    AuthenticationType, HeaderInfo, Packet, PacketFlags, PrivilegeLevel, Serialize,
    UserInformation,
};
use crate::FieldText;

use tinyvec::array_vec;

#[test]
fn serialize_request_no_arguments() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::new(1).unwrap(),
        authentication_type: AuthenticationType::Ascii,
        service: AuthenticationService::Enable,
    };

    let user_information = UserInformation::new(
        "testuser",
        FieldText::assert("tcp49"),
        FieldText::assert("127.0.0.1"),
    )
    .expect("client information should have been valid");

    let request = Request {
        method: AuthenticationMethod::Enable,
        authentication_context,
        user_information,
        arguments: None,
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
        privilege_level: PrivilegeLevel::new(15).expect("15 should be a valid privilege level"),
        authentication_type: AuthenticationType::MsChapV2,
        service: AuthenticationService::FwProxy,
    };

    let user_information = UserInformation::new(
        "testuser",
        FieldText::assert("ttyAMA0"),
        FieldText::assert("127.1.2.2"),
    )
    .expect("client information should have been valid");

    let argument_array = [Argument::new(
        FieldText::assert("service"),
        FieldText::assert("serialization-test"),
        true,
    )
    .expect("argument should be valid")];

    let arguments = Arguments::new(&argument_array).expect("single argument array should be valid");

    let request = Request {
        method: AuthenticationMethod::TacacsPlus,
        authentication_context,
        user_information,
        arguments: Some(arguments),
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
        sequence_number: 1,
        flags: PacketFlags::UNENCRYPTED,
        session_id,
    };

    let arguments_list = [Argument::new(
        FieldText::assert("service"),
        FieldText::assert("fulltest"),
        true,
    )
    .unwrap()];
    let arguments =
        Arguments::new(&arguments_list).expect("argument list should be of proper length");

    let body = Request {
        method: AuthenticationMethod::Kerberos5,
        authentication_context: AuthenticationContext {
            privilege_level: PrivilegeLevel::new(14).unwrap(),
            authentication_type: AuthenticationType::NotSet,
            service: AuthenticationService::Enable,
        },
        user_information: UserInformation::new(
            "requestor",
            FieldText::assert("tcp23"),
            FieldText::assert("127.254.1.2"),
        )
        .unwrap(),
        arguments: Arguments::new(&arguments),
    };

    let packet = Packet::new(header, body);

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
fn deserialize_reply_no_arguments() {
    let mut raw_bytes = array_vec!([u8; 50]);
    raw_bytes.extend_from_slice(&[
        0x01, // status: pass/add
        0,    // no arguments
        0, 15, // server message length
        0, 6, // data length
    ]);

    raw_bytes.extend_from_slice(b"this is a reply"); // server message
    raw_bytes.extend_from_slice(&[123, 91, 3, 4, 21, 168]); // data

    let parsed: Reply = raw_bytes
        .as_slice()
        .try_into()
        .expect("packet parsing should have succeeded");

    // field checks
    assert_eq!(parsed.status, Status::PassAdd);
    assert_eq!(parsed.server_message, FieldText::assert("this is a reply"));
    assert_eq!(parsed.data, &[123, 91, 3, 4, 21, 168]);

    // ensure iterator has no elements & reports a length of 0
    let mut argument_iter = parsed.iter_arguments();
    assert_eq!(argument_iter.len(), 0);
    assert_eq!(argument_iter.next(), None);
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

    let expected_arguments = [
        Argument::new(
            FieldText::assert("service"),
            FieldText::assert("greet"),
            true,
        )
        .unwrap(),
        Argument::new(
            FieldText::assert("person"),
            FieldText::assert("world!"),
            false,
        )
        .unwrap(),
    ];

    let parsed: Reply = raw_bytes
        .as_slice()
        .try_into()
        .expect("argument parsing should have succeeded");

    // check specific fields, as iterator's can't really implement PartialEq
    assert_eq!(parsed.status, Status::PassAdd);
    assert_eq!(parsed.server_message, FieldText::assert("hello"));
    assert_eq!(parsed.data, b"world");

    // ensure argument iteration works properly
    let mut arguments_iter = parsed.iter_arguments();

    // check ExactSizeIterator impl
    assert_eq!(arguments_iter.len(), 2);

    // check actual arguments
    assert_eq!(arguments_iter.next(), Some(expected_arguments[0]));
    assert_eq!(arguments_iter.next(), Some(expected_arguments[1]));
    assert_eq!(arguments_iter.next(), None);
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

    let expected_argument =
        Argument::new(FieldText::assert("service"), FieldText::assert("nah"), true).unwrap();

    let expected_header = HeaderInfo {
        sequence_number: 4,
        flags: PacketFlags::UNENCRYPTED | PacketFlags::SINGLE_CONNECTION,
        session_id: 92837492,
    };

    let parsed: Packet<Reply> = raw_packet
        .as_slice()
        .try_into()
        .expect("packet deserialization should succeed");

    // check fields individually, since PartialEq and argument iteration don't play well together
    assert_eq!(parsed.header, expected_header);

    assert_eq!(parsed.body.status, Status::Fail);
    assert_eq!(
        parsed.body.server_message,
        FieldText::assert("something went wrong :(")
    );
    assert_eq!(parsed.body.data, b"\x88\x88\x88\x88");

    // argument check: iterator should yield only 1 argument and then none
    let mut argument_iter = parsed.body.iter_arguments();

    // also check ExactSizeIterator impl
    assert_eq!(argument_iter.len(), 1);

    assert_eq!(argument_iter.next(), Some(expected_argument));
    assert_eq!(argument_iter.next(), None);
}
