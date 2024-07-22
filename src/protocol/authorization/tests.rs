use super::*;
use crate::protocol::packet::xor_body_with_pad;
use crate::protocol::{
    Arguments, AuthenticationContext, AuthenticationMethod, AuthenticationService,
    AuthenticationType, HeaderInfo, MajorVersion, MinorVersion, Packet, PacketFlags,
    PrivilegeLevel, Serialize, UserInformation, Version,
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
        arguments: Arguments::new(&[]).unwrap(),
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
    let header = HeaderInfo::new(
        Version(MajorVersion::RFC8907, MinorVersion::Default),
        1,
        PacketFlags::UNENCRYPTED,
        session_id,
    );

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
        arguments: Arguments::new(&arguments).unwrap(),
    };

    let packet = Packet::new(header, body);

    let mut buffer = [0x43; 70];
    let serialized_length = packet
        .serialize_unobfuscated(buffer.as_mut_slice())
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
        0, 5, // data length
    ]);

    raw_bytes.extend_from_slice(b"this is a reply"); // server message
    raw_bytes.extend_from_slice(b"short"); // data

    let parsed: Reply = raw_bytes
        .as_slice()
        .try_into()
        .expect("packet parsing should have succeeded");

    // field checks
    assert_eq!(parsed.status, Status::PassAdd);
    assert_eq!(parsed.server_message, FieldText::assert("this is a reply"));
    assert_eq!(parsed.data.as_ref(), "short");

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
    assert_eq!(parsed.data.as_ref(), "world");

    // ensure argument iteration works properly
    let mut arguments_iter = parsed.iter_arguments();

    // check ExactSizeIterator impl
    assert_eq!(arguments_iter.len(), 2);

    // check actual arguments
    assert_eq!(arguments_iter.next(), Some(expected_arguments[0]));
    assert_eq!(arguments_iter.next(), Some(expected_arguments[1]));

    // check ExactSizeIterator impl again, ensuring size_hint and therefore len() return the remaining length
    assert_eq!(arguments_iter.len(), 0);

    // there should be nothing else in the iterator
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
    raw_packet.extend_from_slice(b"data"); // data
    raw_packet.extend_from_slice(b"service=nah");

    let expected_argument =
        Argument::new(FieldText::assert("service"), FieldText::assert("nah"), true).unwrap();

    let expected_header = HeaderInfo::new(
        Version(MajorVersion::RFC8907, MinorVersion::Default),
        4,
        PacketFlags::UNENCRYPTED | PacketFlags::SINGLE_CONNECTION,
        92837492,
    );

    let parsed: Packet<Reply> = Packet::deserialize_unobfuscated(&raw_packet)
        .expect("packet deserialization should succeed");

    // check fields individually, since PartialEq and argument iteration don't play well together
    assert_eq!(parsed.header(), &expected_header);

    assert_eq!(parsed.body().status, Status::Fail);
    assert_eq!(
        parsed.body().server_message,
        FieldText::assert("something went wrong :(")
    );
    assert_eq!(parsed.body().data.as_ref(), "data");

    // argument check: iterator should yield only 1 argument and then none
    let mut argument_iter = parsed.body().iter_arguments();

    // also check ExactSizeIterator impl
    assert_eq!(argument_iter.len(), 1);

    assert_eq!(argument_iter.next(), Some(expected_argument));

    // check ExactSizeIterator impl again, ensuring size_hint and therefore len() return the remaining length
    assert_eq!(argument_iter.len(), 0);

    // there should be nothing else in the iterator
    assert_eq!(argument_iter.next(), None);
}

#[test]
fn deserialize_obfuscated_reply_packet() {
    let mut raw_packet = array_vec!([u8; 70] =>
         // HEADER
         0xc << 4, // version (only major, default minor)
         2,        // authorization packet
         2,        // sequence number
         4,        // single connect flag set (not unencrypted)
         // session id (big-endian u32)
         2,
         234,
         98,
         242,
         // body length (big-endian u32)
         0,
         0,
         0,
         38,
         // BODY
         2, // status: pass/replace arguments
         1, // argument count
         // server message length (big-endian u16)
         0,
         21,
         // data length (big-endian u16)
         0,
         0,
         // argument 1 length
         10,
    );

    // server message
    raw_packet.extend_from_slice(b"privilege level reset");

    // (data field is empty)

    // argument 1
    raw_packet.extend_from_slice(b"priv-lvl=0");

    let expected_header = HeaderInfo::new(
        Version::new(MajorVersion::RFC8907, MinorVersion::Default),
        2,
        PacketFlags::SINGLE_CONNECTION,
        48915186,
    );

    // obfuscate packet body with proper pseudo-pad, again generated in python
    let secret_key = b"packetissecured";
    xor_body_with_pad(
        &expected_header,
        secret_key,
        &mut raw_packet[HeaderInfo::HEADER_SIZE_BYTES..],
    );

    // attempt to deserialize obfuscated packet
    let packet: Packet<Reply> = Packet::deserialize(secret_key, &mut raw_packet)
        .expect("packet deserialization should have succeeded");

    // ensure validity of packet fields

    // header
    assert_eq!(packet.header(), &expected_header);

    // body fields
    let parsed_body = packet.body();
    assert_eq!(*parsed_body.status(), Status::PassReplace);
    assert_eq!(
        parsed_body.server_message().as_ref(),
        "privilege level reset"
    );
    assert_eq!(parsed_body.data().as_ref(), "");

    // also check argument (& ArgumentsInfo iterator impls)
    let mut arguments_iter = parsed_body.iter_arguments();
    assert_eq!(arguments_iter.len(), 1);

    assert_eq!(
        arguments_iter.next(),
        // unwrap/rewrap is done to ensure the iterator actually yields an element
        Some(Argument::new(FieldText::assert("priv-lvl"), FieldText::assert("0"), true).unwrap())
    );

    assert_eq!(arguments_iter.len(), 0);
}

#[cfg(feature = "std")]
#[test]
fn full_unobfuscated_reply_packet_to_owned() {
    use std::string::String;
    use std::vec;

    use crate::protocol::ArgumentOwned;

    let mut raw_packet = array_vec!([u8; 60] =>
        // HEADER
        0xc << 4, // version - major only version, minor v0
        2,        // authorization packet
        2,        // sequence number
        1 | 4,    // both single connection/unencrypted flags set
        // session id
        0xd4,
        0x95,
        0x32,
        0xc3,
        // body length
        0,
        0,
        0,
        41,
        // BODY
        1, // status: add
        1, // argument count
        // server message length
        0,
        11,
        // data length
        0,
        10,
        // argument 1 length
        13,
    );

    // server message
    raw_packet.extend_from_slice(b"message (1)");

    // data/log message
    raw_packet.extend_from_slice(b"ten chars!");

    // argument
    raw_packet.extend_from_slice(b"service=owned");

    let packet: Packet<Reply> = Packet::deserialize_unobfuscated(&raw_packet)
        .expect("packet deserialization should have succeeded");

    let owned_packet = packet.to_owned();

    // check owned packet header
    assert_eq!(
        owned_packet.header(),
        &HeaderInfo::new(
            Version::new(MajorVersion::RFC8907, MinorVersion::Default),
            2,
            PacketFlags::all(),
            3566547651
        )
    );

    // check body fields
    let owned_body = owned_packet.body();

    assert_eq!(owned_body.status, Status::PassAdd);
    assert_eq!(owned_body.server_message, "message (1)");
    assert_eq!(owned_body.data, "ten chars!");
    assert_eq!(
        owned_body.arguments,
        vec![ArgumentOwned {
            name: String::from("service"),
            value: String::from("owned"),
            required: true
        }]
    );
}
