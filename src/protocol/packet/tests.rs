use super::*;

use crate::protocol::accounting::Reply;
use crate::protocol::{MajorVersion, MinorVersion, Version};

#[test]
fn obfuscated_packet_wrong_unencrypted_flag() {
    // body doesn't matter (error should be returned before getting there) so we can omit it
    let mut raw_packet = [
        0xc << 4, // version (minor v0)
        3,        // accounting packet
        2,        // sequence number
        1,        // unencrypted flag - shouldn't be set!
        // session id
        0,
        0,
        0,
        0,
        // body length (doesn't matter)
        0,
        0,
        0,
        0,
    ];

    let deserialize_error = Packet::<Reply>::deserialize(b"supersecret", &mut raw_packet)
        .expect_err("packet deserialization should have failed");
    assert_eq!(
        deserialize_error,
        DeserializeError::IncorrectUnencryptedFlag
    );
}

#[test]
fn unobfuscated_packet_wrong_unencrypted_flag() {
    let raw_packet = [
        0xc << 4, // version (minor v0)
        3,        // accounting packet
        4,        // sequence number
        0,        // unencrypted flag - should be set!
        // session id
        1,
        1,
        1,
        1,
        // body length (doesn't matter)
        0,
        0,
        0,
        0,
    ];

    let deserialize_error = Packet::<Reply>::deserialize_unobfuscated(&raw_packet)
        .expect_err("packet deserialization should have failed");
    assert_eq!(
        deserialize_error,
        DeserializeError::IncorrectUnencryptedFlag
    );
}

#[test]
fn obfuscate_correct_pad_generated() {
    let header = HeaderInfo::new(
        Version::new(MajorVersion::RFC8907, MinorVersion::V1),
        7,
        PacketFlags::empty(),
        487514234,
    );

    // make buffer slightly over 1 MD5 output length, to also test truncation & MD5 iteration
    let mut buffer = [0u8; 20];
    xor_body_with_pad(&header, b"no one will guess this", &mut buffer);

    assert_eq!(
        buffer,
        [
            // known correct pad based on information in header
            0x0d, 0x2e, 0xd1, 0x6f, 0xd6, 0x37, 0xab, 0x81, 0xc1, 0x3a, 0xc8, 0xf9, 0x19, 0xb4,
            0x65, 0x48, 0x06, 0xf6, 0x5b, 0x41
        ]
    );
}
