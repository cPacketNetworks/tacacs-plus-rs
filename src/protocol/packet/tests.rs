use super::*;

use crate::protocol::accounting::Reply;

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
