use super::*;

#[test]
fn invalid_privilege_level_none() {
    let level = PrivilegeLevel::of(42);
    assert!(level.is_none());
}

#[test]
fn client_information_nonascii_port() {
    ClientInformation::new("testuser", "💀", "127.0.0.1")
        .expect_err("non-ASCII port should have failed");
}

#[test]
fn client_information_long_username() {
    let username = [0x41u8; 512]; // AAA...AAA
    ClientInformation::new(
        std::str::from_utf8(&username).unwrap(),
        "tcp49",
        "127.0.0.1",
    )
    .expect_err("username should be too long");
}

#[test]
fn arguments_two_required() {
    let mut arguments = Arguments::new();

    // populate with arguments
    arguments.add_argument("service", "test", true);
    arguments.add_argument("random-argument", "idk", true);

    let mut buffer = [0u8; 40];

    // contains is used here and below since HashMaps are nondeterministic as far as I know
    arguments.serialize_header_client(&mut buffer);
    assert_eq!(buffer[0], 2);
    assert!(buffer.contains(&12));
    assert!(buffer.contains(&19));

    arguments.serialize_body_values(&mut buffer);
    let body_string = std::str::from_utf8(&buffer).expect("body should be valid UTF-8");
    assert!(body_string.contains("service=test"));
    assert!(body_string.contains("random-argument=idk"));
}
