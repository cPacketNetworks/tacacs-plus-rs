use tinyvec::array_vec;

use super::*;

#[test]
fn serialize_authentication_context() {
    let authentication_context = AuthenticationContext {
        privilege_level: PrivilegeLevel::new(14).unwrap(),
        authentication_type: AuthenticationType::Ascii,
        service: AuthenticationService::Login,
    };

    let mut buffer = [0xff; 3];
    authentication_context.serialize(&mut buffer);

    assert_eq!(
        buffer,
        [
            14, // privilege level
            1,  // ASCII authentication
            1,  // login service
        ]
    );
}

#[test]
fn serialize_user_information() {
    let user = "useruser";
    let port = FieldText::assert("tty0");
    let remote_address = FieldText::assert("127.72.12.99");

    let user_info = UserInformation::new(user, port.clone(), remote_address.clone())
        .expect("user information construction should have succeeded");

    let mut buffer = [0xff; 40];

    // test lengths serialization
    let field_lengths_len = user_info
        .serialize_field_lengths(&mut buffer)
        .expect("length serialization should have succeeded");
    assert_eq!(
        buffer[..field_lengths_len],
        [
            user.len().try_into().unwrap(),
            port.len().try_into().unwrap(),
            remote_address.len().try_into().unwrap()
        ]
    );

    // test body/field values serialization
    let field_values_len = user_info
        .serialize_field_values(&mut buffer)
        .expect("value serialization should have succeeded");

    let mut expected_values = array_vec!([u8; 40]);
    expected_values.extend_from_slice(user.as_bytes());
    expected_values.extend_from_slice(port.as_bytes());
    expected_values.extend_from_slice(remote_address.as_bytes());

    assert_eq!(&buffer[..field_values_len], expected_values.as_ref());
}

#[test]
fn user_information_long_user() {
    let user = core::str::from_utf8(&[b'A'; 256]).expect("all As should be valid UTF-8");
    let user_info = UserInformation::new(
        user,
        FieldText::assert("ttyAMA0"),
        FieldText::assert("ttyAMA0"),
    );

    assert!(
        user_info.is_none(),
        "User information with long name should not be constructible"
    );
}
