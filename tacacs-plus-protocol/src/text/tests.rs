use super::FieldText;

#[test]
#[cfg(feature = "std")]
fn owned_and_borrowed_equal() {
    let owned = FieldText::try_from(std::string::String::from("string")).unwrap();
    let borrowed = FieldText::try_from("string").unwrap();
    assert_eq!(owned, borrowed);
}

#[test]
fn text_partialeq_str_impl() {
    let string = "some characters in a string";
    let text = FieldText::try_from(string).unwrap();

    // ensure equality on both sides works
    assert_eq!(string, text);
    assert_eq!(text, string);
}
