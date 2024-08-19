use super::FieldText;

#[test]
#[cfg(feature = "std")]
fn owned_and_borrowed_equal() {
    let owned = FieldText::try_from(std::string::String::from("string")).unwrap();
    let borrowed = FieldText::try_from("string").unwrap();
    assert_eq!(owned, borrowed);
}
