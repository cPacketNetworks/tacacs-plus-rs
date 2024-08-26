//! Convenience type for enforcing valid ASCII printable strings.

use core::fmt;

mod inner;
use inner::FieldTextInner;

#[cfg(test)]
mod tests;

/// A wrapper for `&str` that is checked to be printable ASCII, which is
/// defined as not containing control characters in [RFC8907 section 3.7].
///
/// This type implements `TryFrom<&str>` and `TryFrom<&[u8]>`; in both cases,
/// an invalid argument will be returned as an `Err` variant.
///
/// # Examples
///
/// Conversions from `&str`:
///
/// ```
/// use tacacs_plus_protocol::FieldText;
///
/// let valid_ascii = "a string";
/// assert!(FieldText::try_from(valid_ascii).is_ok());
///
/// let beyond_ascii = "💀";
/// assert!(FieldText::try_from(beyond_ascii).is_err());
/// ```
///
/// Conversions from `&[u8]`:
///
/// ```
/// # use tacacs_plus_protocol::FieldText;
///
/// let valid_slice = b"this is (almost) a string";
/// assert!(FieldText::try_from(valid_slice.as_slice()).is_ok());
///
/// let not_printable = b"all ASCII characters with - oh no! - a\ttab";
/// assert!(FieldText::try_from(not_printable.as_slice()).is_err());
///
/// let invalid_utf8 = [0x80]; // where'd the rest of the codepoint go?
/// assert!(FieldText::try_from(invalid_utf8.as_slice()).is_err());
/// ```
///
/// If the `std` feature is enabled, the `FieldText::from_string_lossy()` constructor
/// is also available in case a `.try_into().unwrap()` is undesirable:
///
/// ```
/// # use tacacs_plus_protocol::FieldText;
/// # #[cfg(feature = "std")] {
/// let already_valid = "all ASCII!";
/// let valid_text = FieldText::from_string_lossy(String::from(already_valid));
/// assert_eq!(valid_text, already_valid);
///
/// let unicode_fun = "\tsome chars and ✨emojis✨ (and a quote: ')";
/// let escaped_text = FieldText::from_string_lossy(String::from(unicode_fun));
/// assert_eq!(escaped_text, "\\tsome chars and \\u{2728}emojis\\u{2728} (and a quote: ')");
///
/// // now that escaped_text is valid ASCII, a .try_into().unwrap() should be guaranteed
/// // not to panic with the escaped string
/// let _: FieldText<'_> = escaped_text.as_ref().try_into().unwrap();
/// # }
/// ```
///
/// [RFC8907 section 3.7]: https://www.rfc-editor.org/rfc/rfc8907.html#section-3.7
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct FieldText<'string>(FieldTextInner<'string>);

impl FieldText<'_> {
    /// Creates a [`FieldText`] from a `String`, escaping any non-printable-ASCII
    /// characters as necessary.
    #[cfg(feature = "std")]
    pub fn from_string_lossy(string: std::string::String) -> FieldText<'static> {
        use std::string::String;

        // we don't just use String::escape_default() + ToString since that also escapes quotes,
        // which we don't want since they're already valid ASCII
        let escaped = string
            .chars()
            .fold(String::with_capacity(string.len()), |mut result, c| {
                if char_is_printable_ascii(c) {
                    result.push(c);
                } else {
                    result.extend(c.escape_default());
                }

                result
            });

        FieldText(FieldTextInner::Owned(escaped))
    }

    /// Converts this [`FieldText`] to one that owns its underlying data,
    /// extending its lifetime to `'static`.
    #[cfg(feature = "std")]
    pub fn into_owned(self) -> FieldText<'static> {
        FieldText(self.0.into_owned())
    }
}

impl<'string> FieldText<'string> {
    /// Gets the length of the underlying `&str`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Gets the byte slice representation of the underlying `&str`.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns true if the underlying `&str` is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns `true` if the underlying `&str` contains any of the provided characters, or false otherwise.
    pub fn contains_any(&self, characters: &[char]) -> bool {
        self.0.contains(characters)
    }

    /// Asserts a string is ASCII, converting it to an [`FieldText`] or panicking if it is not actually ASCII.
    #[cfg(test)]
    pub(crate) fn assert(string: &str) -> FieldText<'_> {
        if is_printable_ascii(string) {
            FieldText(FieldTextInner::Borrowed(string))
        } else {
            panic!("non-ASCII string passed to `FieldText::assert()`");
        }
    }
}

fn is_printable_ascii(string: &str) -> bool {
    // all characters must be ASCII printable (i.e., not control characers)
    string.chars().all(char_is_printable_ascii)
}

fn char_is_printable_ascii(c: char) -> bool {
    c.is_ascii() && !c.is_ascii_control()
}

impl AsRef<str> for FieldText<'_> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'string> TryFrom<&'string str> for FieldText<'string> {
    type Error = &'string str;

    fn try_from(value: &'string str) -> Result<Self, Self::Error> {
        if is_printable_ascii(value) {
            Ok(Self(FieldTextInner::Borrowed(value)))
        } else {
            Err(value)
        }
    }
}

// std-gated since we can't keep a reference to the &str internally without a lifetime parameter on FromStr
#[cfg(feature = "std")]
impl std::str::FromStr for FieldText<'static> {
    type Err = std::string::String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use std::borrow::ToOwned;
        s.to_owned().try_into()
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for FieldText<'bytes> {
    type Error = &'bytes [u8];

    fn try_from(value: &'bytes [u8]) -> Result<Self, Self::Error> {
        if let Ok(value_str) = core::str::from_utf8(value) {
            // defer to TryFrom<&str> impl for ASCII check consistency
            value_str.try_into().map_err(str::as_bytes)
        } else {
            Err(value)
        }
    }
}

#[cfg(feature = "std")]
impl TryFrom<std::string::String> for FieldText<'_> {
    type Error = std::string::String;

    fn try_from(value: std::string::String) -> Result<Self, Self::Error> {
        if is_printable_ascii(&value) {
            Ok(Self(FieldTextInner::Owned(value)))
        } else {
            Err(value)
        }
    }
}

impl PartialEq<&str> for FieldText<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<FieldText<'_>> for &str {
    fn eq(&self, other: &FieldText<'_>) -> bool {
        *self == other.0
    }
}

impl fmt::Display for FieldText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <_ as fmt::Display>::fmt(&self.0, f)
    }
}
