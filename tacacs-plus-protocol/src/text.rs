//! Convenience type for enforcing valid ASCII printable strings.

use core::fmt;

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
/// use tacacs_plus_protocol::FieldText;
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
/// [RFC8907 section 3.7]: https://www.rfc-editor.org/rfc/rfc8907.html#section-3.7
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldText<'string>(&'string str);

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

    fn is_printable_ascii(string: &str) -> bool {
        // all characters must be ASCII printable (i.e., not control characers)
        string.is_ascii() && string.chars().all(|c| !c.is_ascii_control())
    }

    /// Asserts a string is ASCII, converting it to an [`FieldText`] or panicking if it is not actually ASCII.
    #[cfg(test)]
    pub(crate) fn assert(string: &str) -> FieldText<'_> {
        if Self::is_printable_ascii(string) {
            FieldText(string)
        } else {
            panic!("non-ASCII string passed to force_ascii");
        }
    }
}

impl AsRef<str> for FieldText<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'string> TryFrom<&'string str> for FieldText<'string> {
    type Error = &'string str;

    fn try_from(value: &'string str) -> Result<Self, Self::Error> {
        if Self::is_printable_ascii(value) {
            Ok(Self(value))
        } else {
            Err(value)
        }
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

// boilerplate impls, mostly for tests and also lets us #[derive(Debug)] for packet component structs
impl fmt::Debug for FieldText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for FieldText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
