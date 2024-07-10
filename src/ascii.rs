//! Convenience types for enforcing valid ASCII strings.

use core::fmt;

/// A wrapper for `&str` that is checked to be valid ASCII.
///
/// This type implements `TryFrom<&str>` and `TryFrom<&[u8]>`; in both cases,
/// an invalid argument will be returned as an `Err` variant.
///
/// # Examples
///
/// Conversions from `&str`:
///
/// ```
/// use tacacs_plus::AsciiStr;
///
/// let valid_ascii = "a string";
/// assert!(AsciiStr::try_from(valid_ascii).is_ok());
///
/// let beyond_ascii = "💀";
/// assert!(AsciiStr::try_from(beyond_ascii).is_err());
/// ```
///
/// Conversions from `&[u8]`:
///
/// ```
/// use tacacs_plus::AsciiStr;
///
/// let valid_ascii = b"all ASCII characters with a\ttab";
/// assert!(AsciiStr::try_from(valid_ascii.as_slice()).is_ok());
///
/// let invalid_utf8 = [0x80]; // where'd the rest of the codepoint go?
/// assert!(AsciiStr::try_from(invalid_utf8.as_slice()).is_err());
/// ```
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct AsciiStr<'string>(&'string str);

impl<'string> AsciiStr<'string> {
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

    /// Asserts a string is ASCII, converting it to an [`AsciiStr`] or panicking if it is not actually ASCII.
    #[cfg(test)]
    pub(crate) const fn assert(string: &str) -> AsciiStr<'_> {
        if string.is_ascii() {
            AsciiStr(string)
        } else {
            panic!("non-ASCII string passed to force_ascii");
        }
    }
}

impl<'string> TryFrom<&'string str> for AsciiStr<'string> {
    type Error = &'string str;

    fn try_from(value: &'string str) -> Result<Self, Self::Error> {
        if value.is_ascii() {
            Ok(Self(value))
        } else {
            Err(value)
        }
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for AsciiStr<'bytes> {
    type Error = &'bytes [u8];

    fn try_from(value: &'bytes [u8]) -> Result<Self, Self::Error> {
        if value.is_ascii() {
            let value_str = core::str::from_utf8(value).unwrap();
            Ok(Self(value_str))
        } else {
            Err(value)
        }
    }
}

// boilerplate impl, mostly for tests and also lets us #[derive(Debug)] for packet component structs
impl fmt::Debug for AsciiStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for AsciiStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
