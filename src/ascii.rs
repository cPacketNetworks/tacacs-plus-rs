use core::fmt;
use core::ops::Deref;

#[cfg(test)]
mod tests;

/// A wrapper for `&str` that is checked to be valid ASCII.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct AsciiStr<'string>(&'string str);

impl<'string> AsciiStr<'string> {
    /// Attempts to convert a `&str` to an `AsciiStr`.
    /// Returns `Some` if the string is indeed ASCII, and `None` otherwise.
    pub fn try_from_str(string: &'string str) -> Option<Self> {
        if string.is_ascii() {
            Some(Self(string))
        } else {
            None
        }
    }

    /// Attempts to convert a byte slice to an `AsciiStr`.
    /// Returns `Some` if the slice contains only ASCII codepoints, and `None` if not.
    pub fn try_from_bytes(bytes: &'string [u8]) -> Option<Self> {
        if bytes.is_ascii() {
            core::str::from_utf8(bytes).ok().map(Self)
        } else {
            None
        }
    }
}

/// Asserts a string is ASCII, converting it to an [`AsciiStr`] or panicking if it is not actually ASCII.
pub const fn assert_ascii(string: &str) -> AsciiStr {
    if string.is_ascii() {
        AsciiStr(string)
    } else {
        panic!("non-ASCII string passed to force_ascii");
    }
}

// deref coercion is really convenient :)
impl Deref for AsciiStr<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
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
