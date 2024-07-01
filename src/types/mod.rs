use core::fmt;
use core::ops::Deref;

// TODO: placement
#[cfg(test)]
pub(crate) fn force_ascii(value: &str) -> AsciiStr {
    value.try_into().expect("ASCII conversion failed")
}

#[cfg(test)]
mod tests;

// TODO: Error impl? experimental in core though
#[derive(Debug)]
pub struct InvalidAscii(());

// TODO: store &str, str, or &[u8]/[u8]?
/// A wrapper for strs that are guaranteed to be valid ASCII.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct AsciiStr<'string>(&'string str);

impl<'bytes> TryFrom<&'bytes [u8]> for AsciiStr<'bytes> {
    type Error = InvalidAscii;

    fn try_from(value: &'bytes [u8]) -> Result<Self, Self::Error> {
        if value.is_ascii() {
            if let Ok(string) = core::str::from_utf8(value) {
                Ok(Self(string))
            } else {
                Err(InvalidAscii(()))
            }
        } else {
            Err(InvalidAscii(()))
        }
    }
}

impl<'string> TryFrom<&'string str> for AsciiStr<'string> {
    type Error = InvalidAscii;

    fn try_from(value: &'string str) -> Result<Self, Self::Error> {
        if value.is_ascii() {
            Ok(Self(value))
        } else {
            Err(InvalidAscii(()))
        }
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
