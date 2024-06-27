// FIXME: make stuff actually compile when no_std lol
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;
use core::ops::Deref;

mod protocol;
mod session;

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug)]
pub enum TacacsError {
    #[error("Connection to TACACS+ server failed")]
    ConnectionError,

    #[error("The TACACS+ server sent an invalid or corrupt response")]
    BadResponse,

    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

// TODO: placement (maybe dedicated module?)
pub struct AsciiStr<'string>(&'string str);

// TODO: placement
#[cfg(test)]
fn force_ascii(value: &str) -> AsciiStr {
    value.try_into().expect("ASCII conversion failed")
}

// TODO: Error impl? experimental in core though
#[derive(Debug)]
pub struct InvalidAscii;

impl<'string> TryFrom<&'string str> for AsciiStr<'string> {
    type Error = InvalidAscii;

    fn try_from(value: &'string str) -> Result<Self, Self::Error> {
        if value.is_ascii() {
            Ok(Self(value))
        } else {
            Err(InvalidAscii)
        }
    }
}

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
