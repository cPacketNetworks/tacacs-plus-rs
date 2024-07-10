use std::error::Error;
use std::fmt;

use super::{DeserializeError, NotEnoughSpace};

impl fmt::Display for NotEnoughSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not enough space in buffer")
    }
}

impl Error for NotEnoughSpace {}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidWireBytes => "Invalid byte representation of object",
            Self::UnexpectedEnd => "Unexpected end of buffer when deserializing object",
            Self::NotEnoughSpace => "Not enough space in provided buffer",
            Self::VersionMismatch => {
                "Mismatch in protocol version & authentication protocol specified"
            }
        };

        write!(f, "{}", message)
    }
}

impl Error for DeserializeError {}
