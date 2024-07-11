use core::fmt;
use core::iter::zip;

use crate::FieldText;

use super::DeserializeError;

#[cfg(test)]
mod tests;

/// An argument in the TACACS+ protocol, which exists for extensibility.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Argument<'data> {
    name: FieldText<'data>,
    value: FieldText<'data>,
    required: bool,
}

/// Error to determine
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidArgument {
    /// Argument had empty name.
    EmptyName,

    /// Argument name contained a delimiter (= or *).
    NameContainsDelimiter,

    /// Argument encoding did not contain a delimiter.
    NoDelimiter,

    /// Argument was too long to be encodeable.
    TooLong,

    /// Argument wasn't valid ASCII.
    NotAscii,
}

impl fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "arguments cannot have empty names"),
            Self::NameContainsDelimiter => write!(
                f,
                "names cannot contain value delimiter characters (= or *)"
            ),
            Self::NoDelimiter => write!(f, "encoded argument value had no delimiter"),
            Self::TooLong => write!(f, "the total length of an argument (name + length + delimiter) must not exceed u8::MAX, for encoding reasons"),
            Self::NotAscii => write!(f, "encoded argument value was not valid ASCII")
        }
    }
}

impl From<InvalidArgument> for DeserializeError {
    fn from(value: InvalidArgument) -> Self {
        Self::InvalidArgument(value)
    }
}

impl<'data> Argument<'data> {
    /// The delimiter used for a required argument.
    pub const REQUIRED_DELIMITER: char = '=';

    /// The delimiter used for an optional argument.
    pub const OPTIONAL_DELIMITER: char = '*';

    /// Constructs an argument, enforcing a maximum combined name + value + delimiter length of `u8::MAX` (as it must fit in a single byte).
    pub fn new(
        name: FieldText<'data>,
        value: FieldText<'data>,
        required: bool,
    ) -> Result<Self, InvalidArgument> {
        // NOTE: since both name/value are AsciiStrs, we don't have to check if they are ascii as in `check_encoding`

        if name.is_empty() {
            // name must be nonempty (?)
            Err(InvalidArgument::EmptyName)
        } else if name.contains_any(&[Self::REQUIRED_DELIMITER, Self::OPTIONAL_DELIMITER]) {
            // "An argument name MUST NOT contain either of the separators." [RFC 8907]
            Err(InvalidArgument::NameContainsDelimiter)
        } else if name.len() + value.len() >= u8::MAX as usize {
            // length of argument (including delimiter, which is reflected in using < rather than <=) must also fit in a u8 to be encodeable
            Err(InvalidArgument::TooLong)
        } else {
            Ok(Argument {
                name,
                value,
                required,
            })
        }
    }

    /// The encoded length of an argument, including the name/value/delimiter but not the byte holding its length earlier on in a packet.
    fn encoded_length(&self) -> u8 {
        // NOTE: this should never panic due to length checks in new()
        // length includes delimiter
        (self.name.len() + 1 + self.value.len()).try_into().unwrap()
    }

    /// Serializes an argument's name-value encoding, as done in the body of a packet.
    fn serialize(&self, buffer: &mut [u8]) {
        let name_len = self.name.len();
        buffer[..name_len].copy_from_slice(self.name.as_bytes());

        buffer[name_len] = if self.required {
            Self::REQUIRED_DELIMITER
        } else {
            Self::OPTIONAL_DELIMITER
        } as u8;

        // value goes just after delimiter
        let value_len = self.value.len();
        buffer[name_len + 1..name_len + 1 + value_len].copy_from_slice(self.value.as_bytes());
    }

    /// Checks whether a given byte slice is a valid argument encoding.
    ///
    /// See [RFC8907 section 6.1] for more information on argument encodings.
    ///
    /// [RFC8907 section 6.1]: https://www.rfc-editor.org/rfc/rfc8907.html#section-6.1-18
    pub(super) fn check_encoding(raw_argument: &[u8]) -> Result<(), InvalidArgument> {
        if u8::try_from(raw_argument.len()).is_err() {
            // length has to fit in a u8 to be encodeable
            Err(InvalidArgument::TooLong)
        } else if !(raw_argument.is_ascii() && raw_argument.iter().all(|c| !c.is_ascii_control())) {
            // arguments must be ASCII (and more specifically not ASCII control characters)
            Err(InvalidArgument::NotAscii)
        } else if !(raw_argument.contains(&(Self::REQUIRED_DELIMITER as u8))
            || raw_argument.contains(&(Self::OPTIONAL_DELIMITER as u8)))
        {
            // argument must contain a delimiter...
            Err(InvalidArgument::NoDelimiter)
        } else if raw_argument[0] == Self::REQUIRED_DELIMITER as u8
            || raw_argument[0] == Self::OPTIONAL_DELIMITER as u8
        {
            // ...but not start with one, since argument names must be nonempty (?)
            Err(InvalidArgument::EmptyName)
        } else {
            Ok(())
        }
    }

    /// Attempts to deserialize a packet from its name-value encoding on the wire.
    pub(super) fn deserialize(buffer: &'data [u8]) -> Result<Self, InvalidArgument> {
        // ensure encoding is valid before attempting to deserialize
        Self::check_encoding(buffer)?;

        // note: these are guaranteed to be unequal, since a single index cannot contain two characters at once
        let equals_index = buffer.iter().position(|c| *c == b'=');
        let star_index = buffer.iter().position(|c| *c == b'*');

        // determine first delimiter that appears, which is the actual delimiter as names MUST NOT (RFC 8907) contain either delimiter character
        // NOTE: the unwrap should never panic since the presence of a delimiter is checked
        let delimiter_index = match (equals_index, star_index) {
            (None, star) => star,
            (equals, None) => equals,
            (Some(equals), Some(star)) => Some(equals.min(star)),
        }
        .unwrap();

        // at this point, delimiter_index was non-None and must contain one of {*, =}
        let required = buffer[delimiter_index] == Self::REQUIRED_DELIMITER as u8;

        // NOTE: buffer is checked to be full ASCII above, so these unwraps should never panic
        let name = FieldText::try_from(&buffer[..delimiter_index]).unwrap();
        let value = FieldText::try_from(&buffer[delimiter_index + 1..]).unwrap();

        Ok(Self {
            name,
            value,
            required,
        })
    }
}

/// A set of arguments known to be of valid length for use in a TACACS+ packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arguments<'args>(&'args [Argument<'args>]);

impl<'args> Arguments<'args> {
    /// Constructs a new `Arguments`, returning `Some` if the provided slice has less than `u8::MAX` and None otherwise.
    pub fn new<T: AsRef<[Argument<'args>]>>(arguments: &'args T) -> Option<Self> {
        if u8::try_from(arguments.as_ref().len()).is_ok() {
            Some(Self(arguments.as_ref()))
        } else {
            None
        }
    }

    /// Returns the number of arguments an `Arguments` object contains.
    pub fn argument_count(&self) -> usize {
        self.0.len()
    }

    /// Returns the size of this set of arguments on the wire, including encoded values as well as lengths & the argument count.
    pub(super) fn wire_size(&self) -> usize {
        let argument_count = self.0.len();
        let argument_values_len: usize = self
            .0
            .iter()
            .map(|argument| argument.encoded_length() as usize)
            .sum();

        // number of arguments itself takes up extra byte when serializing
        1 + argument_count + argument_values_len
    }

    /// Serializes the argument count & lengths of the stored arguments into a buffer.
    #[must_use]
    pub(super) fn serialize_count_and_lengths(&self, buffer: &mut [u8]) -> usize {
        let argument_count = self.argument_count();

        // strict greater than to allow room for encoded argument count itself
        if buffer.len() > argument_count {
            // NOTE: checks in construction should prevent this unwrap from panicking
            buffer[0] = argument_count.try_into().unwrap();

            // fill in argument lengths after argument count
            for (position, argument) in zip(&mut buffer[1..1 + argument_count], self.0) {
                *position = argument.encoded_length();
            }

            // total bytes written: number of arguments + one extra byte for argument count itself
            1 + argument_count
        } else {
            0
        }
    }

    /// Serializes the stored arguments in their proper encoding to a buffer.
    #[must_use]
    pub(super) fn serialize_encoded_values(&self, buffer: &mut [u8]) -> usize {
        let full_encoded_length = self
            .0
            .iter()
            .map(|argument| argument.encoded_length() as usize)
            .sum();

        if buffer.len() >= full_encoded_length {
            let mut argument_start = 0;
            let mut total_written = 0;

            for argument in self.0.iter() {
                let argument_length = argument.encoded_length() as usize;
                let next_argument_start = argument_start + argument_length;
                argument.serialize(&mut buffer[argument_start..next_argument_start]);

                // update loop state
                argument_start = next_argument_start;

                // this is technically redundant with the initial full_encoded_length calculation above
                // but better to be safe than sorry right?
                total_written += argument_length;
            }

            total_written
        } else {
            0
        }
    }
}

impl<'args> AsRef<[Argument<'args>]> for Arguments<'args> {
    fn as_ref(&self) -> &[Argument<'args>] {
        self.0
    }
}
