use core::fmt;
use core::iter::zip;

use getset::{CopyGetters, Getters, Setters};

use super::{DeserializeError, SerializeError};
use crate::FieldText;

#[cfg(test)]
mod tests;

/// An argument in the TACACS+ protocol, which exists for extensibility.
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash, Getters, CopyGetters, Setters)]
#[getset(set = "pub")]
pub struct Argument<'data> {
    /// The name of the argument.
    #[getset(get = "pub")]
    name: FieldText<'data>,

    /// The value of the argument.
    #[getset(get = "pub")]
    value: FieldText<'data>,

    /// Whether processing this argument is mandatory.
    #[getset(get_copy = "pub")]
    mandatory: bool,
}

impl fmt::Display for Argument<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // just write as encoded form (name + delimiter + value)
        write!(f, "{}{}{}", self.name, self.delimiter(), self.value)
    }
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

    /// Argument wasn't valid printable ASCII, as specified in [RFC8907 section 3.7].
    ///
    /// [RFC8907 section 3.7]: https://www.rfc-editor.org/rfc/rfc8907.html#section-6.1-18
    BadText,
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
            Self::BadText => write!(f, "encoded argument value was not printable ASCII")
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
    const MANDATORY_DELIMITER: char = '=';

    /// The delimiter used for an optional argument.
    const OPTIONAL_DELIMITER: char = '*';

    /// Constructs an argument, enforcing a maximum combined name + value + delimiter length of `u8::MAX` (as it must fit in a single byte for encoding reasons).
    pub fn new(
        name: FieldText<'data>,
        value: FieldText<'data>,
        mandatory: bool,
    ) -> Result<Self, InvalidArgument> {
        // NOTE: since both name/value are already `FieldText`s, we don't have to check if they are ASCII

        if name.is_empty() {
            // name must be nonempty (?)
            Err(InvalidArgument::EmptyName)
        } else if name.contains_any(&[Self::MANDATORY_DELIMITER, Self::OPTIONAL_DELIMITER]) {
            // "An argument name MUST NOT contain either of the separators." [RFC 8907]
            Err(InvalidArgument::NameContainsDelimiter)
        } else if u8::try_from(name.len() + 1 + value.len()).is_err() {
            // length of encoded argument (i.e., including delimiter) must also fit in a u8 to be encodeable
            Err(InvalidArgument::TooLong)
        } else {
            Ok(Argument {
                name,
                value,
                mandatory,
            })
        }
    }

    /// Converts this `Argument` to one which owns its fields.
    #[cfg(feature = "std")]
    pub fn into_owned<'out>(self) -> Argument<'out> {
        Argument {
            name: self.name.into_owned(),
            value: self.value.into_owned(),
            mandatory: self.mandatory,
        }
    }

    /// The encoded length of an argument, including the name/value/delimiter but not the byte holding its length earlier on in a packet.
    fn encoded_length(&self) -> u8 {
        // SAFETY: this should never panic due to length checks in new()
        // length includes delimiter
        (self.name.len() + 1 + self.value.len()).try_into().unwrap()
    }

    /// Serializes an argument's name-value encoding, as done in the body of a packet.
    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let name_len = self.name.len();
        let value_len = self.value.len();

        // delimiter is placed just after name, meaning its index is exactly the name length
        let delimiter_index = name_len;

        // name + value + 1 extra byte for delimiter
        let encoded_len = name_len + 1 + value_len;

        // buffer must be large enough to hold name, value, and delimiter
        if buffer.len() >= encoded_len {
            buffer[..delimiter_index].copy_from_slice(self.name.as_bytes());

            // choose delimiter based on whether argument is required
            buffer[delimiter_index] = self.delimiter() as u8;

            // value goes just after delimiter
            buffer[delimiter_index + 1..encoded_len].copy_from_slice(self.value.as_bytes());

            Ok(encoded_len)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }

    /// Returns the delimiter that will be used for this argument when it's encoded on the wire,
    /// based on whether it's mandatory or not.
    fn delimiter(&self) -> char {
        if self.mandatory {
            Self::MANDATORY_DELIMITER
        } else {
            Self::OPTIONAL_DELIMITER
        }
    }

    /// Attempts to deserialize a packet from its name-value encoding on the wire.
    pub(super) fn deserialize(buffer: &'data [u8]) -> Result<Self, InvalidArgument> {
        // note: these are guaranteed to be unequal, since a single index cannot contain two characters at once
        let equals_index = buffer.iter().position(|c| *c == b'=');
        let star_index = buffer.iter().position(|c| *c == b'*');

        // determine first delimiter that appears, which is the actual delimiter as names MUST NOT (RFC 8907) contain either delimiter character
        let delimiter_index = match (equals_index, star_index) {
            (None, star) => star,
            (equals, None) => equals,
            (Some(equals), Some(star)) => Some(equals.min(star)),
        }
        .ok_or(InvalidArgument::NoDelimiter)?;

        // at this point, delimiter_index was non-None and must contain one of {*, =}
        let required = buffer[delimiter_index] == Self::MANDATORY_DELIMITER as u8;

        // ensure name/value are valid text values per RFC 8907 (i.e., fully printable ASCII)
        let name = FieldText::try_from(&buffer[..delimiter_index])
            .map_err(|_| InvalidArgument::BadText)?;
        let value = FieldText::try_from(&buffer[delimiter_index + 1..])
            .map_err(|_| InvalidArgument::BadText)?;

        // use constructor here to perform checks on fields to avoid diverging code paths
        Self::new(name, value, required)
    }
}

/// A set of arguments known to be of valid length for use in a TACACS+ packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Arguments<'args>(&'args [Argument<'args>]);

impl<'args> Arguments<'args> {
    /// Constructs a new `Arguments`, returning `Some` if the provided slice has less than `u8::MAX` and None otherwise.
    ///
    /// The `u8::MAX` restriction is due to the argument count being required to fit into a single byte when encoding.
    pub fn new<T: AsRef<[Argument<'args>]>>(arguments: &'args T) -> Option<Self> {
        if u8::try_from(arguments.as_ref().len()).is_ok() {
            Some(Self(arguments.as_ref()))
        } else {
            None
        }
    }

    /// Returns the number of arguments an `Arguments` object contains.
    pub fn argument_count(&self) -> u8 {
        // SAFETY: this should not panic as the argument count is verified to fit in a u8 in the constructor
        self.0.len().try_into().unwrap()
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
    pub(super) fn serialize_count_and_lengths(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, SerializeError> {
        let argument_count = self.argument_count();

        // strict greater than to allow room for encoded argument count itself
        if buffer.len() > argument_count as usize {
            buffer[0] = argument_count;

            // fill in argument lengths after argument count
            for (position, argument) in zip(&mut buffer[1..1 + argument_count as usize], self.0) {
                *position = argument.encoded_length();
            }

            // total bytes written: number of arguments + one extra byte for argument count itself
            Ok(1 + argument_count as usize)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }

    /// Serializes the stored arguments in their proper encoding to a buffer.
    pub(super) fn serialize_encoded_values(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, SerializeError> {
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
                let written_length =
                    argument.serialize(&mut buffer[argument_start..next_argument_start])?;

                // update loop state
                argument_start = next_argument_start;

                // this is technically redundant with the initial full_encoded_length calculation above
                // but better to be safe than sorry right?
                total_written += written_length;
            }

            // this case shouldn't happen since argument serialization is basically just direct slice copying
            // but on the off chance that it does this makes it easier to debug
            if total_written != full_encoded_length {
                Err(SerializeError::LengthMismatch {
                    expected: full_encoded_length,
                    actual: total_written,
                })
            } else {
                Ok(total_written)
            }
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

impl<'args> AsRef<[Argument<'args>]> for Arguments<'args> {
    fn as_ref(&self) -> &[Argument<'args>] {
        self.0
    }
}
