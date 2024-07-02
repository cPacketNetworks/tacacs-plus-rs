use core::ops::{Deref, DerefMut};
use tinyvec::SliceVec;

use super::{DeserializeError, NotEnoughSpace};
use crate::AsciiStr;

/// An argument in the TACACS+ protocol, which has various uses.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Argument<'data> {
    name: AsciiStr<'data>,
    value: AsciiStr<'data>,
    required: bool,
}

impl<'data> Argument<'data> {
    /// Constructs an argument, enforcing a maximum combined name + value + delimiter length of `u8::MAX` (as it must fit in a single byte).
    pub fn new(name: AsciiStr<'data>, value: AsciiStr<'data>, required: bool) -> Option<Self> {
        // "An argument name MUST NOT contain either of the separators." [RFC 8907]
        // length of argument (including delimiter, which is reflected in using < rather than <=) must also fit in a u8
        if !name.contains(|c| c == '=' || c == '*') && name.len() + value.len() < u8::MAX as usize {
            Some(Argument {
                name,
                value,
                required,
            })
        } else {
            None
        }
    }

    /// The encoded length of an argument, including the name/value/delimiter but not the byte holding its length earlier on in a packet.
    fn encoded_length(&self) -> usize {
        // length includes delimiter
        self.name.len() + 1 + self.value.len()
    }

    /// Serializes an argument's name-value encoding, as done in the body of a packet.
    fn serialize_name_value(&self, buffer: &mut [u8]) {
        let name_len = self.name.len();
        buffer[..name_len].copy_from_slice(self.name.as_bytes());

        buffer[name_len] = if self.required { '=' } else { '*' } as u8;

        let value_len = self.value.len();
        buffer[name_len + 1..name_len + 1 + value_len].copy_from_slice(self.value.as_bytes());
    }

    // TODO: visibility
    /// Attempts to deserialize a packet from its name-value encoding on the wire.
    pub(super) fn deserialize(buffer: &'data [u8]) -> Option<Self> {
        // note: these are guaranteed to be unequal
        let equals_index = buffer.iter().position(|c| *c == b'=');
        let star_index = buffer.iter().position(|c| *c == b'*');

        // determine first delimiter that appears, which is the actual delimiter as names MUST NOT (RFC 8907) contain either delimiter character
        let delimiter_index = match (equals_index, star_index) {
            (None, star) => star,
            (equals, None) => equals,
            (Some(equals), Some(star)) => Some(core::cmp::min(equals, star)),
        }?;

        // at this point, delimiter_index was non-None and must contain one of {*, =}
        let required = buffer[delimiter_index] == b'=';

        let name = AsciiStr::try_from(&buffer[..delimiter_index]).ok()?;
        let value = AsciiStr::try_from(&buffer[delimiter_index + 1..]).ok()?;

        Some(Self {
            name,
            value,
            required,
        })
    }
}

// TODO: mention somewhere that duplicate arguments won't be handled/will be passed as-is
// TODO: deserialize logic here instead of wherever it is now?
/// A set of arguments, with some validation of length requirements and such.
#[derive(PartialEq, Eq, Debug)]
pub struct Arguments<'storage>(SliceVec<'storage, Argument<'storage>>);

impl<'storage> Arguments<'storage> {
    /// Attempts to convert a full mutable Argument slice to an Arguments object.
    /// Succeeds if the length of the provided slice is less than `u8::MAX`.
    pub fn try_from_full_slice(storage: &'storage mut [Argument<'storage>]) -> Option<Self> {
        Self::try_from_slice_len(storage, storage.len())
    }

    /// Attempts to construct an Arguments object from a mutable Argument slice with some amount of existing parameters.
    /// The backing storage should be of length of at most `u8::MAX`, the maximum number of arguments supported in the TACACS+ protocol due to how they are represented into packets.
    pub fn try_from_slice_len(
        storage: &'storage mut [Argument<'storage>],
        length: usize,
    ) -> Option<Self> {
        // TODO: should this be enforced in overridden {try_,}push() impls instead?
        if storage.len() <= u8::MAX as usize {
            SliceVec::try_from_slice_len(storage, length).map(Self)
        } else {
            None
        }
    }

    /// The total size in bytes that the current set of arguments would occupy, including encoded argument values and their lengths.
    pub fn wire_size(&self) -> usize {
        // minimum length is 1 octet (argument count)
        self.0.iter().fold(1, |total, argument| {
            // 1 extra octet for storing encoded length
            total + 1 + argument.encoded_length()
        })
    }

    /// The current number of arguments, expressed as a u8.
    pub fn argument_count(&self) -> u8 {
        self.0.len() as u8
    }

    /// Serializes the argument count and respective lengths, as stored in the "header" of a packet body.
    pub(super) fn serialize_header(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        let argument_count = self.argument_count();

        // just check for header space; body check happens in serialize_body()
        if buffer.len() > argument_count as usize {
            buffer[0] = argument_count;

            let mut length_index = 1;
            for argument in self.0.iter() {
                // length is guaranteed to fit in a u8 based on checks in try_from_slice_len()
                buffer[length_index] = argument.encoded_length() as u8;
                length_index += 1;
            }

            Ok(())
        } else {
            Err(NotEnoughSpace(()))
        }
    }

    /// Serializes the name-value encodings of the stored arguments to a buffer.
    pub(super) fn serialize_body(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        let full_encoded_length = self.0.iter().map(Argument::encoded_length).sum();

        if buffer.len() >= full_encoded_length {
            let mut argument_start = 0;

            for argument in self.0.iter() {
                let argument_length = argument.encoded_length();
                argument.serialize_name_value(&mut buffer[argument_start..]);
                argument_start += argument_length;
            }
            Ok(())
        } else {
            Err(NotEnoughSpace(()))
        }
    }

    /// Deserializes arguments from their name-value-length encodings on the wire.
    pub(super) fn deserialize(
        lengths: &[u8],
        values: &'storage [u8],
        storage: &'storage mut [Argument<'storage>],
    ) -> Result<Self, DeserializeError> {
        if storage.len() >= lengths.len() {
            // TODO: error type?
            let mut arguments =
                Self::try_from_slice_len(storage, 0).ok_or(DeserializeError::NotEnoughSpace)?;

            let mut argument_start = 0;
            for &length in lengths {
                let next_argument_start = argument_start + length as usize;

                let raw_argument = &values[argument_start..next_argument_start];
                let parsed_argument = Argument::deserialize(raw_argument)
                    .ok_or(DeserializeError::InvalidWireBytes)?;

                // length is checked above so we can do the unchecked push safely
                arguments.push(parsed_argument);

                argument_start = next_argument_start;
            }

            Ok(arguments)
        } else {
            Err(DeserializeError::NotEnoughSpace)
        }
    }
}

// Convenience implementations to provide access to SliceVec methods on Arguments objects.
impl<'storage> Deref for Arguments<'storage> {
    type Target = SliceVec<'storage, Argument<'storage>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Arguments<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
