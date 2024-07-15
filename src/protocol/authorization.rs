//! Authorization features/packets of the TACACS+ protocol.

use byteorder::{ByteOrder, NetworkEndian};
use getset::{CopyGetters, Getters};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use super::{
    Argument, Arguments, AuthenticationContext, AuthenticationMethod, DeserializeError,
    InvalidArgument, PacketBody, PacketType, Serialize, SerializeError, UserInformation,
};
use crate::FieldText;

#[cfg(test)]
mod tests;

/// An authorization request packet body, including arguments.
pub struct Request<'packet> {
    /// Method used to authenticate to TACACS+ client.
    method: AuthenticationMethod,

    /// Other client authentication information.
    authentication_context: AuthenticationContext,

    /// Information about the user connected to the TACACS+ client.
    user_information: UserInformation<'packet>,

    /// Additional arguments to provide as part of an authorization request.
    arguments: Arguments<'packet>,
}

impl<'packet> Request<'packet> {
    /// Assembles an authorization request packet from its fields.
    pub fn new(
        method: AuthenticationMethod,
        authentication_context: AuthenticationContext,
        user_information: UserInformation<'packet>,
        arguments: Arguments<'packet>,
    ) -> Self {
        Self {
            method,
            authentication_context,
            user_information,
            arguments,
        }
    }
}

impl PacketBody for Request<'_> {
    const TYPE: PacketType = PacketType::Authorization;

    // 4 extra bytes come from user information lengths (user, port, remote address) and argument count
    const REQUIRED_FIELDS_LENGTH: usize =
        AuthenticationMethod::WIRE_SIZE + AuthenticationContext::WIRE_SIZE + 4;
}

impl Serialize for Request<'_> {
    fn wire_size(&self) -> usize {
        AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.user_information.wire_size()
            + self.arguments.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.method as u8;
            self.authentication_context
                .serialize_header_information(&mut buffer[1..4]);
            self.user_information
                .serialize_header_information(&mut buffer[4..7])?;

            // the user information fields start after all of the required fields and also the argument lengths, the latter of which take up 1 byte each
            let user_info_start: usize =
                Self::REQUIRED_FIELDS_LENGTH + self.arguments.argument_count();

            let user_information_len = self
                .user_information
                .serialize_body_information(&mut buffer[user_info_start..]);

            // argument lengths start at index 7, just after the argument count
            let arguments_wire_len = self.arguments.serialize_count_and_lengths(&mut buffer[7..])?
                // argument values go after all of the user information
                + self
                    .arguments
                    .serialize_encoded_values(&mut buffer[user_info_start + user_information_len..])?;

            // NOTE: 1 is subtracted from REQUIRED_FIELDS_LENGTH since otherwise the argument count field is double counted (from Arguments::wire_size())
            Ok((Self::REQUIRED_FIELDS_LENGTH - 1) + user_information_len + arguments_wire_len)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

/// The status of an authorization operation, as returned by the server.
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy, TryFromPrimitive)]
pub enum Status {
    /// Authorization passed; server may have additional arguments for the client.
    PassAdd = 0x01,

    /// Authorization passed; server provides argument values to override those provided in the request.
    PassReplace = 0x02,

    /// Authorization request was denied.
    Fail = 0x10,

    /// An error ocurred on the server.
    Error = 0x11,

    /// Forward authorization request to an alternative daemon.
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC 8907."]
    Follow = 0x21,
}

impl Status {
    /// The wire size of an authorization reply status in bytes.
    pub const WIRE_SIZE: usize = 1;
}

#[doc(hidden)]
impl From<TryFromPrimitiveError<Status>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<Status>) -> Self {
        Self::InvalidStatus(value.number)
    }
}

/// Some information about the arguments in the binary representation of a reply packet.
#[derive(Debug)]
struct ArgumentsInfo<'raw> {
    argument_count: u8,
    argument_lengths: &'raw [u8],
    arguments_buffer: &'raw [u8],
}

/// The body of an authorization reply packet.
#[derive(Getters, CopyGetters, Debug)]
pub struct Reply<'packet> {
    /// Gets the status returned in an authorization exchange.
    #[getset(get = "pub")]
    status: Status,

    /// Gets the message sent by the server, to be displayed to the user.
    #[getset(get_copy = "pub")]
    server_message: FieldText<'packet>,

    /// Gets the administrative/log data returned from the server.
    #[getset(get_copy = "pub")]
    data: &'packet [u8],

    // this field not publicly exposed on purpose
    // (used for iterating over arguments)
    arguments_info: ArgumentsInfo<'packet>,
}

/// The non-argument field lengths of a (raw) authorization reply packet, as well as its total length.
struct ReplyFieldLengths {
    data_length: usize,
    server_message_length: usize,
    total_length: usize,
}

/// An iterator over the arguments in an authorization reply packet.
pub struct ArgumentsIterator<'iter> {
    arguments_info: &'iter ArgumentsInfo<'iter>,
    next_argument_number: usize,
    next_offset: usize,
}

impl<'iter> Iterator for ArgumentsIterator<'iter> {
    type Item = Argument<'iter>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_argument_number < self.arguments_info.argument_count as usize {
            let next_length =
                self.arguments_info.argument_lengths[self.next_argument_number] as usize;
            let raw_argument = &self.arguments_info.arguments_buffer
                [self.next_offset..self.next_offset + next_length];

            // update iterator state
            self.next_argument_number += 1;
            self.next_offset += next_length;

            // NOTE: this should always be Some, since the validity of arguments is checked in Reply's TryFrom impl
            Argument::deserialize(raw_argument).ok()
        } else {
            None
        }
    }

    // required for ExactSizeIterator impl
    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.arguments_info.argument_count as usize;
        // these are asserted to be equal in the default ExactSizeIterator::len() implementation
        (size, Some(size))
    }
}

// Gives ArgumentsIterator a .len() method
impl ExactSizeIterator for ArgumentsIterator<'_> {}

impl<'packet> Reply<'packet> {
    const ARGUMENT_LENGTHS_START: usize = 6;

    /// Determines the length of a reply packet encoded into the provided buffer, if possible.
    pub fn claimed_length(buffer: &[u8]) -> Result<usize, DeserializeError> {
        Self::extract_field_lengths(buffer).map(|lengths| lengths.total_length)
    }

    /// Extracts the server message and data lengths from a raw reply packet, if possible.
    fn extract_field_lengths(buffer: &[u8]) -> Result<ReplyFieldLengths, DeserializeError> {
        // data length is the last field in the required part of the header, so we need a full (minimal) header
        if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH {
            let argument_count = buffer[1] as usize;

            // also ensure that all argument lengths are present
            if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH + argument_count {
                let server_message_length = NetworkEndian::read_u16(&buffer[2..4]) as usize;
                let data_length = NetworkEndian::read_u16(&buffer[4..6]) as usize;

                let encoded_arguments_length: usize = buffer
                    [Self::ARGUMENT_LENGTHS_START..Self::ARGUMENT_LENGTHS_START + argument_count]
                    .iter()
                    .map(|&length| length as usize)
                    .sum();

                let total_length = Self::REQUIRED_FIELDS_LENGTH
                    + argument_count // argument lengths in "header"
                    + server_message_length
                    + data_length
                    + encoded_arguments_length;

                Ok(ReplyFieldLengths {
                    data_length,
                    server_message_length,
                    total_length,
                })
            } else {
                Err(DeserializeError::UnexpectedEnd)
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }

    /// Ensures a list of argument lengths and their raw values represent a valid set of arguments.
    fn ensure_arguments_valid(lengths: &[u8], values: &[u8]) -> Result<(), InvalidArgument> {
        let mut argument_start = 0;

        lengths.iter().try_fold((), |_, &length| {
            let raw_argument = &values[argument_start..argument_start + length as usize];
            argument_start += length as usize;

            // we don't care about the actual argument here, but the specific error should be kept
            Argument::deserialize(raw_argument).map(|_| ())
        })
    }

    /// Returns an iterator over the arguments included in this reply packet.
    pub fn iter_arguments(&self) -> ArgumentsIterator<'_> {
        ArgumentsIterator {
            arguments_info: &self.arguments_info,
            next_argument_number: 0,
            next_offset: 0,
        }
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authorization;

    // 1 byte for status, 1 byte for argument count, 2 bytes each for lengths of server message/data
    const REQUIRED_FIELDS_LENGTH: usize = Status::WIRE_SIZE + 1 + 4;
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let ReplyFieldLengths {
            data_length,
            server_message_length,
            total_length,
        } = Self::extract_field_lengths(buffer)?;

        if buffer.len() >= total_length {
            let status: Status = buffer[0].try_into()?;
            let argument_count = buffer[1];

            let body_start = Self::ARGUMENT_LENGTHS_START + argument_count as usize;
            let data_start = body_start + server_message_length;
            let arguments_start = data_start + data_length;

            let server_message = FieldText::try_from(&buffer[body_start..data_start])
                .map_err(|_| DeserializeError::InvalidWireBytes)?;
            let data = &buffer[data_start..arguments_start];

            // arguments occupy the rest of the buffer
            let argument_lengths = &buffer[Self::ARGUMENT_LENGTHS_START..body_start];
            let argument_values = &buffer[arguments_start..total_length];

            Self::ensure_arguments_valid(argument_lengths, argument_values)?;

            let arguments_info = ArgumentsInfo {
                argument_count,
                argument_lengths,
                arguments_buffer: argument_values,
            };

            Ok(Self {
                status,
                server_message,
                data,
                arguments_info,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
