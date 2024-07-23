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

#[cfg(feature = "std")]
pub(crate) mod owned;

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
        let wire_size = self.wire_size();

        if buffer.len() >= wire_size {
            buffer[0] = self.method as u8;
            self.authentication_context.serialize(&mut buffer[1..4]);
            self.user_information
                .serialize_field_lengths(&mut buffer[4..7])?;

            let argument_count = self.arguments.argument_count() as usize;

            // the user information fields start after all of the required fields and also the argument lengths, the latter of which take up 1 byte each
            let user_info_start = Self::REQUIRED_FIELDS_LENGTH + argument_count;

            // cap slice with wire slice to avoid overflowing beyond end of packet body
            let user_info_written_len = self
                .user_information
                .serialize_field_values(&mut buffer[user_info_start..wire_size])?;

            // argument lengths start at index 7, just after the argument count
            // extra 1 added to allow room for argument count itself
            let arguments_wire_len = self.arguments.serialize_count_and_lengths(&mut buffer[7..7 + argument_count + 1])?
                // argument values go after all of the user information, and until the end of the packet
                + self
                    .arguments
                    .serialize_encoded_values(&mut buffer[user_info_start + user_info_written_len..wire_size])?;

            // NOTE: 1 is subtracted from REQUIRED_FIELDS_LENGTH since otherwise the argument count field is double counted (from Arguments::wire_size())
            let actual_written_len =
                (Self::REQUIRED_FIELDS_LENGTH - 1) + user_info_written_len + arguments_wire_len;

            if actual_written_len == wire_size {
                Ok(actual_written_len)
            } else {
                Err(SerializeError::LengthMismatch {
                    expected: wire_size,
                    actual: actual_written_len,
                })
            }
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
    const WIRE_SIZE: usize = 1;
}

// Implementation detail for num_enum, which is why it's hidden
#[doc(hidden)]
impl From<TryFromPrimitiveError<Status>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<Status>) -> Self {
        Self::InvalidStatus(value.number)
    }
}

/// Information about a reply packet's arguments.
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

    /// Gets the administrative log message returned from the server.
    #[getset(get_copy = "pub")]
    data: FieldText<'packet>,

    // this field not publicly exposed on purpose
    // (used for iterating over arguments)
    arguments_info: ArgumentsInfo<'packet>,
}

/// The non-argument field lengths of a (raw) authorization reply packet, as well as its total length.
struct ReplyFieldLengths {
    data_length: u16,
    server_message_length: u16,
    total_length: u32,
}

/// An iterator over the arguments in an authorization reply packet.
pub struct ArgumentsIterator<'iter> {
    /// Argument information, including argument count.
    arguments_info: &'iter ArgumentsInfo<'iter>,

    /// Position of the next argument, as if into a zero-indexed array of complete arguments.
    next_argument_number: usize,

    /// Offset of an argument within the buffer.
    next_offset: usize,
}

impl<'iter> Iterator for ArgumentsIterator<'iter> {
    type Item = Argument<'iter>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_argument_number < self.arguments_info.argument_count as usize {
            // get encoded argument from buffer based on stored offset into buffer/length
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
        let total_size = self.arguments_info.argument_count as usize;
        let remaining_size = total_size - self.next_argument_number;

        // these are asserted to be equal in the default ExactSizeIterator::len() implementation
        (remaining_size, Some(remaining_size))
    }
}

// Gives ArgumentsIterator a .len() method
impl ExactSizeIterator for ArgumentsIterator<'_> {}

impl<'packet> Reply<'packet> {
    const ARGUMENT_LENGTHS_START: usize = 6;

    /// Determines the length of a reply packet based on encoded lengths at the beginning of the packet body, if possible.
    pub fn extract_total_length(buffer: &[u8]) -> Result<u32, DeserializeError> {
        Self::extract_field_lengths(buffer).map(|lengths| lengths.total_length)
    }

    /// Extracts the server message and data lengths from a raw reply packet, if possible.
    fn extract_field_lengths(buffer: &[u8]) -> Result<ReplyFieldLengths, DeserializeError> {
        // data length is the last field in the required part of the header, so we need a full (minimal) header
        if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH {
            let argument_count = buffer[1];

            // also ensure that all argument lengths are present
            if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH + argument_count as usize {
                let server_message_length = NetworkEndian::read_u16(&buffer[2..4]);
                let data_length = NetworkEndian::read_u16(&buffer[4..6]);

                let encoded_arguments_length: u32 = buffer[Self::ARGUMENT_LENGTHS_START
                    ..Self::ARGUMENT_LENGTHS_START + argument_count as usize]
                    .iter()
                    .map(|&length| u32::from(length))
                    .sum();

                // SAFETY: REQUIRED_FIELDS_LENGTH is guaranteed to fit in a u32 by how it's defined
                let total_length = u32::try_from(Self::REQUIRED_FIELDS_LENGTH).unwrap()
                    + u32::from(argument_count) // argument lengths in "header"
                    + u32::from(server_message_length)
                    + u32::from(data_length)
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

// Hidden from docs as this is not meant for external use
#[doc(hidden)]
impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let ReplyFieldLengths {
            data_length,
            server_message_length,
            total_length,
        } = Self::extract_field_lengths(buffer)?;

        // buffer argument is sliced to proper length in Packet::deserialize_body(), so we can compare against that header length indirectly like this
        let length_from_header = buffer.len();

        if total_length as usize == length_from_header {
            let status = Status::try_from(buffer[0])?;
            let argument_count = buffer[1];

            // figure out field offsets
            let body_start = Self::ARGUMENT_LENGTHS_START + argument_count as usize;
            let data_start = body_start + server_message_length as usize;
            let arguments_start = data_start + data_length as usize;

            let server_message = FieldText::try_from(&buffer[body_start..data_start])
                .map_err(|_| DeserializeError::BadText)?;
            let data = FieldText::try_from(&buffer[data_start..arguments_start])
                .map_err(|_| DeserializeError::BadText)?;

            // arguments occupy the rest of the buffer
            let argument_lengths = &buffer[Self::ARGUMENT_LENGTHS_START..body_start];
            let argument_values = &buffer[arguments_start..total_length as usize];

            Self::ensure_arguments_valid(argument_lengths, argument_values)?;

            // bundle some information about arguments for iterator purposes
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
            Err(DeserializeError::WrongBodyBufferSize {
                expected: total_length as usize,
                buffer_size: length_from_header,
            })
        }
    }
}
