//! Accounting protocol packet (de)serialization.

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use getset::{CopyGetters, Getters};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use super::{
    Arguments, AuthenticationContext, AuthenticationMethod, Deserialize, DeserializeError,
    PacketBody, PacketType, Serialize, SerializeError, UserInformation,
};
use crate::FieldText;

#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
mod owned;

#[cfg(feature = "std")]
pub use owned::ReplyOwned;

bitflags! {
    /// Raw bitflags for accounting request packet.
    struct RawFlags: u8 {
        const START    = 0b00000010;
        const STOP     = 0b00000100;
        const WATCHDOG = 0b00001000;
    }
}

/// Valid flag combinations for a TACACS+ account REQUEST packet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flags {
    /// Start of a task.
    StartRecord,

    /// Task complete.
    StopRecord,

    /// Indication that task is still running, with no extra arguments.
    WatchdogNoUpdate,

    /// Update on long-running task, including updated/new argument values.
    WatchdogUpdate,
}

impl From<Flags> for RawFlags {
    fn from(value: Flags) -> Self {
        match value {
            Flags::StartRecord => RawFlags::START,
            Flags::StopRecord => RawFlags::STOP,
            Flags::WatchdogNoUpdate => RawFlags::WATCHDOG,
            Flags::WatchdogUpdate => RawFlags::WATCHDOG | RawFlags::START,
        }
    }
}

impl Flags {
    /// The number of bytes occupied by a flag set on the wire.
    pub(super) const WIRE_SIZE: usize = 1;
}

/// An accounting request packet, used to start, stop, or provide progress on a running job.
pub struct Request<'packet> {
    /// Flags to indicate what kind of accounting record this packet includes.
    flags: Flags,

    /// Method used to authenticate to TACACS+ client.
    authentication_method: AuthenticationMethod,

    /// Other information about authentication to TACACS+ client.
    authentication: AuthenticationContext,

    /// Information about the user connected to the client.
    user_information: UserInformation<'packet>,

    /// Arguments to provide additional information to the server.
    arguments: Arguments<'packet>,
}

impl<'packet> Request<'packet> {
    /// Argument lengths in a request packet start at index 9, if present.
    const ARGUMENT_LENGTHS_OFFSET: usize = 9;

    /// Assembles a new accounting request packet body.
    pub fn new(
        flags: Flags,
        authentication_method: AuthenticationMethod,
        authentication: AuthenticationContext,
        user_information: UserInformation<'packet>,
        arguments: Arguments<'packet>,
    ) -> Self {
        Self {
            flags,
            authentication_method,
            authentication,
            user_information,
            arguments,
        }
    }
}

impl PacketBody for Request<'_> {
    const TYPE: PacketType = PacketType::Accounting;

    // 4 extra bytes come from user information lengths (user, port, remote address) & argument count
    const REQUIRED_FIELDS_LENGTH: usize =
        Flags::WIRE_SIZE + AuthenticationMethod::WIRE_SIZE + AuthenticationContext::WIRE_SIZE + 4;
}

impl Serialize for Request<'_> {
    fn wire_size(&self) -> usize {
        Flags::WIRE_SIZE
            + AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.user_information.wire_size()
            + self.arguments.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let wire_size = self.wire_size();

        if buffer.len() >= wire_size {
            buffer[0] = RawFlags::from(self.flags).bits();
            buffer[1] = self.authentication_method as u8;

            // header information (lengths, etc.)
            self.authentication.serialize(&mut buffer[2..5]);
            self.user_information
                .serialize_field_lengths(&mut buffer[5..8])?;

            let argument_count = self.arguments.argument_count() as usize;

            // body starts after the required fields & the argument lengths (1 byte per argument)
            let body_start = Self::ARGUMENT_LENGTHS_OFFSET + argument_count;

            // actual request content
            // as below, slice bounds are capped to end of packet body to avoid overflowing
            let user_information_len = self
                .user_information
                .serialize_field_values(&mut buffer[body_start..wire_size])?;

            let arguments_serialized_len =
                // argument lengths start at index 8
                // extra byte is included in slice for argument count itself
                self.arguments.serialize_count_and_lengths(&mut buffer[8..8 + argument_count + 1])?
                    // argument values go after the user information values in the body
                    + self
                        .arguments
                        .serialize_encoded_values(&mut buffer[body_start + user_information_len..wire_size])?;

            // NOTE: as with authorization, 1 is subtracted from REQUIRED_FIELDS_LENGTH as the argument count would be double counted otherwise
            let actual_written_len = (Self::REQUIRED_FIELDS_LENGTH - 1)
                + user_information_len
                + arguments_serialized_len;

            // ensure expected/actual sizes match
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

/// The server's reply status in an accounting session.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
pub enum Status {
    /// Task logging succeeded.
    Success = 0x01,

    /// Something went wrong when logging the task.
    Error = 0x02,

    /// Forward accounting request to an alternative daemon.
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC-8907."]
    Follow = 0x21,
}

impl Status {
    /// The number of bytes an accounting reply status occupies on the wire.
    pub(super) const WIRE_SIZE: usize = 1;
}

#[doc(hidden)]
impl From<TryFromPrimitiveError<Status>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<Status>) -> Self {
        Self::InvalidStatus(value.number)
    }
}

/// An accounting reply packet received from a TACACS+ server.
#[derive(PartialEq, Eq, Debug, Getters, CopyGetters)]
pub struct Reply<'packet> {
    /// Gets the status of an accounting reply.
    #[getset(get = "pub")]
    status: Status,

    /// Gets the server message, which may be presented to a user connected to a client.
    #[getset(get_copy = "pub")]
    server_message: FieldText<'packet>,

    /// Gets the administrative/log data received from the server.
    #[getset(get_copy = "pub")]
    data: FieldText<'packet>,
}

/// Field lengths of a reply packet as well as the total length.
struct ReplyFieldLengths {
    server_message_length: u16,
    data_length: u16,
    total_length: u32,
}

impl Reply<'_> {
    /// Offset of the server message in an accounting reply packet body, if present.
    const SERVER_MESSAGE_OFFSET: usize = 5;

    /// Determines how long a raw reply packet is, if applicable, based on various lengths stored in the body "header."
    pub fn extract_total_length(buffer: &[u8]) -> Result<u32, DeserializeError> {
        if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH {
            Self::extract_field_lengths(buffer).map(|lengths| lengths.total_length)
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }

    /// Extracts the server message and data field lengths from a buffer, treating it as if it were a serialized reply packet body.
    fn extract_field_lengths(buffer: &[u8]) -> Result<ReplyFieldLengths, DeserializeError> {
        // ensure buffer is large enough to comprise a valid reply packet
        if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH {
            // server message length is at the beginning of the packet
            let server_message_length = NetworkEndian::read_u16(&buffer[..2]);

            // data length is just after the server message length
            let data_length = NetworkEndian::read_u16(&buffer[2..4]);

            // full packet has required fields/lengths as well as the field values themselves
            // SAFETY: REQUIRED_FIELDS_LENGTH is guaranteed to fit in a u32 based on its defined value
            let total_length = u32::try_from(Self::REQUIRED_FIELDS_LENGTH).unwrap()
                + u32::from(server_message_length)
                + u32::from(data_length);

            Ok(ReplyFieldLengths {
                server_message_length,
                data_length,
                total_length,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Accounting;

    // 4 extra bytes are 2 bytes each for lengths of server message/data
    const REQUIRED_FIELDS_LENGTH: usize = Status::WIRE_SIZE + 4;
}

// hide in docs, since this isn't meant to be used externally
#[doc(hidden)]
impl<'raw> Deserialize<'raw> for Reply<'raw> {
    fn deserialize_from_buffer(buffer: &'raw [u8]) -> Result<Self, DeserializeError> {
        let extracted_lengths = Self::extract_field_lengths(buffer)?;

        // the provided buffer is sliced to the length reported in the packet header in Packet::deserialize_body(),
        // so we can compare against it this way
        let length_from_header = buffer.len();

        // ensure buffer length & calculated length from body fields match
        if extracted_lengths.total_length as usize == length_from_header {
            // SAFETY: extract_field_lengths() performs a check against REQUIRED_FIELDS_LENGTH (5), so this will not panic
            let status = Status::try_from(buffer[4])?;

            let data_offset =
                Self::SERVER_MESSAGE_OFFSET + extracted_lengths.server_message_length as usize;

            let server_message =
                FieldText::try_from(&buffer[Self::SERVER_MESSAGE_OFFSET..data_offset])
                    .map_err(|_| DeserializeError::BadText)?;
            let data = FieldText::try_from(
                &buffer[data_offset..data_offset + extracted_lengths.data_length as usize],
            )
            .map_err(|_| DeserializeError::BadText)?;

            Ok(Self {
                status,
                server_message,
                data,
            })
        } else {
            Err(DeserializeError::WrongBodyBufferSize {
                expected: extracted_lengths.total_length as usize,
                buffer_size: length_from_header,
            })
        }
    }
}
