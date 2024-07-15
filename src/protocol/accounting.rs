//! Accounting protocol packet (de)serialization.

use bitflags::bitflags;
use getset::{CopyGetters, Getters};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use super::{
    Arguments, AuthenticationContext, AuthenticationMethod, DeserializeError, PacketBody,
    PacketType, Serialize, SerializeError, UserInformation,
};
use crate::FieldText;

#[cfg(test)]
mod tests;

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
    pub const WIRE_SIZE: usize = 1;
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
            self.authentication
                .serialize_header_information(&mut buffer[2..5]);
            self.user_information
                .serialize_header_information(&mut buffer[5..8])?;

            let argument_count = self.arguments.argument_count();

            // body starts after the required fields & the argument lengths (1 byte per argument)
            let body_start = Self::REQUIRED_FIELDS_LENGTH + argument_count;

            // actual request content
            let user_information_len = self
                .user_information
                .serialize_body_information(&mut buffer[body_start..]);

            let arguments_serialized_len =
                // argument lengths start at index 8
                self.arguments.serialize_count_and_lengths(&mut buffer[8..])
                    // argument values go after the user information values in the body
                    + self
                        .arguments
                        .serialize_encoded_values(&mut buffer[body_start + user_information_len..]);

            // NOTE: as with authorization, 1 is subtracted from REQUIRED_FIELDS_LENGTH as the argument count would be double counted otherwise
            Ok(
                (Self::REQUIRED_FIELDS_LENGTH - 1)
                    + user_information_len
                    + arguments_serialized_len,
            )
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
    pub const WIRE_SIZE: usize = 1;
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
    data: &'packet [u8],
}

impl Reply<'_> {
    // TODO: merge claimed_length & extract_field lengths into single function, like that one other packet type
    /// Determines how long a raw reply packet claims to be, if applicable, based on various lengths stored in the body "header."
    pub fn claimed_length(buffer: &[u8]) -> Option<usize> {
        if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH {
            let (server_message_length, data_length) = Self::extract_field_lengths(buffer)?;
            Some(Self::REQUIRED_FIELDS_LENGTH + server_message_length + data_length)
        } else {
            None
        }
    }

    /// Extracts the server message and data field lengths from a buffer, treating it as if it were a serialized reply packet body.
    fn extract_field_lengths(buffer: &[u8]) -> Option<(usize, usize)> {
        if buffer.len() >= 4 {
            let server_message_length = u16::from_be_bytes(buffer[0..2].try_into().ok()?);
            let data_length = u16::from_be_bytes(buffer[2..4].try_into().ok()?);

            Some((server_message_length as usize, data_length as usize))
        } else {
            None
        }
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Accounting;

    // 4 extra bytes are 2 bytes each for lengths of server message/data
    const REQUIRED_FIELDS_LENGTH: usize = Status::WIRE_SIZE + 4;
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let claimed_body_length =
            Self::claimed_length(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

        // NOTE: the length returned by claimed_length() if non-None is guaranteed to be at least REQUIRED_FIELDS_LENGTH (5) so we can assume that here without explicitly checking it
        if buffer.len() >= claimed_body_length {
            let status: Status = buffer[4].try_into()?;

            let (server_message_length, data_length) =
                Self::extract_field_lengths(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

            let server_message_start = Self::REQUIRED_FIELDS_LENGTH;
            let data_start = server_message_start + server_message_length;

            let server_message = FieldText::try_from(&buffer[server_message_start..data_start])
                .map_err(|_| DeserializeError::InvalidWireBytes)?;
            let data = &buffer[data_start..data_start + data_length];

            Ok(Self {
                status,
                server_message,
                data,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
