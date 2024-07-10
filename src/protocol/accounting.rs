//! Accounting protocol packet (de)serialization.

use bitflags::bitflags;

use super::{
    Arguments, AuthenticationContext, AuthenticationMethod, DeserializeError, NotEnoughSpace,
    PacketBody, PacketType, Serialize, UserInformation,
};
use crate::AsciiStr;

#[cfg(test)]
mod tests;

bitflags! {
    /// Raw bitflags for accounting request packet.
    struct RawFlags: u8 {
        const Start    = 0b00000010;
        const Stop     = 0b00000100;
        const Watchdog = 0b00001000;
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
            Flags::StartRecord => RawFlags::Start,
            Flags::StopRecord => RawFlags::Stop,
            Flags::WatchdogNoUpdate => RawFlags::Watchdog,
            Flags::WatchdogUpdate => RawFlags::Watchdog | RawFlags::Start,
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
    pub flags: Flags,

    /// Method used to authenticate to TACACS+ client.
    pub authentication_method: AuthenticationMethod,

    /// Other information about authentication to TACACS+ client.
    pub authentication: AuthenticationContext,

    /// Information about the user connected to the client.
    pub user_information: UserInformation<'packet>,

    /// Arguments to provide additional information to the server.
    pub arguments: Arguments<'packet>,
}

impl PacketBody for Request<'_> {
    const TYPE: PacketType = PacketType::Accounting;
    const MINIMUM_LENGTH: usize =
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

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        let wire_size = self.wire_size();

        if buffer.len() >= wire_size {
            buffer[0] = RawFlags::from(self.flags).bits();
            buffer[1] = self.authentication_method as u8;

            // header information (lengths, etc.)
            self.authentication
                .serialize_header_information(&mut buffer[2..5]);
            self.user_information
                .serialize_header_information(&mut buffer[5..8]);
            self.arguments.serialize_header(&mut buffer[8..])?;

            let argument_count = self.arguments.argument_count();

            // extra 1 is added to avoid overwriting the last argument length
            let body_start = Self::MINIMUM_LENGTH + argument_count as usize;

            // actual request content
            let user_information_len = self
                .user_information
                .serialize_body_information(&mut buffer[body_start..]);
            self.arguments
                .serialize_body(&mut buffer[body_start + user_information_len..])?;

            Ok(wire_size)
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

/// The server's reply status in an accounting session.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    /// Task logging succeeded.
    Success = 0x01,

    /// Something went wrong when logging the task.
    Error = 0x02,

    /// Forward accounting request to an alternative daemon.
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC-8907."]
    Follow = 0x21,
}

impl TryFrom<u8> for Status {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, DeserializeError> {
        match value {
            0x01 => Ok(Self::Success),
            0x02 => Ok(Self::Error),
            #[allow(deprecated)]
            0x21 => Ok(Self::Follow),
            _ => Err(DeserializeError::InvalidWireBytes),
        }
    }
}

/// An accounting reply packet received from a TACACS+ server.
#[derive(PartialEq, Eq, Debug)]
pub struct Reply<'packet> {
    status: Status,
    server_message: AsciiStr<'packet>,
    data: &'packet [u8],
}

impl Reply<'_> {
    /// Determines how long a raw reply packet claims to be, if applicable, based on various lengths stored in the body "header."
    pub fn claimed_length(buffer: &[u8]) -> Option<usize> {
        if buffer.len() >= Self::MINIMUM_LENGTH {
            let (server_message_length, data_length) = Self::extract_field_lengths(buffer)?;
            Some(Self::MINIMUM_LENGTH + server_message_length + data_length)
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

    /// The status received from the server.
    pub fn status(&self) -> Status {
        self.status
    }

    /// The message received from the server, potentially to display to a user.
    pub fn server_message(&self) -> AsciiStr<'_> {
        self.server_message
    }

    /// The domain-specific data received from the server.
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Accounting;
    const MINIMUM_LENGTH: usize = 5;
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let claimed_body_length =
            Self::claimed_length(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

        if buffer.len() >= claimed_body_length {
            let status: Status = buffer[4].try_into()?;

            let (server_message_length, data_length) =
                Self::extract_field_lengths(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

            let server_message_start = Self::MINIMUM_LENGTH;
            let data_start = server_message_start + server_message_length;

            let server_message = AsciiStr::try_from(&buffer[server_message_start..data_start])
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
