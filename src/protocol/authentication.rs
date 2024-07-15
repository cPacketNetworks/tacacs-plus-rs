//! Authentication-related protocol packets.

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use getset::{CopyGetters, Getters};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use super::{
    AuthenticationContext, AuthenticationType, DeserializeError, MinorVersion, PacketBody,
    PacketType, Serialize, SerializeError, UserInformation,
};
use crate::FieldText;

#[cfg(test)]
mod tests;

/// The authentication action, as indicated upon initiation of an authentication session.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Login request.
    Login = 0x01,

    /// Password change request.
    ChangePassword = 0x02,

    /// Outbound authentication request.
    #[deprecated = "Outbound authentication should not be used due to its security implications, according to RFC-8907."]
    SendAuth = 0x04,
}

impl Action {
    /// The number of bytes an `Action` occupies on the wire.
    pub const WIRE_SIZE: usize = 1;
}

/// The authentication status, as returned by a TACACS+ server.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum Status {
    /// Authentication succeeded.
    Pass = 0x01,

    /// Authentication failed.
    Fail = 0x02,

    /// Request for more domain-specific data.
    GetData = 0x03,

    /// Request for username.
    GetUser = 0x04,

    /// Request for password.
    GetPassword = 0x05,

    /// Restart session, discarding current one.
    Restart = 0x06,

    /// Server-side error while authenticating.
    Error = 0x07,

    /// Forward authentication request to an alternative daemon.
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC-8907."]
    Follow = 0x21,
}

impl Status {
    /// Number of bytes an authentication reply status occupies on the wire.
    pub const WIRE_SIZE: usize = 1;
}

#[doc(hidden)]
impl From<TryFromPrimitiveError<Status>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<Status>) -> Self {
        Self::InvalidStatus(value.number)
    }
}

/// An authentication start packet, used to initiate an authentication session.
pub struct Start<'packet> {
    action: Action,
    authentication: AuthenticationContext,
    user_information: UserInformation<'packet>,
    data: Option<&'packet [u8]>,
}

impl<'packet> Start<'packet> {
    /// Initializes a new start packet with the provided fields and an empty data field.
    pub fn new(
        action: Action,
        authentication: AuthenticationContext,
        user_information: UserInformation<'packet>,
        data: Option<&'packet [u8]>,
    ) -> Option<Self> {
        // TODO: ensure action/authentication type compatibility?

        // ensure data length is small enough to be properly encoded without truncation
        if data.map_or(true, |slice| u8::try_from(slice.len()).is_ok())
            && authentication.authentication_type != AuthenticationType::NotSet
        {
            Some(Self {
                action,
                authentication,
                user_information,
                data,
            })
        } else {
            None
        }
    }
}

impl PacketBody for Start<'_> {
    const TYPE: PacketType = PacketType::Authentication;

    // extra byte for data length
    const REQUIRED_FIELDS_LENGTH: usize = Action::WIRE_SIZE
        + AuthenticationContext::WIRE_SIZE
        + UserInformation::HEADER_INFORMATION_SIZE
        + 1;

    fn required_minor_version(&self) -> Option<MinorVersion> {
        // NOTE: a check in Start::new() guarantees that the authentication type will not be NotSet
        match self.authentication.authentication_type {
            AuthenticationType::Ascii => Some(MinorVersion::Default),
            _ => Some(MinorVersion::V1),
        }
    }
}

impl Serialize for Start<'_> {
    fn wire_size(&self) -> usize {
        Action::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.user_information.wire_size()
            + 1 // extra byte to include length of data
            + self.data.map_or(0, <[u8]>::len)
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let wire_size = self.wire_size();

        if buffer.len() >= self.wire_size() {
            buffer[0] = self.action as u8;

            self.authentication
                .serialize_header_information(&mut buffer[1..4]);

            self.user_information
                .serialize_header_information(&mut buffer[4..7])?;

            // information written before this occupies 8 bytes
            let mut total_bytes_written = 8;

            // user information values start at index 8
            // cap slice with wire size to avoid overflows, although that shouldn't happen
            let user_info_written_len = self
                .user_information
                .serialize_body_information(&mut buffer[8..wire_size]);
            total_bytes_written += user_info_written_len;

            // data starts after the end of the user information values
            let data_start = 8 + user_info_written_len;
            if let Some(data) = self.data {
                let data_len = data.len();

                // length is verified to fit in a u8 in new(), but verify anyways
                buffer[7] = data_len.try_into()?;

                // copy over packet data
                buffer[data_start..data_start + data_len].copy_from_slice(data);

                total_bytes_written += data_len;
            } else {
                // set data_len field to 0; no data has to be copied to the data section of the packet
                buffer[7] = 0;
            }

            if total_bytes_written == wire_size {
                Ok(total_bytes_written)
            } else {
                Err(SerializeError::LengthMismatch {
                    expected: wire_size,
                    actual: total_bytes_written,
                })
            }
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

/// Flags received in an authentication reply packet.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct ReplyFlags(u8);

impl ReplyFlags {
    /// Number of bytes reply flags occupy on the wire.
    pub const WIRE_SIZE: usize = 1;
}

bitflags! {
    impl ReplyFlags: u8 {
        /// Indicates the client MUST NOT display user input.
        const NO_ECHO = 0b00000001;
    }
}

/// An authentication reply packet received from a server.
#[derive(Debug, PartialEq, Getters, CopyGetters)]
pub struct Reply<'packet> {
    /// Gets the status of this authentication exchange, as returned from the server.
    #[getset(get = "pub")]
    status: Status,

    /// Returns the message meant to be displayed to the user.
    #[getset(get_copy = "pub")]
    server_message: FieldText<'packet>,

    /// Returns the authentication data for processing by the client.
    #[getset(get_copy = "pub")]
    data: &'packet [u8],

    /// Gets the flags returned from the server as part of this authentication exchange.
    #[getset(get = "pub")]
    flags: ReplyFlags,
}

impl Reply<'_> {
    /// Attempts to extract the claimed reply packed body length from a buffer.
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
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into().ok()?);
            let data_length = u16::from_be_bytes(buffer[4..6].try_into().ok()?);

            Some((server_message_length as usize, data_length as usize))
        } else {
            None
        }
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authentication;

    // extra 2 bytes each for lengths of server message & data
    const REQUIRED_FIELDS_LENGTH: usize = Status::WIRE_SIZE + ReplyFlags::WIRE_SIZE + 4;
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let claimed_length = Self::claimed_length(buffer).ok_or(DeserializeError::UnexpectedEnd)?;
        let buffer_length = buffer.len();

        if buffer_length >= claimed_length {
            let status: Status = buffer[0].try_into()?;
            let flag_byte = buffer[1];
            let flags = ReplyFlags::from_bits(flag_byte)
                .ok_or(DeserializeError::InvalidBodyFlags(flag_byte))?;

            let (server_message_length, data_length) =
                Self::extract_field_lengths(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

            let body_begin = Self::REQUIRED_FIELDS_LENGTH;
            let data_begin = body_begin + server_message_length;

            Ok(Reply {
                status,
                server_message: FieldText::try_from(&buffer[body_begin..data_begin])
                    .map_err(|_| DeserializeError::BadText)?,
                data: &buffer[data_begin..data_begin + data_length],
                flags,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

/// Flags to send as part of an authentication continue packet.
#[derive(Debug)]
pub struct ContinueFlags(u8);

bitflags! {
    impl ContinueFlags: u8 {
        /// Indicates the client is prematurely aborting the authentication session.
        const ABORT = 0b00000001;
    }
}

/// A continue packet potentially sent as part of an authentication session.
pub struct Continue<'packet> {
    user_message: Option<&'packet [u8]>,
    data: Option<&'packet [u8]>,
    flags: ContinueFlags,
}

impl<'packet> Continue<'packet> {
    /// Offset of the user message within a continue packet body, if present.
    const USER_MESSAGE_OFFSET: usize = 5;

    /// Constructs a continue packet, performing length checks on the user message and data fields to ensure encodable lengths.
    pub fn new(
        user_message: Option<&'packet [u8]>,
        data: Option<&'packet [u8]>,
        flags: ContinueFlags,
    ) -> Option<Self> {
        if user_message.map_or(true, |message| u16::try_from(message.len()).is_ok())
            && data.map_or(true, |data_slice| u16::try_from(data_slice.len()).is_ok())
        {
            Some(Continue {
                user_message,
                data,
                flags,
            })
        } else {
            None
        }
    }
}

impl PacketBody for Continue<'_> {
    const TYPE: PacketType = PacketType::Authentication;

    // 2 bytes each for user message & data length; 1 byte for flags
    const REQUIRED_FIELDS_LENGTH: usize = 5;
}

impl Serialize for Continue<'_> {
    fn wire_size(&self) -> usize {
        Self::REQUIRED_FIELDS_LENGTH
            + self.user_message.map_or(0, <[u8]>::len)
            + self.data.map_or(0, <[u8]>::len)
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let wire_size = self.wire_size();

        if buffer.len() >= wire_size {
            // write field lengths into beginning of body
            let user_message_len = self.user_message.map_or(0, <[u8]>::len).try_into()?;
            NetworkEndian::write_u16(&mut buffer[..2], user_message_len);

            let data_len = self.data.map_or(0, <[u8]>::len).try_into()?;
            NetworkEndian::write_u16(&mut buffer[2..4], data_len);

            let data_offset = Self::USER_MESSAGE_OFFSET + user_message_len as usize;

            // set abort flag if needed
            buffer[4] = self.flags.bits();

            // copy user message into buffer, if present
            if let Some(message) = self.user_message {
                buffer[Self::USER_MESSAGE_OFFSET..data_offset].copy_from_slice(message);
            }

            // copy data into buffer, again if present
            if let Some(data) = self.data {
                buffer[data_offset..data_offset + data_len as usize].copy_from_slice(data);
            }

            // total number of bytes written includes required "header" fields & two variable length fields
            let actual_written_len =
                Self::REQUIRED_FIELDS_LENGTH + user_message_len as usize + data_len as usize;

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
