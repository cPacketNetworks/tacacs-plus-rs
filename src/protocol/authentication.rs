//! Authentication-related protocol packets.

use byteorder::{ByteOrder, NetworkEndian};
use num_enum::TryFromPrimitive;

use super::{
    AuthenticationContext, AuthenticationType, DeserializeError, MinorVersion, NotEnoughSpace,
    PacketBody, PacketType, Serialize, UserInformation,
};
use crate::AsciiStr;

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
    const MINIMUM_LENGTH: usize = Action::WIRE_SIZE + AuthenticationContext::WIRE_SIZE + 4;

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

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.action as u8;

            self.authentication
                .serialize_header_information(&mut buffer[1..4]);

            self.user_information
                .serialize_header_information(&mut buffer[4..7]);

            let user_information_len = self
                .user_information
                .serialize_body_information(&mut buffer[8..]);

            if let Some(data) = self.data {
                let data_len = data.len();

                // length is verified in with_data(), so this should be safe
                buffer[7] = data_len as u8;

                // copy over packet data
                buffer[8 + user_information_len..8 + user_information_len + data_len]
                    .copy_from_slice(data);
            } else {
                // set data_len field to 0; no data has to be copied to the data section of the packet
                buffer[7] = 0;
            }

            Ok(self.wire_size())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

/// An authentication reply packet received from a server.
#[derive(Debug, PartialEq)]
pub struct Reply<'packet> {
    status: Status,
    server_message: AsciiStr<'packet>,
    data: &'packet [u8],
    no_echo: bool,
}

impl Reply<'_> {
    /// Attempts to extract the claimed reply packed body length from a buffer.
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
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into().ok()?);
            let data_length = u16::from_be_bytes(buffer[4..6].try_into().ok()?);

            Some((server_message_length as usize, data_length as usize))
        } else {
            None
        }
    }

    /// Status of the server reply.
    pub fn status(&self) -> Status {
        self.status
    }

    /// Message received from the server, potentially to display to the user.
    pub fn server_message(&self) -> AsciiStr<'_> {
        self.server_message
    }

    /// Domain-specific data received from the server.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Whether the no echo flag was set by the server in this reply.
    pub fn no_echo(&self) -> bool {
        self.no_echo
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authentication;
    const MINIMUM_LENGTH: usize = 6;
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let claimed_length = Self::claimed_length(buffer).ok_or(DeserializeError::UnexpectedEnd)?;
        let buffer_length = buffer.len();

        if buffer_length >= claimed_length {
            let status: Status = buffer[0].try_into()?;
            let no_echo = match buffer[1] {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(DeserializeError::InvalidWireBytes),
            }?;

            let (server_message_length, data_length) =
                Self::extract_field_lengths(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

            let body_begin = Self::MINIMUM_LENGTH;
            let data_begin = body_begin + server_message_length;

            Ok(Reply {
                status,
                server_message: AsciiStr::try_from(&buffer[body_begin..data_begin])
                    .map_err(|_| DeserializeError::InvalidWireBytes)?,
                data: &buffer[data_begin..data_begin + data_length],
                no_echo,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

/// A continue packet potentially sent as part of an authentication session.
pub struct Continue<'packet> {
    user_message: Option<&'packet [u8]>,
    data: Option<&'packet [u8]>,
    abort: bool,
}

impl<'packet> Continue<'packet> {
    /// Constructs a continue packet, performing length checks on the user message and data fields to ensure encodable lengths.
    pub fn new(
        user_message: Option<&'packet [u8]>,
        data: Option<&'packet [u8]>,
        abort: bool,
    ) -> Option<Self> {
        if user_message.map_or(true, |message| u16::try_from(message.len()).is_ok())
            && data.map_or(true, |data_slice| u16::try_from(data_slice.len()).is_ok())
        {
            Some(Continue {
                user_message,
                data,
                abort,
            })
        } else {
            None
        }
    }
}

impl PacketBody for Continue<'_> {
    const TYPE: PacketType = PacketType::Authentication;
    const MINIMUM_LENGTH: usize = 5;
}

impl Serialize for Continue<'_> {
    fn wire_size(&self) -> usize {
        Self::MINIMUM_LENGTH
            + self.user_message.map_or(0, <[u8]>::len)
            + self.data.map_or(0, <[u8]>::len)
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            // set abort flag if needed
            buffer[4] = u8::from(self.abort);

            let mut user_message_len = 0;
            if let Some(message) = self.user_message {
                user_message_len = message.len();
                buffer[5..5 + user_message_len].copy_from_slice(message);
            }

            // set user message length in packet buffer
            NetworkEndian::write_u16(&mut buffer[..2], user_message_len as u16);

            let mut data_len = 0;
            if let Some(data) = self.data {
                data_len = data.len();
                buffer[5 + user_message_len..5 + user_message_len + data_len].copy_from_slice(data);
            }

            // set data length
            NetworkEndian::write_u16(&mut buffer[2..4], data_len as u16);

            Ok(self.wire_size())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}
