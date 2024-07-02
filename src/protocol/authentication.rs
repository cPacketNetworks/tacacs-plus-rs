use super::{
    AuthenticationContext, AuthenticationType, ClientInformation, DeserializeError, MinorVersion,
    NotEnoughSpace, PacketBody, PacketType, Serialize,
};
use crate::AsciiStr;

#[cfg(test)]
mod tests;

/// The authentication action, as indicated upon initiation of an authentication session.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Login = 0x01,
    ChangePassword = 0x02,
    // TODO: deprecate or something? or have some sort of warning
    SendAuth = 0x04,
}

impl Action {
    /// The number of bytes an `Action` occupies on the wire.
    pub const WIRE_SIZE: usize = 1;
}

/// The authentication status, as returned by a TACACS+ server.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass = 0x01,
    Fail = 0x02,
    GetData = 0x03,
    GetUser = 0x04,
    GetPassword = 0x05,
    Restart = 0x06,
    Error = 0x07,
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC-8907."]
    Follow = 0x21,
}

impl TryFrom<u8> for Status {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, DeserializeError> {
        match value {
            0x01 => Ok(Self::Pass),
            0x02 => Ok(Self::Fail),
            0x03 => Ok(Self::GetData),
            0x04 => Ok(Self::GetUser),
            0x05 => Ok(Self::GetPassword),
            0x06 => Ok(Self::Restart),
            0x07 => Ok(Self::Error),
            #[allow(deprecated)]
            0x21 => Ok(Self::Follow),
            _ => Err(DeserializeError::InvalidWireBytes),
        }
    }
}

/// An authentication START packet, used to initiate an authentication session.
pub struct Start<'packet> {
    action: Action,
    authentication: AuthenticationContext,
    client_information: ClientInformation<'packet>,
    data: Option<&'packet [u8]>,
}

impl<'packet> Start<'packet> {
    /// Initializes a new start packet with the provided fields and an empty data field.
    pub fn new(
        action: Action,
        authentication: AuthenticationContext,
        client_information: ClientInformation<'packet>,
        data: Option<&'packet [u8]>,
    ) -> Option<Self> {
        // TODO: ensure action/authentication method compatibility?

        // ensure data length is small enough to be properly encoded without truncation
        if data.map_or(true, |slice| slice.len() <= u8::MAX as usize) {
            Some(Self {
                action,
                authentication,
                client_information,
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
            + self.client_information.wire_size()
            + 1 // extra byte to include length of data
            + self.data.map_or(0, |data| data.len())
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.action as u8;

            self.authentication
                .serialize_header_information(&mut buffer[1..4]);

            self.client_information
                .serialize_header_information(&mut buffer[4..7]);

            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[8..]);

            if let Some(data) = self.data {
                let data_len = data.len();

                // length is verified in with_data(), so this should be safe
                buffer[7] = data_len as u8;

                // copy over packet data
                buffer[8 + client_information_len..8 + client_information_len + data_len]
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
pub struct Reply<'data> {
    status: Status,
    server_message: AsciiStr<'data>,
    data: &'data [u8],
    no_echo: bool,
}

impl Reply<'_> {
    // 1 byte for status, 1 for flags, 2 for server_msg_len, 2 for data_len
    const HEADER_SIZE_BYTES: usize = 1 + 1 + 2 + 2;

    /// Attempts to extract the claimed reply packed body length from a buffer.
    pub fn claimed_packet_body_length(buffer: &[u8]) -> Option<usize> {
        if buffer.len() >= Self::HEADER_SIZE_BYTES {
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into().ok()?) as usize;
            let data_length = u16::from_be_bytes(buffer[4..6].try_into().ok()?) as usize;
            Some(Self::HEADER_SIZE_BYTES + server_message_length + data_length)
        } else {
            None
        }
    }

    /// Status of the server reply.
    pub fn status(&self) -> Status {
        self.status
    }

    /// Message received from the server, potentially to display to the user.
    pub fn server_message(&self) -> AsciiStr {
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
        let total_len = buffer.len();

        if total_len >= Self::HEADER_SIZE_BYTES {
            let status: Status = buffer[0].try_into()?;
            let no_echo = match buffer[1] {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(DeserializeError::InvalidWireBytes),
            }?;

            // attempt to convert slices into arrays which u16::from_be_bytes needs
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into()?) as usize;
            let data_length = u16::from_be_bytes(buffer[4..6].try_into()?) as usize;

            if total_len
                >= Reply::claimed_packet_body_length(buffer)
                    .ok_or(DeserializeError::InvalidWireBytes)?
            {
                let body_begin = Self::HEADER_SIZE_BYTES;
                let data_begin = body_begin + server_message_length;

                Ok(Reply {
                    status,
                    server_message: AsciiStr::try_from(&buffer[body_begin..data_begin])?,
                    data: &buffer[data_begin..data_begin + data_length],
                    no_echo,
                })
            } else {
                Err(DeserializeError::LengthMismatch)
            }
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
            + self.user_message.map_or(0, |message| message.len())
            + self.data.map_or(0, |data| data.len())
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            // set abort flag if needed
            buffer[4] = self.abort as u8;

            let mut user_message_len = 0;
            if let Some(message) = self.user_message {
                user_message_len = message.len();
                buffer[5..5 + user_message_len].copy_from_slice(message);
            }

            // set user message length in packet buffer
            buffer[..2].copy_from_slice(&(user_message_len as u16).to_be_bytes());

            let mut data_len = 0;
            if let Some(data) = self.data {
                data_len = data.len();
                buffer[5 + user_message_len..5 + user_message_len + data_len].copy_from_slice(data);
            }

            // set data length
            buffer[2..4].copy_from_slice(&(data_len as u16).to_be_bytes());

            Ok(self.wire_size())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}
