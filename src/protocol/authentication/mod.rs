use super::common::{AuthenticationContext, ClientInformation, DeserializeError, NotEnoughSpace};

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
        use Status::*;

        match value {
            0x01 => Ok(Pass),
            0x02 => Ok(Fail),
            0x03 => Ok(GetData),
            0x04 => Ok(GetUser),
            0x05 => Ok(GetPassword),
            0x06 => Ok(Restart),
            0x07 => Ok(Error),
            #[allow(deprecated)]
            0x21 => Ok(Follow),
            _ => Err(DeserializeError::InvalidWireBytes),
        }
    }
}

/// An authentication START packet, used to initiate an authentication session.
pub struct Start<'packet> {
    // TODO: visibility for consistency? or migrate everything over to constructor
    // data should be kept private and only modified through functions that verify new values
    action: Action,
    authentication: AuthenticationContext,
    client_information: ClientInformation<'packet>,
    data: Option<&'packet [u8]>,
}

// TODO: common error type?
#[derive(Debug)]
pub struct DataTooLong;

impl<'packet> Start<'packet> {
    /// Initializes a new start packet with the provided fields and an empty data field.
    pub fn new(
        action: Action,
        authentication: AuthenticationContext,
        client_information: ClientInformation<'packet>,
    ) -> Self {
        Self {
            action,
            authentication,
            client_information,
            data: None,
        }
    }

    /// Returns the current size of the packet as represented on the wire.
    pub fn wire_size(&self) -> usize {
        Action::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + 1 // extra byte to include length of data
            + self.data.map_or(0, |data| data.len())
    }

    /// Sets the data associated with this packet if it's short enough (i.e., shorter than u8::MAX bytes); otherwise returns an error.
    pub fn set_data(&mut self, new_data: &'packet [u8]) -> Result<(), DataTooLong> {
        if new_data.len() < u8::MAX as usize {
            self.data = Some(new_data);
            Ok(())
        } else {
            Err(DataTooLong)
        }
    }

    // TODO: not fully pub? also need packet header for outside consumer
    // TODO: this could be a trait
    pub fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.action as u8;

            self.authentication
                .serialize_header_information(&mut buffer[1..=3]);

            self.client_information
                .serialize_header_information(&mut buffer[4..=6]);

            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[8..]);

            if let Some(data) = self.data {
                let data_len = data.len();

                // length is verified in with_data(), so this should be completely safe
                buffer[7] = data_len as u8;

                // copy over packet data
                buffer[8 + client_information_len..8 + client_information_len + data_len]
                    .copy_from_slice(data);
            } else {
                // set data_len field to 0; no data has to be copied to the data section of the packet
                buffer[7] = 0;
            }

            Ok(())
        } else {
            Err(NotEnoughSpace)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Reply<'data> {
    status: Status,
    server_message: &'data [u8],
    data: &'data [u8],
    no_echo: bool,
}

impl Reply<'_> {
    // 1 byte for status, 1 for flags, 2 for server_msg_len, 2 for data_len
    const HEADER_SIZE_BYTES: usize = 1 + 1 + 2 + 2;

    pub fn claimed_packet_body_length(buffer: &[u8]) -> Result<usize, DeserializeError> {
        if buffer.len() >= Self::HEADER_SIZE_BYTES {
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into()?) as usize;
            let data_length = u16::from_be_bytes(buffer[4..6].try_into()?) as usize;
            Ok(Self::HEADER_SIZE_BYTES + server_message_length + data_length)
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }

    pub fn server_message(&self) -> &[u8] {
        self.server_message
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }

    pub fn no_echo(&self) -> bool {
        self.no_echo
    }
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        let total_len = buffer.len();

        if total_len >= Self::HEADER_SIZE_BYTES {
            let status: Status = buffer[0].try_into()?;

            // TODO: find a better way to catch invalid wire bytes than this
            let no_echo = match buffer[1] {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(DeserializeError::InvalidWireBytes),
            }?;

            // attempt to convert slices into arrays which u16::from_be_bytes needs
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into()?) as usize;
            let data_length = u16::from_be_bytes(buffer[4..6].try_into()?) as usize;

            // TODO: exact size or allow for bigger?
            // allowing for bigger could be a bad idea actually, should have a separate function to get expected length though
            // (thinking leaking part of not properly cleared buffer)
            // ensure buffer length matches (or exceeds?) expected length based on length fields
            if total_len >= Reply::claimed_packet_body_length(buffer)? {
                let body_begin = Self::HEADER_SIZE_BYTES;
                Ok(Reply {
                    status,
                    server_message: &buffer[body_begin..body_begin + server_message_length],
                    data: &buffer[body_begin + server_message_length
                        ..body_begin + server_message_length + data_length],
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

pub struct Continue<'packet> {
    user_message: Option<&'packet [u8]>,
    data: Option<&'packet [u8]>,
    // TODO: abstract behind method in case of future changes?
    pub abort: bool,
}

impl<'packet> Continue<'packet> {
    pub fn new() -> Self {
        Continue {
            user_message: None,
            data: None,
            abort: false,
        }
    }

    pub fn set_user_message(&mut self, new_message: &'packet [u8]) -> Result<(), DataTooLong> {
        if new_message.len() <= u16::MAX as usize {
            self.user_message = Some(new_message);
            Ok(())
        } else {
            Err(DataTooLong)
        }
    }

    pub fn set_data(&mut self, new_data: &'packet [u8]) -> Result<(), DataTooLong> {
        if new_data.len() <= u16::MAX as usize {
            self.data = Some(new_data);
            Ok(())
        } else {
            Err(DataTooLong)
        }
    }

    pub fn wire_size(&self) -> usize {
        // 3 includes 1 byte of flags (abort) and 2 bytes of encoded lengths
        3 + self.user_message.map_or(0, |message| message.len())
            + self.data.map_or(0, |data| data.len())
    }

    pub fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
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

            Ok(())
        } else {
            Err(NotEnoughSpace)
        }
    }
}
