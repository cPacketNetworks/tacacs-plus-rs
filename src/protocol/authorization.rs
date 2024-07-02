//! Authorization features/packets of the TACACS+ protocol.

use crate::AsciiStr;

use super::{
    Argument, Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation,
    DeserializeError, DeserializeWithArguments, NotEnoughSpace, PacketBody, PacketType, Serialize,
};

#[cfg(test)]
mod tests;

/// An authorization request packet body, including arguments.
pub struct Request<'request> {
    pub method: AuthenticationMethod,
    pub authentication_context: AuthenticationContext,
    pub client_information: ClientInformation<'request>,
    pub arguments: Arguments<'request>,
}

impl PacketBody for Request<'_> {
    const TYPE: PacketType = PacketType::Authorization;
    const MINIMUM_LENGTH: usize =
        AuthenticationMethod::WIRE_SIZE + AuthenticationContext::WIRE_SIZE + 4;
}

impl Serialize for Request<'_> {
    fn wire_size(&self) -> usize {
        AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + self.arguments.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.method as u8;
            self.authentication_context
                .serialize_header_information(&mut buffer[1..4]);
            self.client_information
                .serialize_header_information(&mut buffer[4..7]);

            self.arguments.serialize_header(&mut buffer[7..])?;

            let body_start: usize = Self::MINIMUM_LENGTH + self.arguments.argument_count() as usize;

            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[body_start..]);

            self.arguments
                .serialize_body(&mut buffer[body_start + client_information_len..])?;

            Ok(self.wire_size())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Status {
    PassAdd = 0x01,
    PassReplace = 0x02,
    Fail = 0x10,
    Error = 0x11,
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC 8907."]
    Follow = 0x21,
}

impl TryFrom<u8> for Status {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, DeserializeError> {
        use Status::*;

        match value {
            0x01 => Ok(PassAdd),
            0x02 => Ok(PassReplace),
            0x10 => Ok(Fail),
            0x11 => Ok(Error),
            #[allow(deprecated)]
            0x21 => Ok(Follow),
            _ => Err(DeserializeError::InvalidWireBytes),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Reply<'data> {
    // TODO: make not pub(super) (it's only like this for protocol module level tests)
    pub(super) status: Status,
    pub(super) server_message: AsciiStr<'data>,
    pub(super) data: &'data [u8],
    pub(super) arguments: Arguments<'data>,
}

impl<'body> Reply<'body> {
    /// The result status of the request.
    pub fn status(&self) -> Status {
        self.status
    }

    /// The message received from the server.
    pub fn server_mesage(&self) -> AsciiStr {
        self.server_message
    }

    /// The domain-specific data received from the server.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// The arguments sent by the server.
    pub fn arguments(&self) -> &Arguments<'body> {
        &self.arguments
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authorization;
    const MINIMUM_LENGTH: usize = 6;
}

impl<'raw> DeserializeWithArguments<'raw> for Reply<'raw> {
    fn deserialize_from_buffer(
        buffer: &'raw [u8],
        argument_space: &'raw mut [Argument<'raw>],
    ) -> Result<Self, DeserializeError> {
        if buffer.len() >= Self::MINIMUM_LENGTH {
            let status: Status = buffer[0].try_into()?;
            let argument_count = buffer[1] as usize;
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into()?) as usize;
            let data_length = u16::from_be_bytes(buffer[4..6].try_into()?) as usize;

            let body_start = 6 + argument_count;
            let data_start = body_start + server_message_length;
            let arguments_start = data_start + data_length;

            let server_message = AsciiStr::try_from(&buffer[body_start..data_start])?;
            let data = &buffer[data_start..arguments_start];

            let argument_lengths = &buffer[6..6 + argument_count];
            let total_argument_length: usize = argument_lengths
                .iter()
                .map(|&length| usize::from(length))
                .sum();
            let argument_values = &buffer[arguments_start..arguments_start + total_argument_length];
            let arguments =
                Arguments::deserialize(argument_lengths, argument_values, argument_space)?;

            Ok(Self {
                status,
                server_message,
                data,
                arguments,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

// TODO: reconciling Request arguments with Reply? (ADD/REPL status)
