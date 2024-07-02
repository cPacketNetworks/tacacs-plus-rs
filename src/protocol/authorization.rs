use crate::AsciiStr;

use super::{
    Argument, Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation,
    DeserializeError, DeserializeWithArguments, NotEnoughSpace, PacketBody, PacketType, Serialize,
};

#[cfg(test)]
mod tests;

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
        // TODO: just rely on checks in components?
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.method as u8;
            self.authentication_context
                .serialize_header_information(&mut buffer[1..=3]);
            self.client_information
                .serialize_header_information(&mut buffer[4..=6]);

            self.arguments.serialize_header(&mut buffer[7..])?;

            // extra 1 added since we have to go past the last argument length in the header
            let body_start: usize = 7 + 1 + self.arguments.argument_count() as usize;

            // actual client information
            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[body_start..]);

            // actual argument names/values
            self.arguments
                .serialize_body(&mut buffer[body_start + client_information_len..])?;

            Ok(self.wire_size())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

#[repr(u8)]
#[derive(PartialEq, Eq, Debug)]
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
    pub(super) status: Status,
    pub(super) server_message: AsciiStr<'data>,
    pub(super) data: &'data [u8],
    pub(super) arguments: Arguments<'data>,
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
            // wish I could just use sum() here but references :(
            let total_argument_length = argument_lengths
                .iter()
                .fold(0, |total, &length| total + length as usize);
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
