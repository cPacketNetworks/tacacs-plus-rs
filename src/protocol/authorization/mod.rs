use core::iter::zip;

use crate::AsciiStr;

use super::{
    common::{
        Argument, Arguments, ArgumentsArray, AuthenticationContext, AuthenticationMethod,
        ClientInformation, DeserializeError, NotEnoughSpace,
    },
    DeserializeWithArguments, PacketBody, PacketType, Serialize,
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

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
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

            Ok(())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

#[repr(u8)]
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

pub struct Reply<'data> {
    status: Status,
    server_message: AsciiStr<'data>,
    data: &'data [u8],
    arguments: Arguments<'data>,
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authorization;
    const MINIMUM_LENGTH: usize = 6;
}

impl<'raw> DeserializeWithArguments<'raw> for Reply<'raw> {
    fn deserialize_from_buffer(
        &self,
        buffer: &'raw [u8],
        argument_space: ArgumentsArray<'raw>,
    ) -> Result<Self, DeserializeError> {
        if buffer.len() >= Self::MINIMUM_LENGTH {
            let argument_count = buffer[1];

            if argument_count as usize <= buffer.len() {
                let mut arguments = Arguments::try_from_slicevec(argument_space)
                    .ok_or(DeserializeError::NotEnoughSpace)?;

                let status: Status = buffer[0].try_into()?;
                let server_message_length = u16::from_be_bytes(buffer[2..4].try_into()?);
                let data_length = u16::from_be_bytes(buffer[4..6].try_into()?);

                let body_start = 5 + argument_count as usize;
                let data_start = body_start + server_message_length as usize;
                let arguments_start = data_start + data_length as usize;

                let server_message = AsciiStr::try_from(&buffer[body_start..data_start])?;
                let data = &buffer[data_start..arguments_start];

                // TODO: verify no arg behavior
                let mut argument_cursor = arguments_start;

                for length in &buffer[6..6 + argument_count as usize] {
                    let next_argument_start = argument_cursor + *length as usize;

                    let raw_argument = &buffer[argument_cursor..next_argument_start];
                    let parsed_argument = Argument::deserialize(raw_argument)
                        .ok_or(DeserializeError::InvalidWireBytes)?;

                    arguments.push(parsed_argument);

                    argument_cursor = next_argument_start;
                }

                Ok(Self {
                    status,
                    server_message,
                    data,
                    arguments,
                })
            } else {
                Err(DeserializeError::NotEnoughSpace)
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

impl<'data> Reply<'data> {
    /// Header size, not including argument lengths as the number varies
    const BASE_HEADER_SIZE_BYTES: usize = 1 + 1 + 2 + 2;

    pub fn claimed_body_length(buffer: &[u8]) -> Result<usize, DeserializeError> {
        let argument_count = *buffer.get(1).ok_or(DeserializeError::UnexpectedEnd)?;

        if buffer.len() >= Self::BASE_HEADER_SIZE_BYTES + argument_count as usize {
            let server_message_len = u16::from_be_bytes(buffer[2..4].try_into()?);
            let data_len = u16::from_be_bytes(buffer[4..6].try_into()?);
            todo!()
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }

    pub fn from_buffer(
        buffer: &'data [u8],
        argument_space: &'data mut Arguments<'data>,
    ) -> Result<Self, DeserializeError> {
        let status: Status = buffer[0].try_into()?;

        // TODO: finish impl

        todo!()
    }
}

// TODO: reconciling Request arguments with Reply? (ADD/REPL status)

// struct ReplyHeader {
//     status: Status,
//     argument_count: u8,
//     server_message_length: u8,
//     data_length: u8,
//     argument_lengths: &[u8],
// }
