use crate::AsciiStr;

use super::common::{
    Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation, DeserializeError,
    NotEnoughSpace,
};

#[cfg(test)]
mod tests;

pub struct Request<'request> {
    pub method: AuthenticationMethod,
    pub authentication_context: AuthenticationContext,
    pub client_information: ClientInformation<'request>,
    pub arguments: Arguments<'request>,
}

impl Request<'_> {
    pub fn wire_size(&self) -> usize {
        AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + self.arguments.wire_size()
    }

    pub fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        // TODO: just rely on checks in components?
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.method as u8;
            self.authentication_context
                .serialize_header_information(&mut buffer[1..=3]);
            self.client_information
                .serialize_header_information(&mut buffer[4..=6]);

            self.arguments.serialize_header(&mut buffer[7..])?;

            // extra 1 added since we have to go past the last argument length in the header
            let body_start = 7 + 1 + self.arguments.argument_count();

            // actual client information
            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[body_start..]);

            // actual argument names/values
            self.arguments
                .serialize_body(&mut buffer[body_start + client_information_len..])?;

            Ok(())
        } else {
            Err(NotEnoughSpace)
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

impl<'data> Reply<'data> {
    /// Header size, not including argument lengths as the number varies
    const BASE_HEADER_SIZE_BYTES: usize = 1 + 1 + 2 + 2;

    pub fn claimed_body_length(buffer: &[u8]) -> Result<usize, DeserializeError> {
        let argument_count = buffer.get(1).ok_or(DeserializeError::UnexpectedEnd);

        if buffer.len() >= Self::BASE_HEADER_SIZE_BYTES + argument_count {
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
