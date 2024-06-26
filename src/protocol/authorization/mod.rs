use ascii::AsciiString;

use super::common::{
    Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation, SerializeError,
};

#[cfg(test)]
mod tests;

pub struct Request {
    pub method: AuthenticationMethod,
    pub authentication_context: AuthenticationContext,
    pub client_information: ClientInformation,
    pub arguments: Arguments,
}

impl Request {
    pub fn wire_size(&self) -> usize {
        AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + self.arguments.wire_size()
    }

    pub fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), SerializeError> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.method as u8;
            self.authentication_context
                .serialize_header_information(&mut buffer[1..=3]);
            self.client_information
                .serialize_header_information(&mut buffer[4..=7]);

            let argument_count = self.arguments.serialize_header_client(&mut buffer[8..]);
            let body_start = 8 + argument_count;

            // actual client information
            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[body_start..]);

            // actual argument names/values
            self.arguments
                .serialize_body_values(&mut buffer[body_start + client_information_len..]);

            Ok(())
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

#[repr(u8)]
pub enum Status {
    PassAdd = 0x01,
    PassReplace = 0x02,
    Fail = 0x10,
    Error = 0x11,
    #[deprecated = "Forwarding to an alternative daemon was deprecated in IETF RFC 8907."]
    Follow = 0x21,
}

pub struct Reply {
    status: Status,
    server_message: AsciiString,
    data: AsciiString,
    // TODO: also somehow keep track of required arguments?
    arguments: Arguments,
}

// struct ReplyHeader {
//     status: Status,
//     argument_count: u8,
//     server_message_length: u8,
//     data_length: u8,
//     argument_lengths: &[u8],
// }
