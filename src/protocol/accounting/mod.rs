use bitflags::bitflags;

use super::common::{
    Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation, SerializeError,
};

#[cfg(test)]
mod tests;

bitflags! {
    pub struct Flags: u8 {
        const Start = 0x02;
        const Stop = 0x04;
        const Watchdog = 0x08;
    }
}

impl Flags {
    pub const WIRE_SIZE: usize = 1;
}

// const MIN_REQUEST_SIZE: usize = something;

pub struct Request {
    pub flags: Flags,
    pub authentication_method: AuthenticationMethod,
    pub authentication: AuthenticationContext,
    pub client_information: ClientInformation,
    pub arguments: Arguments,
}

impl Request {
    pub fn wire_size(&self) -> usize {
        Flags::WIRE_SIZE
            + AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + self.arguments.wire_size()
    }

    pub fn serialize_into_buffer(self, buffer: &mut [u8]) -> Result<(), SerializeError> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.flags.bits();
            buffer[1] = self.authentication_method as u8;

            // TODO: return & check result along the way?
            // header information (lengths, etc.)
            self.authentication
                .serialize_header_information(&mut buffer[2..=4]);
            self.client_information
                .serialize_header_information(&mut buffer[5..=7]);
            let argument_count = self.arguments.serialize_header_client(&mut buffer[8..]);

            // extra 1 is added to avoid overwriting the last argument length
            let body_start = 8 + 1 + argument_count;

            // actual request content
            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[body_start..]);
            self.arguments
                .serialize_body_values(&mut buffer[body_start + client_information_len..]);

            Ok(())
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}
