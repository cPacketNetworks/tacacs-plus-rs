use std::fmt::Error;

use super::common::{AuthenticationContext, ClientInformation, SerializeError};

#[cfg(test)]
mod tests;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Action {
    Login = 0x01,
    ChangePassword = 0x02,
    // TODO: deprecate or something? or have some sort of warning
    SendAuth = 0x04,
}

impl Action {
    pub const WIRE_SIZE: usize = 1;
}

#[repr(u8)]
pub enum Status {
    Pass = 0x01,
    Fail = 0x02,
    GetData = 0x03,
    GetUser = 0x04,
    GetPassword = 0x05,
    Restart = 0x06,
    Error = 0x07,
    Follow = 0x21,
}

pub struct Start<'message> {
    // TODO: visibility for consistency? or migrate everything over to constructor
    // data should be kept private and only modified
    action: Action,
    authentication: AuthenticationContext,
    client_information: ClientInformation,
    data: Option<&'message [u8]>,
}

// TODO: common error type?
#[derive(Debug)]
pub struct DataTooLong;

impl<'packet> Start<'packet> {
    pub fn new(
        action: Action,
        authentication: AuthenticationContext,
        client_information: ClientInformation,
    ) -> Self {
        Self {
            action,
            authentication,
            client_information,
            data: None,
        }
    }

    pub fn wire_size(&self) -> usize {
        Action::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + 1 // extra byte to include length of data
            + self.data.map_or(0, |data| data.len())
    }

    pub fn set_data(&mut self, new_data: &'packet [u8]) -> Result<(), DataTooLong> {
        if new_data.len() < u8::MAX as usize {
            self.data = Some(new_data);
            Ok(())
        } else {
            Err(DataTooLong)
        }
    }

    // TODO: not fully pub? also need packet header for outside consumer
    pub fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), SerializeError> {
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
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

pub struct Reply<'message> {
    status: Status,
    server_message: &'message [u8],
    data: &'message [u8],
    flags: u8,
}

pub struct Continue<'message> {
    user_message: &'message [u8],
    data: &'message [u8],
    flags: u8,
}

impl TryFrom<&[u8]> for Reply<'_> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        todo!()
    }
}
