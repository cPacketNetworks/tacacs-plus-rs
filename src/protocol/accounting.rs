use bitflags::bitflags;

use crate::AsciiStr;

use super::{
    Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation, DeserializeError,
    NotEnoughSpace, PacketBody, PacketType, Serialize,
};

#[cfg(test)]
mod tests;

bitflags! {
    struct RawFlags: u8 {
        const Start = 0x02;
        const Stop = 0x04;
        const Watchdog = 0x08;
    }
}

/// Valid accounting flag combinations for a TACACS+ account REQUEST packet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flags {
    StartRecord,
    StopRecord,
    WatchdogNoUpdate,
    WatchdogUpdate,
}

impl From<Flags> for RawFlags {
    fn from(value: Flags) -> Self {
        use Flags::*;

        match value {
            StartRecord => RawFlags::Start,
            StopRecord => RawFlags::Stop,
            WatchdogNoUpdate => RawFlags::Watchdog,
            WatchdogUpdate => RawFlags::Watchdog | RawFlags::Start,
        }
    }
}

impl Flags {
    pub const WIRE_SIZE: usize = 1;
}

pub struct Request<'request> {
    pub flags: Flags,
    pub authentication_method: AuthenticationMethod,
    pub authentication: AuthenticationContext,
    pub client_information: ClientInformation<'request>,
    pub arguments: Arguments<'request>,
}

impl PacketBody for Request<'_> {
    const TYPE: PacketType = PacketType::Accounting;
    const MINIMUM_LENGTH: usize =
        Flags::WIRE_SIZE + AuthenticationMethod::WIRE_SIZE + AuthenticationContext::WIRE_SIZE + 4;
}

impl Serialize for Request<'_> {
    fn wire_size(&self) -> usize {
        Flags::WIRE_SIZE
            + AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + self.arguments.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = RawFlags::from(self.flags).bits();
            buffer[1] = self.authentication_method as u8;

            // TODO: return & check result along the way?
            // header information (lengths, etc.)
            self.authentication
                .serialize_header_information(&mut buffer[2..=4]);
            self.client_information
                .serialize_header_information(&mut buffer[5..=7]);
            self.arguments.serialize_header(&mut buffer[8..])?;

            let argument_count = self.arguments.argument_count();

            // extra 1 is added to avoid overwriting the last argument length
            let body_start = 8 + 1 + argument_count as usize;

            // actual request content
            let client_information_len = self
                .client_information
                .serialize_body_information(&mut buffer[body_start..]);
            self.arguments
                .serialize_body(&mut buffer[body_start + client_information_len..])?;

            Ok(())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Success = 0x01,
    Error = 0x02,
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC-8907."]
    Follow = 0x21,
}

impl TryFrom<u8> for Status {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, DeserializeError> {
        match value {
            0x01 => Ok(Self::Success),
            0x02 => Ok(Self::Error),
            #[allow(deprecated)]
            0x21 => Ok(Self::Follow),
            _ => Err(DeserializeError::InvalidWireBytes),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Reply<'data> {
    pub(super) status: Status,
    pub(super) server_message: AsciiStr<'data>,
    pub(super) data: &'data [u8],
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Accounting;
    const MINIMUM_LENGTH: usize = 6;
}

impl<'raw> TryFrom<&'raw [u8]> for Reply<'raw> {
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        if buffer.len() >= Self::MINIMUM_LENGTH {
            let status: Status = buffer[4].try_into()?;

            let server_message_length = u16::from_be_bytes(buffer[0..2].try_into()?);
            let data_length = u16::from_be_bytes(buffer[2..4].try_into()?);

            let server_message_start = 5;
            let data_start = server_message_start + server_message_length as usize;

            let server_message = AsciiStr::try_from(&buffer[server_message_start..data_start])?;
            let data = &buffer[data_start..data_start + data_length as usize];

            Ok(Self {
                status,
                server_message,
                data,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
