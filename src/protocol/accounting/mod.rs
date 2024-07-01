use bitflags::bitflags;

use super::common::{
    Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation, NotEnoughSpace,
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
pub enum AccountingFlags {
    StartRecord,
    StopRecord,
    WatchdogNoUpdate,
    WatchdogUpdate,
}

impl From<AccountingFlags> for RawFlags {
    fn from(value: AccountingFlags) -> Self {
        use AccountingFlags::*;

        match value {
            StartRecord => RawFlags::Start,
            StopRecord => RawFlags::Stop,
            WatchdogNoUpdate => RawFlags::Watchdog,
            WatchdogUpdate => RawFlags::Watchdog | RawFlags::Start,
        }
    }
}

impl AccountingFlags {
    pub const WIRE_SIZE: usize = 1;
}

pub struct Request<'request> {
    pub flags: AccountingFlags,
    pub authentication_method: AuthenticationMethod,
    pub authentication: AuthenticationContext,
    pub client_information: ClientInformation<'request>,
    pub arguments: Arguments<'request>,
}

impl Request<'_> {
    pub fn wire_size(&self) -> usize {
        AccountingFlags::WIRE_SIZE
            + AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.client_information.wire_size()
            + self.arguments.wire_size()
    }

    pub fn serialize_into_buffer(self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
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
            let body_start = 8 + 1 + argument_count;

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
