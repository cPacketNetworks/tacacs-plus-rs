use bitflags::bitflags;
use futures::io;

use super::common::{
    Arguments, AuthenticationContext, AuthenticationMethod, ClientInformation, SerializeError,
};

bitflags! {
    pub struct Flags: u8 {
        const Start = 0x02;
        const Stop = 0x04;
        const Watchdog = 0x08;
    }
}

// const MIN_REQUEST_SIZE: usize = something;

pub struct Request {
    flags: Flags,
    authentication_method: AuthenticationMethod,
    authentication: AuthenticationContext,
    client_information: ClientInformation,
    arguments: Arguments,
}

impl Request {
    // TODO: &mut [u8] argument or return &[u8] instead? might be easier to work with in no_std case
    // can't really just return &[u8] without backing storage
    // could also go as_bytes_mut a la AES crate
    // error conditions:
    // - buffer not big enough
    //
    // maybe just write to something that implements Write? then it could be renamed write_packet
    // pub fn serialize_bytes(&self, buffer: &mut [u8]) -> Result<(), SerializeError> {
    // pub async fn write_packet(&self, destination: Pin<&W>) -> io::Error
    // where
    //     W: io::AsyncWrite,
    // {
    //     buffer[0] = self.flags;
    //     buffer[1] = self.authentication_method;

    //     // authentication fields are ordered differently between accounting/authorization unfortunately
    //     self.authentication.serialize_bytes(&mut buffer[2..5]);

    //     // TODO: handle different strings and their lengths
    //     self.client_information.serialize_lengths(&mut buffer[5..8]);
    // }
}
