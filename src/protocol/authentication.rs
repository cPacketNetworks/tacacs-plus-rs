use std::fmt::Error;

use ascii::AsciiString;

#[repr(u8)]
pub enum Action {
    Login = 0x01,
    ChangePassword = 0x02,
    SendAuth = 0x04,
}

/// Types of authentication supported by the TACACS+ protocol
///
/// *Note:* TACACS+ as a protocol does not meet modern standards of security; access to the data lines must be protected. See [RFC-8907 Section 10.1]
///
/// [RFC-8907 Section 10.1]: https://datatracker.ietf.org/doc/html/rfc8907#section-10.1
#[repr(u8)]
pub enum Type {
    /// Plain text username & password exchange
    Ascii = 0x01,
    Pap = 0x02,
    Chap = 0x03,
    Arap = 0x04,
    MsChap = 0x05,
    MsChapV2 = 0x06,
}

#[repr(u8)]
pub enum Service {
    None = 0x00,
    Login = 0x01,
    Enable = 0x02,
    Ppp = 0x03,
    Arap = 0x04,
    Pt = 0x05,
    Rcmd = 0x06,
    X25 = 0x07,
    Nasi = 0x08,
    FwProxy = 0x09,
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
    action: Action,
    privilege_level: u8,
    authentication_type: Type,
    authentication_service: Service,
    user: String,
    port: AsciiString,
    remote_address: AsciiString,
    data: &'message [u8],
}

struct StartHeader {
    action: Action,
    privilege_level: u8,
    authentication_type: Type,
    authentication_service: Service,
    user_length: u8,
    port_length: u8,
    remote_address_length: u8,
    data_length: u8,
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
