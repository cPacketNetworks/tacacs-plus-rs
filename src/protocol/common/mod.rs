use core::array::TryFromSliceError;

use super::NotEnoughSpace;
use crate::{AsciiStr, InvalidAscii};

#[cfg(test)]
mod tests;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AuthenticationMethod {
    NotSet = 0x00,
    None = 0x01,
    Kerberos5 = 0x02,
    Line = 0x03,
    Enable = 0x04,
    Local = 0x05,
    TacacsPlus = 0x06,
    Guest = 0x08,
    Radius = 0x10,
    Kerberos4 = 0x11,
    Rcmd = 0x20,
}

// TODO: is impl overkill? :P
impl AuthenticationMethod {
    pub const WIRE_SIZE: usize = 1;
}

/// A privilege level for authentication. Limited to the range 0-15, inclusive.
pub struct PrivilegeLevel(u8);

impl PrivilegeLevel {
    // TODO: naming?
    /// Converts an integer to a PrivilegeLevel if it is in the proper range (0-15).
    pub fn of(level: u8) -> Option<Self> {
        if level <= 15 {
            Some(Self(level))
        } else {
            None
        }
    }
}

/// Types of authentication supported by the TACACS+ protocol
///
/// *Note:* TACACS+ as a protocol does not meet modern standards of security; access to the data lines must be protected. See [RFC-8907 Section 10.1]
///
/// [RFC-8907 Section 10.1]: https://datatracker.ietf.org/doc/html/rfc8907#section-10.1
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AuthenticationType {
    /// Plain text username & password exchange
    Ascii = 0x01,
    Pap = 0x02,
    Chap = 0x03,
    Arap = 0x04,
    MsChap = 0x05,
    MsChapV2 = 0x06,
}

// TODO: auth in name?
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
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

pub struct AuthenticationContext {
    pub privilege_level: PrivilegeLevel,
    pub authentication_type: AuthenticationType,
    pub service: Service,
}

impl AuthenticationContext {
    pub(super) const WIRE_SIZE: usize = 3;

    pub(super) fn serialize_header_information(&self, buffer: &mut [u8]) {
        buffer[0] = self.privilege_level.0;
        buffer[1] = self.authentication_type as u8;
        buffer[2] = self.service as u8;
    }
}

#[derive(Debug)]
pub struct ClientInformation<'info> {
    user: &'info str,
    port: AsciiStr<'info>,
    remote_address: AsciiStr<'info>,
}

// TODO: error impl
// TODO: not pub(super)

impl<'info> ClientInformation<'info> {
    // three lengths in header
    const HEADER_INFORMATION_SIZE: usize = 3;

    pub fn wire_size(&self) -> usize {
        Self::HEADER_INFORMATION_SIZE
            + self.user.len()
            + self.port.len()
            + self.remote_address.len()
    }

    pub fn new(
        user: &'info str,
        port: AsciiStr<'info>,
        remote_address: AsciiStr<'info>,
    ) -> Option<Self> {
        if user.len() <= 255 && port.len() <= 255 && remote_address.len() <= 255 {
            Some(Self {
                user,
                port,
                remote_address,
            })
        } else {
            None
        }
    }

    // TODO: visibility
    pub(super) fn serialize_header_information(&self, buffer: &mut [u8]) {
        buffer[0] = self.user.len() as u8;
        buffer[1] = self.port.len() as u8;
        buffer[2] = self.remote_address.len() as u8;
    }

    pub(super) fn serialize_body_information(&self, buffer: &mut [u8]) -> usize {
        let user_len = self.user.len();
        let port_len = self.port.len();
        let remote_address_len = self.remote_address.len();
        let total_len = user_len + port_len + remote_address_len;

        buffer[0..user_len].copy_from_slice(self.user.as_bytes());
        buffer[user_len..user_len + port_len].copy_from_slice(self.port.as_bytes());
        buffer[user_len + port_len..total_len].copy_from_slice(self.remote_address.as_bytes());

        total_len
    }
}

// TODO: figure out error impl (maybe)
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    InvalidWireBytes,
    UnexpectedEnd,
    LengthMismatch,
    // TODO: include required length as part of error value?
    NotEnoughSpace,
    // TODO: is this the right place for this?
    VersionMismatch,
}

// Used in &[u8] -> &[u8; 2] -> u16 conversions in reply deserialization
impl From<TryFromSliceError> for DeserializeError {
    fn from(_value: TryFromSliceError) -> Self {
        // slice conversion error means there was a length mismatch, which probably means we were expecting more data
        Self::UnexpectedEnd
    }
}

impl From<InvalidAscii> for DeserializeError {
    fn from(_value: InvalidAscii) -> Self {
        Self::InvalidWireBytes
    }
}

impl From<NotEnoughSpace> for DeserializeError {
    fn from(_value: NotEnoughSpace) -> Self {
        Self::NotEnoughSpace
    }
}
