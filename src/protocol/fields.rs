use crate::AsciiStr;

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
    RCommand = 0x20,
}

impl AuthenticationMethod {
    pub const WIRE_SIZE: usize = 1;
}

/// A privilege level for authentication. Limited to the range 0-15, inclusive.
pub struct PrivilegeLevel(u8);

impl PrivilegeLevel {
    /// Converts an integer to a `PrivilegeLevel` if it is in the proper range (0-15).
    pub fn of(level: u8) -> Option<Self> {
        if level <= 15 {
            Some(Self(level))
        } else {
            None
        }
    }
}

/// Types of authentication supported by the TACACS+ protocol.
///
/// *Note:* TACACS+ as a protocol does not meet modern standards of security; access to the data lines must be protected. See [RFC-8907 Section 10.1]
///
/// [RFC-8907 Section 10.1]: https://datatracker.ietf.org/doc/html/rfc8907#section-10.1.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AuthenticationType {
    /// Plain text username & password exchange.
    Ascii = 0x01,

    /// The Password Authentication Protocol, as specified by [RFC-1334](https://www.rfc-editor.org/rfc/rfc1334.html).
    Pap = 0x02,

    /// The Challenge-Handshake Authentication Protocol, also specified in [RFC-1334](https://www.rfc-editor.org/rfc/rfc1334.html).
    Chap = 0x03,

    /// The AppleTalk Remote Access Protocol. Not present in RFC-8907, but kept here for completeness.
    Arap = 0x04,

    /// Version 1 of Microsoft's CHAP extension.
    MsChap = 0x05,

    /// Version 2 of Microsoft's CHAP extension.
    MsChapV2 = 0x06,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum AuthenticationService {
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
    pub service: AuthenticationService,
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

impl<'info> ClientInformation<'info> {
    // three lengths in header
    const HEADER_INFORMATION_SIZE: usize = 3;

    pub fn wire_size(&self) -> usize {
        Self::HEADER_INFORMATION_SIZE
            + self.user.len()
            + self.port.len()
            + self.remote_address.len()
    }

    /// Bundles together information about a TACACS+ client, performing some length checks on fields to ensure validity.
    pub fn new(
        user: &'info str,
        port: AsciiStr<'info>,
        remote_address: AsciiStr<'info>,
    ) -> Option<Self> {
        if user.len() <= u8::MAX as usize
            && port.len() <= u8::MAX as usize
            && remote_address.len() <= u8::MAX as usize
        {
            Some(Self {
                user,
                port,
                remote_address,
            })
        } else {
            None
        }
    }

    /// Places field lengths into the "header" section of a packet body.
    pub(super) fn serialize_header_information(&self, buffer: &mut [u8]) {
        buffer[0] = self.user.len() as u8;
        buffer[1] = self.port.len() as u8;
        buffer[2] = self.remote_address.len() as u8;
    }

    /// Copies client information fields into their proper locations within a packet body.
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
