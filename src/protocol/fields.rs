use crate::protocol::MinorVersion;
use crate::AsciiStr;

/// The method used to authenticate to the TACACS+ client.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthenticationMethod {
    /// Unknown.
    NotSet = 0x00,

    /// No authentication performed.
    None = 0x01,

    /// Kerberos version 5
    Kerberos5 = 0x02,

    /// Fixed password associated with access line
    Line = 0x03,

    /// Granting new privileges (a la `su(1)`)
    Enable = 0x04,

    /// Client-local user database
    Local = 0x05,

    /// The TACACS+ protocol itself.
    TacacsPlus = 0x06,

    /// (Unqualified) guest authentication
    Guest = 0x08,

    /// RADIUS (RFC 3579)
    Radius = 0x10,

    /// Kerberos version 4
    Kerberos4 = 0x11,

    /// r-command, like `rlogin(1)`
    RCommand = 0x20,
}

impl AuthenticationMethod {
    pub const WIRE_SIZE: usize = 1;
}

/// A privilege level for authentication. Limited to the range 0-15, inclusive.
pub struct PrivilegeLevel(u8);

impl PrivilegeLevel {
    /// Converts an integer to a `PrivilegeLevel` if it is in the proper range (0-15).
    ///
    /// # Examples
    /// ```
    /// use tacacs_plus::protocol::PrivilegeLevel;
    ///
    /// let valid_level = PrivilegeLevel::of(3);
    /// assert!(valid_level.is_some());
    ///
    /// let too_big = PrivilegeLevel::of(42);
    /// assert!(too_big.is_none());
    /// ```
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
/// RFC-8907 partitions these by supported minor version: [`Ascii`](AuthenticationType::Ascii) requires [`MinorVersion::Default`](crate::protocol::MinorVersion::Default), while the rest (beside [`NotSet`](AuthenticationType::NotSet), I believe) require [`MinorVersion::V1`](crate::protocol::MinorVersion::V1).
///
/// *Note:* TACACS+ as a protocol does not meet modern standards of security; access to the data lines must be protected. See [RFC-8907 Section 10.1]
///
/// [RFC-8907 Section 10.1]: https://datatracker.ietf.org/doc/html/rfc8907#section-10.1.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticationType {
    /// Authentication type not set, typically when it's not available to the client.
    ///
    /// **NOTE:** This option is only valid for authorization and accounting requests.
    NotSet = 0x00,

    /// Plain text username & password exchange.
    Ascii = 0x01,

    /// The Password Authentication Protocol, as specified by [RFC-1334](https://www.rfc-editor.org/rfc/rfc1334.html).
    Pap = 0x02,

    /// The Challenge-Handshake Authentication Protocol, also specified in [RFC-1334](https://www.rfc-editor.org/rfc/rfc1334.html).
    Chap = 0x03,

    /// Version 1 of Microsoft's CHAP extension.
    MsChap = 0x05,

    /// Version 2 of Microsoft's CHAP extension.
    MsChapV2 = 0x06,
}

impl AuthenticationType {
    /// Returns the required minor version for this `AuthenticationType`, if applicable.
    pub const fn required_minor_version(&self) -> Option<MinorVersion> {
        match self {
            AuthenticationType::NotSet => None,
            AuthenticationType::Ascii => Some(MinorVersion::Default),
            _ => Some(MinorVersion::V1),
        }
    }
}

/// A TACACS+ authentication service. Most of these values are only kept for backwards compatibility, so that's something to keep in mind.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum AuthenticationService {
    /// No authentication performed.
    None = 0x00,

    /// Regular login to a client device.
    Login = 0x01,

    /// Request for a change in privileges, a la `su(1)`.
    Enable = 0x02,

    /// Point-to-Point Protocol
    Ppp = 0x03,

    // I'm gonna be honest I have no idea what this stands for and I don't know if anyone else does either
    // could be NAT protocol translation (but draft predates RFC 2766), plaintext, and who knows what else
    Pt = 0x05,

    /// Authentication from the r-command suite, e.g. via `rlogin(1)`.
    RCommand = 0x06,

    /// [X.25 suite](https://en.wikipedia.org/wiki/X.25) (I assume), potentially its NetWare flavor.
    X25 = 0x07,

    /// NetWare Asynchronous Support Interface
    Nasi = 0x08,

    /// Firewall proxy
    FwProxy = 0x09,
}

/// Some authentication information about a request, sent or received from a server.
pub struct AuthenticationContext {
    pub privilege_level: PrivilegeLevel,
    pub authentication_type: AuthenticationType,
    pub service: AuthenticationService,
}

impl AuthenticationContext {
    /// Size of authentication context information on the wire, in bytes.
    pub const WIRE_SIZE: usize = 3;

    /// Serializes authentication context information into a packet body "header."
    pub(super) fn serialize_header_information(&self, buffer: &mut [u8]) {
        buffer[0] = self.privilege_level.0;
        buffer[1] = self.authentication_type as u8;
        buffer[2] = self.service as u8;
    }
}

/// Some information about the user connected to a TACACS+ client.
#[derive(Debug)]
pub struct UserInformation<'info> {
    user: &'info str,
    port: AsciiStr<'info>,
    remote_address: AsciiStr<'info>,
}

impl<'info> UserInformation<'info> {
    // three lengths in header
    const HEADER_INFORMATION_SIZE: usize = 3;

    /// Returns the number of bytes this information bundle will occupy on the wire.
    pub fn wire_size(&self) -> usize {
        Self::HEADER_INFORMATION_SIZE
            + self.user.len()
            + self.port.len()
            + self.remote_address.len()
    }

    /// Bundles together information about a TACACS+ client user, performing some length & ASCII checks on fields to ensure validity.
    ///
    /// `user` can be any (UTF-8) string, but `port` and `remote_address` must be valid ASCII.
    /// All three fields must also be at most 255 characters long (i.e., `u8::MAX`).
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
