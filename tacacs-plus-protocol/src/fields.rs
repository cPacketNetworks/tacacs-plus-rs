use core::fmt;
use getset::{CopyGetters, Getters};

use crate::FieldText;
use crate::MinorVersion;

use super::SerializeError;

#[cfg(test)]
mod tests;

/// The method used to authenticate to the TACACS+ client.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AuthenticationMethod {
    /// Unknown.
    NotSet = 0x00,

    /// No authentication performed.
    None = 0x01,

    /// Kerberos version 5
    Kerberos5 = 0x02,

    /// Fixed password associated with access line
    Line = 0x03,

    /// Granting new privileges (similar to `su(1)`)
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
    /// The number of bytes an `AuthenticationMethod` occupies on the wire.
    pub(super) const WIRE_SIZE: usize = 1;
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::NotSet => "not set",
                Self::None => "none",
                Self::Kerberos5 => "Kerberos 5",
                Self::Line => "terminal line",
                Self::Enable => "enable",
                Self::Local => "local user database",
                Self::TacacsPlus => "TACACS+",
                Self::Guest => "guest authentication",
                Self::Radius => "RADIUS",
                Self::Kerberos4 => "Kerberos 4",
                Self::RCommand => "r-command",
            }
        )
    }
}

/// A privilege level for authentication. Limited to the range 0-15, inclusive.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub struct PrivilegeLevel(u8);

impl PrivilegeLevel {
    /// Converts an integer to a `PrivilegeLevel` if it is in the proper range (0-15).
    ///
    /// # Examples
    /// ```
    /// use tacacs_plus_protocol::PrivilegeLevel;
    ///
    /// let valid_level = PrivilegeLevel::new(3);
    /// assert!(valid_level.is_some());
    ///
    /// let too_big = PrivilegeLevel::new(42);
    /// assert!(too_big.is_none());
    /// ```
    pub fn new(level: u8) -> Option<Self> {
        if level <= 15 {
            Some(Self(level))
        } else {
            None
        }
    }
}

impl Default for PrivilegeLevel {
    /// Returns the lowest privilege level of 0.
    fn default() -> Self {
        Self(0)
    }
}

impl fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Types of authentication supported by the TACACS+ protocol.
///
/// RFC-8907 partitions these by supported minor version: [`Ascii`](AuthenticationType::Ascii) requires [`MinorVersion::Default`](crate::MinorVersion::Default), while the rest (beside [`NotSet`](AuthenticationType::NotSet), I believe) require [`MinorVersion::V1`](crate::MinorVersion::V1).
///
/// *Note:* TACACS+ as a protocol does not meet modern standards of security; access to the data lines must be protected. See [RFC-8907 Section 10.1]
///
/// [RFC-8907 Section 10.1]: https://datatracker.ietf.org/doc/html/rfc8907#section-10.1.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

impl fmt::Display for AuthenticationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::NotSet => "not set",
                Self::Ascii => "ASCII",
                Self::Pap => "PAP",
                Self::Chap => "CHAP",
                Self::MsChap => "MSCHAP",
                Self::MsChapV2 => "MSCHAPv2",
            }
        )
    }
}

/// A TACACS+ authentication service. Most of these values are only kept for backwards compatibility.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthenticationService {
    /// No authentication performed.
    None = 0x00,

    /// Regular login to a client device.
    Login = 0x01,

    /// Request for a change in privileges, similar to the functionality of `su(1)`.
    Enable = 0x02,

    /// Point-to-Point Protocol
    Ppp = 0x03,

    // I'm gonna be honest I have no idea what this stands for and I don't know if anyone else does either
    // could be NAT protocol translation (but draft predates RFC 2766), plaintext, and who knows what else
    /// PT authentication (not sure exactly what the acronym stands for).
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

impl fmt::Display for AuthenticationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => "none",
                Self::Login => "login",
                Self::Enable => "enable",
                Self::Ppp => "PPP",
                Self::Pt => "PT",
                Self::RCommand => "r-command",
                Self::X25 => "X25",
                Self::Nasi => "NASI",
                Self::FwProxy => "firewall proxy",
            }
        )
    }
}

/// Some authentication information about a request, sent or received from a server.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct AuthenticationContext {
    /// The privilege level of the request.
    pub privilege_level: PrivilegeLevel,

    /// The method used to authenticate to the TACACS+ client.
    pub authentication_type: AuthenticationType,

    /// The service used to authenticate to the TACACS+ client.
    pub service: AuthenticationService,
}

impl AuthenticationContext {
    /// Size of authentication context information on the wire, in bytes.
    pub(super) const WIRE_SIZE: usize = 3;

    /// Serializes authentication context information into a packet body "header."
    pub(super) fn serialize(&self, buffer: &mut [u8]) {
        buffer[0] = self.privilege_level.0;
        buffer[1] = self.authentication_type as u8;
        buffer[2] = self.service as u8;
    }
}

/// Some information about the user connected to a TACACS+ client.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Getters, CopyGetters)]
pub struct UserInformation<'info> {
    /// The user performing the action that is connected to the client.
    #[getset(get_copy = "pub")]
    user: &'info str,

    /// The port the user is connected to.
    #[getset(get = "pub")]
    port: FieldText<'info>,

    /// The remote address that the user is connecting from.
    #[getset(get = "pub")]
    remote_address: FieldText<'info>,
}

impl<'info> UserInformation<'info> {
    /// Number of bytes occupied by `UserInformation` "header" information (i.e., field lengths).
    pub(super) const HEADER_INFORMATION_SIZE: usize = 3; // 3 single-byte field lengths

    /// Returns the number of bytes this information bundle will occupy on the wire.
    pub(super) fn wire_size(&self) -> usize {
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
        port: FieldText<'info>,
        remote_address: FieldText<'info>,
    ) -> Option<Self> {
        if u8::try_from(user.len()).is_ok()
            && u8::try_from(port.len()).is_ok()
            && u8::try_from(remote_address.len()).is_ok()
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

    /// Serializes the lengths of the contained fields in the proper order, as to be done in the "header" of a client-sent packet body.
    pub(super) fn serialize_field_lengths(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, SerializeError> {
        if buffer.len() >= Self::HEADER_INFORMATION_SIZE {
            buffer[0] = self.user.len().try_into()?;
            buffer[1] = self.port.len().try_into()?;
            buffer[2] = self.remote_address.len().try_into()?;

            // 3 bytes serialized as part of "header" information
            Ok(3)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }

    /// Copies client information fields into their proper locations within a packet body.
    pub(super) fn serialize_field_values(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, SerializeError> {
        // ensure buffer is large enough to serialize field values into (i.e., excluding the header lengths)
        if buffer.len() >= self.wire_size() - Self::HEADER_INFORMATION_SIZE {
            let user_len = self.user.len();
            let port_len = self.port.len();
            let remote_address_len = self.remote_address.len();
            let total_len = user_len + port_len + remote_address_len;

            // three fields are serialized contiguously without any delimiters, as lengths are stored elsewhere
            buffer[..user_len].copy_from_slice(self.user.as_bytes());
            buffer[user_len..user_len + port_len].copy_from_slice(self.port.as_bytes());
            buffer[user_len + port_len..total_len].copy_from_slice(self.remote_address.as_bytes());

            Ok(total_len)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}
