use core::array::TryFromSliceError;

use crate::AsciiStr;

#[cfg(test)]
mod tests;

// TODO: impl
// mod trait_impls;

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
#[derive(Debug)]
pub struct NotEnoughSpace;

// TODO: naming + struct instead?
#[derive(Debug)]
pub enum TextError {
    FieldTooLong,
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

    pub fn new(
        user: &'info str,
        port: AsciiStr<'info>,
        remote_address: AsciiStr<'info>,
    ) -> Result<Self, TextError> {
        if user.len() <= 255 && port.len() <= 255 && remote_address.len() <= 255 {
            Ok(Self {
                user,
                port,
                remote_address,
            })
        } else {
            Err(TextError::FieldTooLong)
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

// TODO: deserialization from server; seems to only happen in authorizaton REPLY
// TODO: somehow mention that duplicate arguments won't be handled/will be passed as-is
pub struct Argument<'data> {
    name: AsciiStr<'data>,
    value: AsciiStr<'data>,
    required: bool,
}

impl<'data> Argument<'data> {
    pub fn new(name: AsciiStr<'data>, value: AsciiStr<'data>, required: bool) -> Option<Self> {
        // "An argument name MUST NOT contain either of the separators." [RFC 8907]
        // length of argument (including delimiter, which is reflected in using < rather than <=) must also fit in a u8
        if !name.contains(|c| c == '=' || c == '*') && name.len() + value.len() < u8::MAX as usize {
            Some(Argument {
                name,
                value,
                required,
            })
        } else {
            None
        }
    }

    fn encoded_length(&self) -> usize {
        self.name.len() + 1 + self.value.len()
    }

    fn serialize(&self, buffer: &mut [u8]) {
        let name_len = self.name.len();
        let value_len = self.value.len();

        buffer[..name_len].copy_from_slice(self.name.as_bytes());
        buffer[name_len] = if self.required { '=' } else { '*' } as u8;
        buffer[name_len + 1..name_len + 1 + value_len].copy_from_slice(self.value.as_bytes());
    }
}

// TODO: figure out if two lifetime parameters are necessary (reference & arguments)
pub struct Arguments<'slice>(&'slice [Argument<'slice>]);

// impl<'arguments> TryFrom<&'arguments [Argument<'arguments>]> for  Arguments<'arguments> {
impl<'slice> TryFrom<&'slice [Argument<'_>]> for Arguments<'slice> {
    type Error = ();

    fn try_from(value: &'slice [Argument]) -> Result<Self, Self::Error> {
        if value.len() <= u8::MAX as usize {
            Ok(Self(value))
        } else {
            Err(())
        }
    }
}

impl Arguments<'_> {
    pub fn wire_size(&self) -> usize {
        self.0.iter().fold(1, |total, argument| {
            // 1 octet for encoded length, 1 octet for delimiter
            total + 1 + argument.encoded_length()
        })
    }

    pub fn argument_count(&self) -> usize {
        self.0.len()
    }

    pub(super) fn serialize_header(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        let argument_count = self.0.len();

        // just check for header space; body check happens in serialize_body()
        if buffer.len() > argument_count {
            let argument_count = self.0.len();

            // this won't truncate any nonzero bits since the only way to construct an Arguments is via TryFrom, where there is a length check
            buffer[0] = argument_count as u8;

            let mut length_index = 1;
            for argument in self.0.iter() {
                // length is guaranteed to fit in a u8 based on checks in Argument::new()
                buffer[length_index] = argument.encoded_length() as u8;
                length_index += 1;
            }

            Ok(())
        } else {
            Err(NotEnoughSpace)
        }
    }

    pub(super) fn serialize_body(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        let full_encoded_length = self
            .0
            .iter()
            .fold(0, |total, argument| total + argument.encoded_length());

        if buffer.len() >= full_encoded_length {
            let mut argument_start = 0;

            for argument in self.0.iter() {
                let argument_length = argument.encoded_length();
                argument.serialize(&mut buffer[argument_start..]);
                argument_start += argument_length;
            }
            Ok(())
        } else {
            Err(NotEnoughSpace)
        }
    }
}

// TODO: figure out error impl (maybe)
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    InvalidWireBytes,
    UnexpectedEnd,
    LengthMismatch,
}

// Used in &[u8] -> &[u8; 2] -> u16 conversions in reply deserialization
impl From<TryFromSliceError> for DeserializeError {
    fn from(_value: TryFromSliceError) -> Self {
        // slice conversion error means there was a length mismatch, which probably means we were expecting more data
        Self::UnexpectedEnd
    }
}
