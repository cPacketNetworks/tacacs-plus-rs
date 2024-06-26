use ascii::AsciiString;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

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

/// size in bytes
pub const AUTHENTICATION_CONTEXT_SIZE: usize = 4;

pub struct AuthenticationContext {
    // TODO: remove?
    // method: AuthenticationMethod,
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
pub struct ClientInformation {
    // TODO: normalization or whatever as required by RFC 8907 (UsernameCasePreserved)
    user: String,
    // TODO: String or AsciiString for these two fields?
    port: String,
    remote_address: String,
}

#[derive(Debug)]
pub enum SerializeError {
    NotEnoughSpace,
}

// TODO: naming
#[derive(Debug)]
pub enum TextError {
    InvalidAscii,
    FieldTooLong,
}

impl ClientInformation {
    // three lengths in header
    const HEADER_INFORMATION_SIZE: usize = 3;

    pub fn wire_size(&self) -> usize {
        Self::HEADER_INFORMATION_SIZE
            + self.user.len()
            + self.port.len()
            + self.remote_address.len()
    }

    pub fn new(user: &str, port: &str, remote_address: &str) -> Result<Self, TextError> {
        if port.is_ascii() && remote_address.is_ascii() {
            // TODO: length tests
            if user.len() <= 255 && port.len() <= 255 && remote_address.len() <= 255 {
                Ok(Self {
                    user: user.into(),
                    port: port.into(),
                    remote_address: remote_address.into(),
                })
            } else {
                Err(TextError::FieldTooLong)
            }
        } else {
            Err(TextError::InvalidAscii)
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

// TODO: argument keys cannot contain =/* (value delimiters)

// TODO: store required status inline/as part of value? like tuple/struct or smth
// (separate set might be redundant/inefficient)
#[derive(Default)]
pub struct Arguments {
    // TODO: visibility
    value_map: HashMap<String, String>,
    required_arguments: HashSet<String>,
}

impl Arguments {
    pub fn new() -> Arguments {
        Default::default()
    }

    // TODO: get_wire_size? also visibility
    pub fn wire_size(&self) -> usize {
        self.value_map
            .iter()
            // start with length 1 for argument count
            .fold(1, |total, (name, value)| {
                // include 1 byte for argument length and another for value separator (= or *)
                total + 1 + name.len() + 1 + value.len()
            })
    }

    // TODO: insert method w/ required toggle (also remove method?)
    pub fn add_argument(&mut self, name: &str, value: &str, required: bool) -> bool {
        if !name.contains('=') && !name.contains('*') {
            self.value_map.insert(name.into(), value.into());

            if required {
                self.required_arguments.insert(name.into());
            }

            true
        } else {
            false
        }
    }

    pub fn remove_argument(&mut self, name: &str) -> bool {
        self.required_arguments.remove(name);
        self.value_map.remove(name).is_some()
    }

    // TODO: mention unchecked
    pub(super) fn serialize_header_client(&self, buffer: &mut [u8]) -> usize {
        let argument_count = self.value_map.len();
        buffer[0] = argument_count as u8;

        let mut index = 1;

        for (name, value) in self.value_map.iter() {
            // as before, save room for the separator
            buffer[index] = (name.len() + 1 + value.len()) as u8;
            index += 1;
        }

        argument_count
    }

    pub(super) fn serialize_body_values(&self, buffer: &mut [u8]) -> usize {
        let mut cursor = buffer;
        let mut total_len = 0;

        for (name, value) in self.value_map.iter() {
            // leave space for separator
            let name_len = name.len();
            let value_len = value.len();
            let argument_len = name_len + 1 + value_len;

            // choose delimiter based on whether argument is required
            let delimiter = if self.required_arguments.contains(name) {
                '='
            } else {
                '*'
            };

            // copy argument information to buffer
            cursor[..name_len].copy_from_slice(name.as_bytes());
            cursor[name_len] = delimiter as u8;
            cursor[name_len + 1..argument_len].copy_from_slice(value.as_bytes());

            // move on to next argument/section of buffer
            total_len += argument_len;
            cursor = &mut cursor[argument_len..];
        }

        total_len
    }
}

// TODO: deserialization from server; seems to only happen in authorizaton REPLY
impl FromStr for Arguments {
    type Err = ();

    fn from_str(_string: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
