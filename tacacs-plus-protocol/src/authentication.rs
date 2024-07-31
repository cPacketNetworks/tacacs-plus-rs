//! Authentication-related protocol packets.

use core::fmt;

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use getset::{CopyGetters, Getters};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use super::{
    AuthenticationContext, AuthenticationType, DeserializeError, MinorVersion, PacketBody,
    PacketType, Serialize, SerializeError, UserInformation,
};
use crate::{Deserialize, FieldText};

#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
mod owned;

#[cfg(feature = "std")]
pub use owned::ReplyOwned;

/// The authentication action, as indicated upon initiation of an authentication session.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Login request.
    Login = 0x01,

    /// Password change request.
    ChangePassword = 0x02,

    /// Outbound authentication request.
    #[deprecated = "Outbound authentication should not be used due to its security implications, according to RFC-8907."]
    SendAuth = 0x04,
}

impl Action {
    /// The number of bytes an `Action` occupies on the wire.
    const WIRE_SIZE: usize = 1;
}

/// The authentication status, as returned by a TACACS+ server.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum Status {
    /// Authentication succeeded.
    Pass = 0x01,

    /// Authentication failed.
    Fail = 0x02,

    /// Request for more domain-specific data.
    GetData = 0x03,

    /// Request for username.
    GetUser = 0x04,

    /// Request for password.
    GetPassword = 0x05,

    /// Restart session, discarding current one.
    Restart = 0x06,

    /// Server-side error while authenticating.
    Error = 0x07,

    /// Forward authentication request to an alternative daemon.
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC-8907."]
    Follow = 0x21,
}

impl Status {
    /// Number of bytes an authentication reply status occupies on the wire.
    const WIRE_SIZE: usize = 1;
}

#[doc(hidden)]
impl From<TryFromPrimitiveError<Status>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<Status>) -> Self {
        Self::InvalidStatus(value.number)
    }
}

/// An authentication start packet, used to initiate an authentication session.
#[derive(Debug, PartialEq, Eq)]
pub struct Start<'packet> {
    action: Action,
    authentication: AuthenticationContext,
    user_information: UserInformation<'packet>,
    data: Option<&'packet [u8]>,
}

/// Error returned when attempting to construct an invalid start packet body.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum BadStart {
    /// Data field was too long to encode.
    DataTooLong,

    /// Authentication type was not set, which is invalid for authentication packets.
    AuthTypeNotSet,

    /// Action & authentication type were incompatible.
    ///
    /// See [Table 1] of RFC8907 for valid combinations.
    ///
    /// [Table 1]: https://www.rfc-editor.org/rfc/rfc8907.html#name-tacacs-protocol-versioning
    IncompatibleActionAndType,
}

impl fmt::Display for BadStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataTooLong => write!(f, "data field too long to encode in a single byte"),
            Self::AuthTypeNotSet => write!(
                f,
                "authentication type must be set for authentication packets"
            ),
            Self::IncompatibleActionAndType => {
                write!(f, "authentication action & type are incompatible")
            }
        }
    }
}

impl<'packet> Start<'packet> {
    /// Initializes a new start packet with the provided fields and an empty data field.
    pub fn new(
        action: Action,
        authentication: AuthenticationContext,
        user_information: UserInformation<'packet>,
        data: Option<&'packet [u8]>,
    ) -> Result<Self, BadStart> {
        // ensure data length is small enough to be properly encoded without truncation
        if data.map_or(false, |slice| u8::try_from(slice.len()).is_err()) {
            Err(BadStart::DataTooLong)
        } else if authentication.authentication_type == AuthenticationType::NotSet {
            // authentication type must be set in an authentication start packet
            Err(BadStart::AuthTypeNotSet)
        } else if !Self::action_and_type_compatible(authentication.authentication_type, action) {
            Err(BadStart::IncompatibleActionAndType)
        } else {
            Ok(Self {
                action,
                authentication,
                user_information,
                data,
            })
        }
    }

    /// Predicate for whether authentication type & authentication are compatible.
    ///
    /// NOTE: `NotSet` should not be passed to this function, as it is not allowed in authentication packets.
    ///
    /// Derived from [Table 1] in RFC8907.
    ///
    /// [Table 1]: https://www.rfc-editor.org/rfc/rfc8907.html#name-tacacs-protocol-versioning
    fn action_and_type_compatible(auth_type: AuthenticationType, action: Action) -> bool {
        match (auth_type, action) {
            // ASCII authentication can be used with login/chpass actions
            (AuthenticationType::Ascii, Action::Login | Action::ChangePassword) => true,

            // ASCII authentication can't be used with sendauth option
            // (also marked as deprecated but we allow this internally)
            #[allow(deprecated)]
            (AuthenticationType::Ascii, Action::SendAuth) => false,

            // change password is not valid for any other authentication types
            (_, Action::ChangePassword) => false,

            // NotSet is invalid anyways, so we don't handle it and provide a warning in the doc comment for this function
            (AuthenticationType::NotSet, _) => unreachable!(),

            // all other authentication types can be used for both sendauth/login
            _ => true,
        }
    }
}

impl PacketBody for Start<'_> {
    const TYPE: PacketType = PacketType::Authentication;

    // extra byte for data length
    const REQUIRED_FIELDS_LENGTH: usize = Action::WIRE_SIZE
        + AuthenticationContext::WIRE_SIZE
        + UserInformation::HEADER_INFORMATION_SIZE
        + 1;

    fn required_minor_version(&self) -> Option<MinorVersion> {
        // NOTE: a check in Start::new() guarantees that the authentication type will not be NotSet
        match self.authentication.authentication_type {
            AuthenticationType::Ascii => Some(MinorVersion::Default),
            _ => Some(MinorVersion::V1),
        }
    }
}

impl Serialize for Start<'_> {
    fn wire_size(&self) -> usize {
        Action::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.user_information.wire_size()
            + 1 // extra byte to include length of data
            + self.data.map_or(0, <[u8]>::len)
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let wire_size = self.wire_size();

        if buffer.len() >= self.wire_size() {
            buffer[0] = self.action as u8;

            self.authentication.serialize(&mut buffer[1..4]);

            self.user_information
                .serialize_field_lengths(&mut buffer[4..7])?;

            // information written before this occupies 8 bytes
            let mut total_bytes_written = 8;

            // user information values start at index 8
            // cap slice with wire size to avoid overflows, although that shouldn't happen
            let user_info_written_len = self
                .user_information
                .serialize_field_values(&mut buffer[8..wire_size])?;
            total_bytes_written += user_info_written_len;

            // data starts after the end of the user information values
            let data_start = 8 + user_info_written_len;
            if let Some(data) = self.data {
                let data_len = data.len();

                // length is verified to fit in a u8 in new(), but verify anyways
                buffer[7] = data_len.try_into()?;

                // copy over packet data
                buffer[data_start..data_start + data_len].copy_from_slice(data);

                total_bytes_written += data_len;
            } else {
                // set data_len field to 0; no data has to be copied to the data section of the packet
                buffer[7] = 0;
            }

            if total_bytes_written == wire_size {
                Ok(total_bytes_written)
            } else {
                Err(SerializeError::LengthMismatch {
                    expected: wire_size,
                    actual: total_bytes_written,
                })
            }
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

/// Flags received in an authentication reply packet.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ReplyFlags(u8);

impl ReplyFlags {
    /// Number of bytes reply flags occupy on the wire.
    const WIRE_SIZE: usize = 1;
}

bitflags! {
    impl ReplyFlags: u8 {
        /// Indicates the client MUST NOT display user input.
        const NO_ECHO = 0b00000001;
    }
}

/// An authentication reply packet received from a server.
#[derive(Debug, PartialEq, Getters, CopyGetters)]
pub struct Reply<'packet> {
    /// Gets the status of this authentication exchange, as returned from the server.
    #[getset(get = "pub")]
    status: Status,

    /// Returns the message meant to be displayed to the user.
    #[getset(get_copy = "pub")]
    server_message: FieldText<'packet>,

    /// Returns the authentication data for processing by the client.
    #[getset(get_copy = "pub")]
    data: &'packet [u8],

    /// Gets the flags returned from the server as part of this authentication exchange.
    #[getset(get = "pub")]
    flags: ReplyFlags,
}

struct ReplyFieldLengths {
    server_message_length: u16,
    data_length: u16,
    total_length: u32,
}

impl Reply<'_> {
    /// Server message offset within packet body as a zero-based index.
    const SERVER_MESSAGE_OFFSET: usize = 6;

    /// Attempts to extract the claimed reply packed body length from a buffer.
    pub fn extract_total_length(buffer: &[u8]) -> Result<u32, DeserializeError> {
        Self::extract_field_lengths(buffer).map(|lengths| lengths.total_length)
    }

    /// Extracts the server message and data field lengths from a buffer, treating it as if it were a serialized reply packet body.
    fn extract_field_lengths(buffer: &[u8]) -> Result<ReplyFieldLengths, DeserializeError> {
        // data length is the last required field
        if buffer.len() >= Self::REQUIRED_FIELDS_LENGTH {
            let server_message_length = NetworkEndian::read_u16(&buffer[2..4]);
            let data_length = NetworkEndian::read_u16(&buffer[4..6]);

            // total length is just the sum of field lengths & the encoded lengths themselves
            // SAFETY: REQUIRED_FIELDS_LENGTH as defined is guaranteed to fit in a u32
            let total_length = u32::try_from(Self::REQUIRED_FIELDS_LENGTH).unwrap()
                + u32::from(server_message_length)
                + u32::from(data_length);

            Ok(ReplyFieldLengths {
                server_message_length,
                data_length,
                total_length,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authentication;

    // extra 2 bytes each for lengths of server message & data
    const REQUIRED_FIELDS_LENGTH: usize = Status::WIRE_SIZE + ReplyFlags::WIRE_SIZE + 4;
}

// Hide from docs, as this is meant for internal use only
#[doc(hidden)]
impl<'raw> Deserialize<'raw> for Reply<'raw> {
    fn deserialize_from_buffer(buffer: &'raw [u8]) -> Result<Self, DeserializeError> {
        let field_lengths = Self::extract_field_lengths(buffer)?;

        // buffer is sliced to length reported in packet header in Packet::deserialize_body(), so we can compare against
        // it using the buffer length
        let length_from_header = buffer.len();

        // ensure buffer is large enough to contain entire packet
        if field_lengths.total_length as usize == length_from_header {
            let status = Status::try_from(buffer[0])?;
            let flag_byte = buffer[1];
            let flags = ReplyFlags::from_bits(flag_byte)
                .ok_or(DeserializeError::InvalidBodyFlags(flag_byte))?;

            let data_begin =
                Self::SERVER_MESSAGE_OFFSET + field_lengths.server_message_length as usize;

            let server_message =
                FieldText::try_from(&buffer[Self::SERVER_MESSAGE_OFFSET..data_begin])
                    .map_err(|_| DeserializeError::BadText)?;
            let data = &buffer[data_begin..data_begin + field_lengths.data_length as usize];

            Ok(Reply {
                status,
                server_message,
                data,
                flags,
            })
        } else {
            Err(DeserializeError::WrongBodyBufferSize {
                expected: field_lengths.total_length as usize,
                buffer_size: length_from_header,
            })
        }
    }
}

/// Flags to send as part of an authentication continue packet.
#[derive(Debug)]
pub struct ContinueFlags(u8);

bitflags! {
    impl ContinueFlags: u8 {
        /// Indicates the client is prematurely aborting the authentication session.
        const ABORT = 0b00000001;
    }
}

/// A continue packet potentially sent as part of an authentication session.
pub struct Continue<'packet> {
    user_message: Option<&'packet [u8]>,
    data: Option<&'packet [u8]>,
    flags: ContinueFlags,
}

impl<'packet> Continue<'packet> {
    /// Offset of the user message within a continue packet body, if present.
    const USER_MESSAGE_OFFSET: usize = 5;

    /// Constructs a continue packet, performing length checks on the user message and data fields to ensure encodable lengths.
    pub fn new(
        user_message: Option<&'packet [u8]>,
        data: Option<&'packet [u8]>,
        flags: ContinueFlags,
    ) -> Option<Self> {
        if user_message.map_or(true, |message| u16::try_from(message.len()).is_ok())
            && data.map_or(true, |data_slice| u16::try_from(data_slice.len()).is_ok())
        {
            Some(Continue {
                user_message,
                data,
                flags,
            })
        } else {
            None
        }
    }
}

impl PacketBody for Continue<'_> {
    const TYPE: PacketType = PacketType::Authentication;

    // 2 bytes each for user message & data length; 1 byte for flags
    const REQUIRED_FIELDS_LENGTH: usize = 5;
}

impl Serialize for Continue<'_> {
    fn wire_size(&self) -> usize {
        Self::REQUIRED_FIELDS_LENGTH
            + self.user_message.map_or(0, <[u8]>::len)
            + self.data.map_or(0, <[u8]>::len)
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let wire_size = self.wire_size();

        if buffer.len() >= wire_size {
            // write field lengths into beginning of body
            let user_message_len = self.user_message.map_or(0, <[u8]>::len).try_into()?;
            NetworkEndian::write_u16(&mut buffer[..2], user_message_len);

            let data_len = self.data.map_or(0, <[u8]>::len).try_into()?;
            NetworkEndian::write_u16(&mut buffer[2..4], data_len);

            let data_offset = Self::USER_MESSAGE_OFFSET + user_message_len as usize;

            // set abort flag if needed
            buffer[4] = self.flags.bits();

            // copy user message into buffer, if present
            if let Some(message) = self.user_message {
                buffer[Self::USER_MESSAGE_OFFSET..data_offset].copy_from_slice(message);
            }

            // copy data into buffer, again if present
            if let Some(data) = self.data {
                buffer[data_offset..data_offset + data_len as usize].copy_from_slice(data);
            }

            // total number of bytes written includes required "header" fields & two variable length fields
            let actual_written_len =
                Self::REQUIRED_FIELDS_LENGTH + user_message_len as usize + data_len as usize;

            if actual_written_len == wire_size {
                Ok(actual_written_len)
            } else {
                Err(SerializeError::LengthMismatch {
                    expected: wire_size,
                    actual: actual_written_len,
                })
            }
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}
