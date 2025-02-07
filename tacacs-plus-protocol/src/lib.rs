//! # tacacs-plus-protocol
//!
//! Serialization & deserialization of (RFC8907) TACACS+ protocol packets.

#![no_std]
#![warn(missing_docs)]
#![warn(clippy::cast_lossless)]
#![warn(clippy::cast_possible_truncation)]
// show std badge on feature-gated types/etc. on docs.rs (see also Cargo.toml)
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "std")]
extern crate std;

use core::{fmt, num::TryFromIntError};

mod util;

pub mod accounting;
pub mod authentication;
pub mod authorization;

mod packet;
use getset::CopyGetters;
pub use packet::header::HeaderInfo;
pub use packet::{Packet, PacketFlags, PacketType};

mod arguments;
pub use arguments::{Argument, Arguments, InvalidArgument};

mod fields;
pub use fields::*;

mod text;
pub use text::{FieldText, InvalidText};

#[cfg(feature = "std")]
mod owned;

/// An error that occurred when serializing a packet or any of its components into their binary format.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum SerializeError {
    /// The provided buffer did not have enough space to serialize the object.
    NotEnoughSpace,

    /// The length of a field exceeded the maximum value encodeable on the wire.
    LengthOverflow,

    /// Mismatch between expected/actual number of bytes written.
    LengthMismatch {
        /// The expected number of bytes to have been written.
        expected: usize,
        /// That actual number of bytes written during serialization.
        actual: usize,
    },
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughSpace => write!(f, "not enough space in buffer"),
            Self::LengthOverflow => write!(f, "field length overflowed"),
            Self::LengthMismatch { expected, actual } => write!(
                f,
                "mismatch in number of bytes written: expected {expected}, actual {actual}"
            ),
        }
    }
}

#[doc(hidden)]
impl From<TryFromIntError> for SerializeError {
    fn from(_value: TryFromIntError) -> Self {
        Self::LengthOverflow
    }
}

/// An error that occurred during deserialization of a full/partial packet.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    /// Invalid binary status representation in response.
    InvalidStatus(u8),

    /// Invalid packet type number on the wire.
    InvalidPacketType(u8),

    /// Invalid header flag byte.
    InvalidHeaderFlags(u8),

    /// Invalid body flag byte.
    InvalidBodyFlags(u8),

    /// Invalid version number.
    InvalidVersion(u8),

    /// Invalid arguments when deserializing
    InvalidArgument(InvalidArgument),

    /// Mismatch between expected/received packet types.
    PacketTypeMismatch {
        /// The expected packet type.
        expected: PacketType,

        /// The actual packet type that was parsed.
        actual: PacketType,
    },

    /// Text field was not printable ASCII when it should have been.
    BadText,

    /// Unencrypted flag was not the expected value.
    IncorrectUnencryptedFlag,

    /// Buffer containing raw body had incorrect length with respect to length fields in the body.
    WrongBodyBufferSize {
        /// The expected buffer length, based on length fields in the packet body.
        expected: usize,
        /// The size of the buffer being deserialized, sliced to just the body section.
        buffer_size: usize,
    },

    /// Object representation was cut off in some way.
    UnexpectedEnd,
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStatus(num) => write!(f, "invalid status byte in raw packet: {num:#x}"),
            Self::InvalidPacketType(num) => write!(f, "invalid packet type byte: {num:#x}"),
            Self::InvalidHeaderFlags(num) => write!(f, "invalid header flags: {num:#x}"),
            Self::InvalidBodyFlags(num) => write!(f, "invalid body flags: {num:#x}"),
            Self::InvalidVersion(num) => write!(
                f,
                "invalid version number: major {:#x}, minor {:#x}",
                num >> 4,     // major version is 4 upper bits of byte
                num & 0b1111  // minor version is 4 lower bits
            ),
            Self::InvalidArgument(reason) => write!(f, "invalid argument: {reason}"),
            Self::BadText => write!(f, "text field was not printable ASCII"),
            Self::IncorrectUnencryptedFlag => write!(f, "unencrypted flag had an incorrect value"),
            Self::PacketTypeMismatch { expected, actual } => write!(f, "packet type mismatch: expected {expected:?} but got {actual:?}"),
            Self::WrongBodyBufferSize { expected, buffer_size } => write!(f, "body buffer size didn't match length fields: expected {expected} bytes, but buffer was actually {buffer_size}"),
            Self::UnexpectedEnd => write!(f, "unexpected end of buffer when deserializing object"),
        }
    }
}

// Error trait is only available on std (on stable; stabilized in nightly 1.81) so this has to be std-gated
#[cfg(feature = "std")]
mod error_impls {
    use std::error::Error;
    use std::fmt;

    use super::text::InvalidText;
    use super::{DeserializeError, InvalidArgument, SerializeError};

    impl Error for DeserializeError {}
    impl Error for SerializeError {}
    impl Error for InvalidArgument {}
    impl Error for super::authentication::BadStart {}
    impl Error for super::authentication::DataTooLong {}
    impl<T> Error for InvalidText<T> where InvalidText<T>: fmt::Debug + fmt::Display {}
}

// suggestion from Rust API guidelines: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
// seals the PacketBody trait
mod sealed {
    use super::{accounting, authentication, authorization};
    use super::{Packet, PacketBody};

    pub trait Sealed {}

    // authentication packet types
    impl Sealed for authentication::Start<'_> {}
    impl Sealed for authentication::Continue<'_> {}
    impl Sealed for authentication::Reply<'_> {}

    // authorization packet bodies
    impl Sealed for authorization::Request<'_> {}
    impl Sealed for authorization::Reply<'_> {}

    // accounting packet bodies
    impl Sealed for accounting::Request<'_> {}
    impl Sealed for accounting::Reply<'_> {}

    // full packet type
    impl<B: PacketBody> Sealed for Packet<B> {}
}

/// The major version of the TACACS+ protocol.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MajorVersion {
    /// The only current major version specified in RFC8907.
    RFC8907 = 0xc,
}

impl fmt::Display for MajorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MajorVersion::RFC8907 => "RFC 8907",
            }
        )
    }
}

/// The minor version of the TACACS+ protocol in use, which specifies choices for authentication methods.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MinorVersion {
    /// Default minor version, used for ASCII authentication.
    Default = 0x0,
    /// Minor version 1, which is used for (MS)CHAP and PAP authentication.
    V1 = 0x1,
}

impl fmt::Display for MinorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Default => "default",
                Self::V1 => "1",
            }
        )
    }
}

/// The full protocol version.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct Version {
    /// The major TACACS+ version.
    major: MajorVersion,

    /// The minor TACACS+ version.
    minor: MinorVersion,
}

impl Version {
    /// Bundles together a TACACS+ protocol major and minor version.
    pub fn new(major: MajorVersion, minor: MinorVersion) -> Self {
        Self { major, minor }
    }
}

impl Default for Version {
    fn default() -> Self {
        Self {
            major: MajorVersion::RFC8907,
            minor: MinorVersion::Default,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "major {}, minor {}", self.major(), self.minor())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // compare major versions, then tiebreak with minor versions
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
    }
}

impl TryFrom<u8> for Version {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // only major version is 0xc currently
        if value >> 4 == MajorVersion::RFC8907 as u8 {
            let minor_version = match value & 0xf {
                0 => Ok(MinorVersion::Default),
                1 => Ok(MinorVersion::V1),
                _ => Err(DeserializeError::InvalidVersion(value)),
            }?;

            Ok(Self {
                major: MajorVersion::RFC8907,
                minor: minor_version,
            })
        } else {
            Err(DeserializeError::InvalidVersion(value))
        }
    }
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        ((value.major as u8) << 4) | (value.minor as u8 & 0xf)
    }
}

/// A type that can be treated as a TACACS+ protocol packet body.
///
/// This trait is sealed per the [Rust API guidelines], so it cannot be implemented by external types.
///
/// [Rust API guidelines]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait PacketBody: sealed::Sealed {
    /// Type of the packet (one of authentication, authorization, or accounting).
    const TYPE: PacketType;

    /// Length of body just including required fields.
    const REQUIRED_FIELDS_LENGTH: usize;

    /// Required protocol minor version based on the contents of the packet body.
    ///
    /// This is used since [`AuthenticationMethod`]s are partitioned by protocol minor version.
    fn required_minor_version(&self) -> Option<MinorVersion> {
        None
    }
}

/// Something that can be serialized into a binary format.
#[doc(hidden)]
pub trait Serialize: sealed::Sealed {
    /// Returns the current size of the packet as represented on the wire.
    fn wire_size(&self) -> usize;

    /// Serializes data into a buffer, returning the resulting length on success.
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError>;
}

/// Something that can be deserialized from a binary format.
#[doc(hidden)]
pub trait Deserialize<'raw>: sealed::Sealed + Sized {
    /// Attempts to deserialize an object from a buffer.
    fn deserialize_from_buffer(buffer: &'raw [u8]) -> Result<Self, DeserializeError>;
}
