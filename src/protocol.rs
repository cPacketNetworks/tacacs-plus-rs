//! TACACS+ protocol packet <-> binary format conversions.

use core::{fmt, num::TryFromIntError};

pub mod accounting;
pub mod authentication;
pub mod authorization;

mod packet;
pub use packet::header::HeaderInfo;
pub use packet::{Packet, PacketFlags, PacketType};

mod arguments;
pub use arguments::{Argument, Arguments, InvalidArgument};

#[cfg(feature = "std")]
pub use arguments::ArgumentOwned;

mod fields;
pub use fields::*;

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

    use super::{DeserializeError, InvalidArgument, SerializeError};

    impl Error for DeserializeError {}
    impl Error for SerializeError {}
    impl Error for InvalidArgument {}
    impl Error for super::authentication::BadStart {}
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MajorVersion {
    /// The only current major version specified in RFC8907.
    RFC8907 = 0xc,
}

/// The minor version of the TACACS+ protocol in use, which specifies choices for authentication methods.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinorVersion {
    /// Default minor version, used for ASCII authentication.
    Default = 0x0,
    /// Minor version 1, which is used for (MS)CHAP and PAP authentication.
    V1 = 0x1,
}

/// The full protocol version.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Version(MajorVersion, MinorVersion);

impl Version {
    /// Bundles together a TACACS+ protocol major and minor version.
    pub fn new(major: MajorVersion, minor: MinorVersion) -> Self {
        Self(major, minor)
    }

    /// Gets the major TACACS+ version.
    pub fn major(&self) -> MajorVersion {
        self.0
    }

    /// Gets the minor TACACS+ version.
    pub fn minor(&self) -> MinorVersion {
        self.1
    }
}

impl Default for Version {
    fn default() -> Self {
        Self(MajorVersion::RFC8907, MinorVersion::Default)
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

            Ok(Self(MajorVersion::RFC8907, minor_version))
        } else {
            Err(DeserializeError::InvalidVersion(value))
        }
    }
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        ((value.0 as u8) << 4) | (value.1 as u8 & 0xf)
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

// TODO: merge with PacketBody? would have to implement serialization of Reply packets though
// Might also be a good idea to bring deserialization in as well (to make it more explicit than TryFrom/TryInto)
/// Something that can be serialized into a binary format.
#[doc(hidden)]
trait Serialize: sealed::Sealed {
    /// Returns the current size of the packet as represented on the wire.
    fn wire_size(&self) -> usize;

    /// Serializes data into a buffer, returning the resulting length on success.
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError>;
}

/// Converts a reference-based packet to a packet that owns its fields.
///
/// A [`Borrow`](std::borrow::Borrow) impl for the different packet types would be nontrivial, if even possible,
/// which is why the [`ToOwned`](std::borrow::ToOwned) trait isn't used.
#[cfg(feature = "std")]
pub(crate) trait ToOwnedBody: PacketBody {
    /// The resulting owned packet type.
    type Owned;

    /// Converts the packet type with references to its data to one that owns its field data.
    fn to_owned(&self) -> Self::Owned;
}
