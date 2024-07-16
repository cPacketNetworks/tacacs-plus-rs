//! TACACS+ protocol packet <-> binary format conversions.

use core::{fmt, num::TryFromIntError};

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use getset::{CopyGetters, Getters};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

pub mod accounting;
pub mod authentication;
pub mod authorization;

mod arguments;
pub use arguments::{Argument, Arguments, InvalidArgument};

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

    /// Text field was not ASCII when it should have been.
    BadText,

    /// Invalid byte representation of an object.
    InvalidWireBytes,

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
            Self::PacketTypeMismatch { expected, actual } => write!(
                f,
                "packet type mismatch: expected {expected:?} but got {actual:?}"
            ),
            Self::InvalidWireBytes => write!(f, "invalid byte representation of object"),
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

/// Flags to indicate information about packets or the client/server.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PacketFlags(u8);

bitflags! {
    impl PacketFlags: u8 {
        /// Indicates the body of the packet is unobfuscated.
        const UNENCRYPTED       = 0b00000001;

        /// Signals to the server that the client would like to reuse a TCP connection across multiple sessions.
        const SINGLE_CONNECTION = 0b00000100;
    }
}

/// Information included in a TACACS+ packet header.
#[derive(PartialEq, Eq, Debug, Clone, CopyGetters)]
pub struct HeaderInfo {
    #[getset(get_copy = "pub")]
    /// The protocol major and minor version.
    version: Version,

    #[getset(get_copy = "pub")]
    /// The sequence number of the packet. This should be odd for client packets, and even for server packets.
    sequence_number: u8,

    #[getset(get_copy = "pub")]
    /// Session/packet flags.
    flags: PacketFlags,

    #[getset(get_copy = "pub")]
    /// ID of the current session.
    session_id: u32,
}

impl HeaderInfo {
    /// Size of a full TACACS+ packet header.
    const HEADER_SIZE_BYTES: usize = 12;

    /// Bundles some information to be put in the header of a TACACS+ packet.
    pub fn new(version: Version, sequence_number: u8, flags: PacketFlags, session_id: u32) -> Self {
        Self {
            version,
            sequence_number,
            flags,
            session_id,
        }
    }

    /// Serializes the information stored in a `HeaderInfo` struct, along with the supplemented information to form a complete header.
    fn serialize(
        &self,
        buffer: &mut [u8],
        packet_type: PacketType,
        body_length: u32,
    ) -> Result<usize, SerializeError> {
        // ensure buffer is large enough to store header
        if buffer.len() >= Self::HEADER_SIZE_BYTES {
            buffer[0] = self.version.into();
            buffer[1] = packet_type as u8;
            buffer[2] = self.sequence_number;
            buffer[3] = self.flags.bits();

            // session id is middle 4 bytes of header
            NetworkEndian::write_u32(&mut buffer[4..8], self.session_id);

            // body length goes at the end of the header (last 4 bytes)
            NetworkEndian::write_u32(&mut buffer[8..12], body_length);

            Ok(Self::HEADER_SIZE_BYTES)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

impl TryFrom<&[u8]> for HeaderInfo {
    type Error = DeserializeError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let header = Self {
            version: buffer[0].try_into()?,
            sequence_number: buffer[2],
            flags: PacketFlags::from_bits(buffer[3])
                .ok_or(DeserializeError::InvalidHeaderFlags(buffer[3]))?,
            session_id: NetworkEndian::read_u32(&buffer[4..8]),
        };

        Ok(header)
    }
}

/// The type of a protocol packet.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
pub enum PacketType {
    /// Authentication packet.
    Authentication = 0x1,

    /// Authorization packet.
    Authorization = 0x2,

    /// Accounting packet.
    Accounting = 0x3,
}

impl From<TryFromPrimitiveError<PacketType>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<PacketType>) -> Self {
        Self::InvalidPacketType(value.number)
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
pub trait Serialize {
    /// Returns the current size of the packet as represented on the wire.
    fn wire_size(&self) -> usize;

    /// Serializes data into a buffer, returning the resulting length on success.
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError>;
}

/// A full TACACS+ protocol packet.
#[derive(Getters, PartialEq, Eq, Debug)]
pub struct Packet<B: PacketBody> {
    /// Gets some of the header information associated with a packet.
    #[getset(get = "pub")]
    header: HeaderInfo,

    /// Gets the body of the packet.
    #[getset(get = "pub")]
    body: B,
}

impl<B: PacketBody> Packet<B> {
    /// Location of the start of the packet body, after the header.
    const BODY_START: usize = 12;

    /// Assembles a header and body into a full packet.
    ///
    /// NOTE: The version stored in the header may be updated depending on the body,
    /// as authentication start packets in particular may require a specific protocol
    /// minor version. Prefer using [`Packet::header()`] and reading the version from
    /// there rather than the `HeaderInfo` passed as an argument.
    pub fn new(mut header: HeaderInfo, body: B) -> Self {
        // update minor version to what is required by the body, if applicable
        if let Some(minor) = body.required_minor_version() {
            header.version.1 = minor;
        }

        Self { header, body }
    }
}

impl<B: PacketBody + Serialize> Serialize for Packet<B> {
    fn wire_size(&self) -> usize {
        HeaderInfo::HEADER_SIZE_BYTES + self.body.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        if buffer.len() >= self.wire_size() {
            // serialize body first to get its length, which is stored in the header
            let body_length = self
                .body
                .serialize_into_buffer(&mut buffer[HeaderInfo::HEADER_SIZE_BYTES..])?;

            // fill in header information
            let header_bytes = self.header.serialize(
                &mut buffer[..HeaderInfo::HEADER_SIZE_BYTES],
                B::TYPE,
                body_length.try_into()?,
            )?;

            // return total length written
            Ok(header_bytes + body_length)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

impl<'raw, B: PacketBody + TryFrom<&'raw [u8], Error = DeserializeError>> TryFrom<&'raw [u8]>
    for Packet<B>
{
    type Error = DeserializeError;

    fn try_from(buffer: &'raw [u8]) -> Result<Self, Self::Error> {
        if buffer.len() > HeaderInfo::HEADER_SIZE_BYTES {
            let header: HeaderInfo = buffer[..HeaderInfo::HEADER_SIZE_BYTES].try_into()?;

            let actual_packet_type = PacketType::try_from(buffer[1])?;
            if actual_packet_type == B::TYPE {
                // body length is stored at the end of the 12-byte header
                let body_length = NetworkEndian::read_u32(&buffer[8..12]) as usize;

                // ensure buffer actually contains whole body
                if buffer[Self::BODY_START..].len() >= body_length {
                    let body =
                        buffer[Self::BODY_START..Self::BODY_START + body_length].try_into()?;
                    Ok(Self::new(header, body))
                } else {
                    Err(DeserializeError::UnexpectedEnd)
                }
            } else {
                Err(DeserializeError::PacketTypeMismatch {
                    expected: B::TYPE,
                    actual: actual_packet_type,
                })
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
