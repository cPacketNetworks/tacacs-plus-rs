//! TACACS+ protocol packet <-> binary format conversions.

use core::fmt;

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

pub mod accounting;
pub mod authentication;
pub mod authorization;

mod arguments;
pub use arguments::{Argument, Arguments};

mod fields;
pub use fields::*;

/// An error that occurred when serializing a packet or any of its components into their binary format.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum SerializeError {
    /// The provided buffer did not have enough space to serialize the object.
    NotEnoughSpace,
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NotEnoughSpace => "not enough space in buffer",
        };

        write!(f, "{}", message)
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

    /// Invalid version number.
    InvalidVersion(u8),

    /// Mismatch between expected/received packet types.
    PacketTypeMismatch {
        /// The expected packet type.
        expected: PacketType,

        /// The actual packet type that was parsed.
        actual: PacketType,
    },

    /// Invalid byte representation of an object.
    InvalidWireBytes,

    /// Object representation was cut off in some way.
    UnexpectedEnd,

    /// There wasn't enough space in a target buffer.
    NotEnoughSpace,
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStatus(num) => write!(f, "invalid status byte in raw packet: {num:#x}"),
            Self::InvalidPacketType(num) => write!(f, "invalid packet type byte: {num:#x}"),
            Self::InvalidHeaderFlags(num) => write!(f, "invalid header flags: {num:#x}"),
            Self::InvalidVersion(num) => write!(
                f,
                "invalid version number: major {:#x}, minor {:#x}",
                num >> 4,
                num & 0xf
            ),
            Self::PacketTypeMismatch { expected, actual } => write!(
                f,
                "packet type mismatch: expected {expected:?} but got {actual:?}"
            ),
            Self::InvalidWireBytes => write!(f, "invalid byte representation of object"),
            Self::UnexpectedEnd => write!(f, "unexpected end of buffer when deserializing object"),
            Self::NotEnoughSpace => write!(f, "not enough space in provided buffer"),
        }
    }
}

// Error trait is only available on std (on stable; stabilized in nightly 1.81) so this has to be std-gated
#[cfg(feature = "std")]
mod error_impls {
    use std::error::Error;

    use super::{DeserializeError, SerializeError};

    impl Error for DeserializeError {}
    impl Error for SerializeError {}
}

// suggestion from Rust API guidelines: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
// seals the PacketBody trait
mod sealed_trait {
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
    /// The only current major version specified in RFC-8907.
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
    /// Gets the major TACACS+ version.
    pub fn major(&self) -> MajorVersion {
        self.0
    }

    /// Gets the minor TACACS+ version.
    pub fn minor(&self) -> MinorVersion {
        self.1
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// Size of universal packet flags on the wire.
    const WIRE_SIZE: usize = 1;
}

bitflags! {
    impl PacketFlags: u8 {
        /// Indicates the body of the packet is unobfuscated.
        const UNENCRYPTED       = 0b00000001;

        /// Signals to the server that the client would like to reuse a TCP connection across multiple sessions.
        const SINGLE_CONNECTION = 0b00000100;
    }
}

/// Information included in a TACACS+ packet header.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct HeaderInfo {
    /// The sequence number of the packet. This should be odd for client packets, and even for server packets.
    pub sequence_number: u8,

    /// Session/packet flags.
    pub flags: PacketFlags,

    /// ID of the current session.
    pub session_id: u32,
}

impl HeaderInfo {
    /// Size of a full TACACS+ packet header.
    const HEADER_SIZE_BYTES: usize = 12;

    /// Number of bytes written with a partial header serialization.
    ///
    /// Includes one for the sequence number, 1 for the packet flags, and 4 for the session id.
    const PARTIAL_SERIALIZE_NUM_BYTES: usize = 1 + PacketFlags::WIRE_SIZE + 4;

    /// Serializes the information stored in a `HeaderInfo` struct, which isn't the complete header (missing body length/packet type), hence the `_partial` suffix.
    fn serialize_partial(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        // NOTE: the full header size is compared against, despite the partial information only occupying 8 bytes of space (technically 7, but the type byte is skipped)
        // it doesn't make sense to partially serialize a buffer if it doesn't have space for a full header, hence the check against the full length
        if buffer.len() >= Self::HEADER_SIZE_BYTES {
            buffer[2] = self.sequence_number;
            buffer[3] = self.flags.bits();
            NetworkEndian::write_u32(&mut buffer[4..8], self.session_id);

            Ok(Self::PARTIAL_SERIALIZE_NUM_BYTES)
        } else {
            Err(SerializeError::NotEnoughSpace)
        }
    }
}

impl TryFrom<&[u8]> for HeaderInfo {
    type Error = DeserializeError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let header = Self {
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
pub trait PacketBody: sealed_trait::Sealed {
    /// Type of the packet (one of authentication, authorization, or accounting).
    const TYPE: PacketType;

    /// Length of body just including required fields.
    const REQUIRED_FIELDS_LENGTH: usize;

    /// Required protocol minor version based on the contents of the packet body.
    /// This really only exists since certain authentication methods are supposed to be gated by minor version.
    fn required_minor_version(&self) -> Option<MinorVersion> {
        None
    }
}

/// Something that can be serialized into a binary format.
pub trait Serialize {
    /// Returns the current size of the packet as represented on the wire.
    fn wire_size(&self) -> usize;

    /// Serializes data into a buffer, returning the resulting length on success or `NotEnoughSpace` on error.
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError>;
}

/// A full TACACS+ protocol packet.
#[derive(PartialEq, Eq, Debug)]
pub struct Packet<B: PacketBody> {
    header: HeaderInfo,
    body: B,
    version: Version,
}

impl<B: PacketBody> Packet<B> {
    /// Size of a TACACS+ packet header, in bytes.
    pub const HEADER_SIZE_BYTES: usize = 12;

    /// Assembles a header and body into a full packet.
    pub fn new(header: HeaderInfo, body: B) -> Self {
        let minor_version = body
            .required_minor_version()
            .unwrap_or(MinorVersion::Default);
        let version = Version(MajorVersion::RFC8907, minor_version);

        Self {
            header,
            body,
            version,
        }
    }

    /// Returns the header information of this packet.
    pub fn header(&self) -> &HeaderInfo {
        &self.header
    }

    /// Getter for the body of a packet.
    pub fn body(&self) -> &B {
        &self.body
    }

    /// Returns the protocol version of this packet.
    pub fn version(&self) -> Version {
        self.version
    }
}

impl<B: PacketBody + Serialize> Serialize for Packet<B> {
    fn wire_size(&self) -> usize {
        Self::HEADER_SIZE_BYTES + self.body.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        if buffer.len() >= self.wire_size() {
            // fill in header information
            let mut header_bytes = self.header.serialize_partial(buffer)?;

            buffer[0] = self.version.into();
            buffer[1] = B::TYPE as u8;
            header_bytes += 2;

            let body_length = self
                .body
                .serialize_into_buffer(&mut buffer[Self::HEADER_SIZE_BYTES..])?;

            // body length constitutes the last 4 bytes of the 12-byte header
            // filled in last to avoid making incorrect assumptions about the length of the body
            NetworkEndian::write_u32(&mut buffer[8..12], body_length.try_into().unwrap());
            header_bytes += 4;

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
        if buffer.len() > Self::HEADER_SIZE_BYTES {
            let header: HeaderInfo = buffer[..Self::HEADER_SIZE_BYTES].try_into()?;

            let actual_packet_type = PacketType::try_from(buffer[1])?;
            if actual_packet_type == B::TYPE {
                let body_length = NetworkEndian::read_u32(&buffer[8..12]) as usize;

                // TODO: figure out this check, it feels a bit fishy
                if body_length <= buffer[12..].len() {
                    let body = buffer[12..12 + body_length].try_into()?;
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
