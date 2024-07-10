//! TACACS+ protocol packet <-> binary format conversions.

use core::array::TryFromSliceError;

use bitflags::bitflags;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

pub mod accounting;
pub mod authentication;
pub mod authorization;

mod arguments;
pub use arguments::{Argument, Arguments};

mod fields;
use byteorder::{ByteOrder, NetworkEndian};
pub use fields::*;

// Error trait is only available on std (on stable; stabilized in nightly 1.81) so this has to be std-gated
#[cfg(feature = "std")]
mod error_impls;

/// An error type indicating that there is not enough space to complete an operation.
#[derive(Debug)]
pub struct NotEnoughSpace(());

/// An error that occurred during deserialization of a full/partial packet.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    /// Invalid byte representation of an object.
    InvalidWireBytes,

    /// Object representation was cut off in some way.
    UnexpectedEnd,

    /// There wasn't enough space in a target buffer.
    NotEnoughSpace,

    /// Mismatch between expected/actual protocol versions, if relevant.
    VersionMismatch,
}

// Used in &[u8] -> &[u8; N] -> uNN conversions in reply deserialization
impl From<TryFromSliceError> for DeserializeError {
    fn from(_value: TryFromSliceError) -> Self {
        // slice conversion error means there was a length mismatch, which probably means we were expecting more data
        Self::UnexpectedEnd
    }
}

impl From<NotEnoughSpace> for DeserializeError {
    fn from(_value: NotEnoughSpace) -> Self {
        Self::NotEnoughSpace
    }
}

// TODO: limit to enums in crate via sealed trait or similar?
#[doc(hidden)]
impl<Enum: TryFromPrimitive<Primitive = u8>> From<TryFromPrimitiveError<Enum>>
    for DeserializeError
{
    fn from(_value: TryFromPrimitiveError<Enum>) -> Self {
        Self::InvalidWireBytes
    }
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
    /// Creates a full version from a major and minor version.
    pub fn of(major: MajorVersion, minor: MinorVersion) -> Self {
        Self(major, minor)
    }
}

impl TryFrom<u8> for Version {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // only major version is 0xc currently
        if value >> 4 == 0xc {
            let minor_version = match value & 0xf {
                0 => Ok(MinorVersion::Default),
                1 => Ok(MinorVersion::V1),
                _ => Err(DeserializeError::InvalidWireBytes),
            }?;

            Ok(Self(MajorVersion::RFC8907, minor_version))
        } else {
            Err(DeserializeError::InvalidWireBytes)
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

bitflags! {
    impl PacketFlags: u8 {
        /// Indicates the body of the packet is unobfuscated.
        const Unencrypted      = 0b00000001;

        /// Signals to the server that the client would like to reuse a TCP connection across multiple sessions.
        const SingleConnection = 0b00000100;
    }
}

/// Information included in a TACACS+ packet header.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct HeaderInfo {
    /// The packet's protocol version.
    pub version: Version,

    /// The sequence number of the packet. This should be odd for client packets, and even for server packets.
    pub sequence_number: u8,

    /// Session/packet flags.
    pub flags: PacketFlags,

    /// ID of the current session.
    pub session_id: u32,
}

impl TryFrom<&[u8]> for HeaderInfo {
    type Error = DeserializeError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let version: Version = buffer[0].try_into()?;

        let header = Self {
            version,
            sequence_number: buffer[2],
            flags: PacketFlags::from_bits(buffer[3]).ok_or(DeserializeError::InvalidWireBytes)?,
            session_id: u32::from_be_bytes(buffer[4..8].try_into()?),
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

/// A type that can be treated as a TACACS+ protocol packet body.
pub trait PacketBody {
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
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace>;
}

/// Something that includes arguments that can be deserialized from a binary arguments.
pub trait DeserializeWithArguments<'raw> {
    /// Attempts to deserialize an object from its binary format, storing its arguments in the provided slice.
    fn deserialize_from_buffer(
        buffer: &'raw [u8],
        argument_space: &'raw mut [Argument<'raw>],
    ) -> Result<Self, DeserializeError>
    where
        Self: Sized;
}

/// A full TACACS+ protocol packet.
#[derive(PartialEq, Eq, Debug)]
pub struct Packet<B: PacketBody> {
    header: HeaderInfo,
    body: B,
}

impl<B: PacketBody> Packet<B> {
    /// Size of a TACACS+ packet header, in bytes.
    pub const HEADER_SIZE_BYTES: usize = 12;

    /// Assembles a header and body into a packet, barring minor version incompatibility.
    pub fn new(header: HeaderInfo, body: B) -> Option<Self> {
        match body.required_minor_version() {
            Some(required_version) if header.version.1 != required_version => None,
            _ => Some(Self { header, body }),
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
}

impl<B: PacketBody + Serialize> Serialize for Packet<B> {
    fn wire_size(&self) -> usize {
        Self::HEADER_SIZE_BYTES + self.body.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            // fill in header information
            buffer[0] = self.header.version.into();
            buffer[1] = B::TYPE as u8;
            buffer[2] = self.header.sequence_number;
            buffer[3] = self.header.flags.bits();

            NetworkEndian::write_u32(&mut buffer[4..8], self.header.session_id);

            let body_length = self
                .body
                .serialize_into_buffer(&mut buffer[Self::HEADER_SIZE_BYTES..])?;

            NetworkEndian::write_u32(&mut buffer[8..12], body_length as u32);

            Ok(Self::HEADER_SIZE_BYTES + body_length)
        } else {
            Err(NotEnoughSpace(()))
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

            if PacketType::try_from(buffer[1])? == B::TYPE {
                let body_length = u32::from_be_bytes(buffer[8..12].try_into()?) as usize;

                if body_length <= buffer[12..].len() {
                    let body = buffer[12..12 + body_length].try_into()?;
                    Self::new(header, body).ok_or(DeserializeError::VersionMismatch)
                } else {
                    Err(DeserializeError::UnexpectedEnd)
                }
            } else {
                Err(DeserializeError::InvalidWireBytes)
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
