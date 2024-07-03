use core::array::TryFromSliceError;

use bitflags::bitflags;

pub mod accounting;
pub mod authentication;
pub mod authorization;

mod arguments;
pub use arguments::{Argument, Arguments};

mod fields;
pub use fields::*;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct NotEnoughSpace(());

/// An error that occurred during deserialization of a full/partial packet.
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    InvalidWireBytes,
    UnexpectedEnd,
    LengthMismatch,
    NotEnoughSpace,
    // TODO: placement?
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

/// The major version of the TACACS+ protocol.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MajorVersion {
    TheOnlyVersion = 0xc,
}

/// The minor version of the TACACS+ protocol in use, which specifies choices for authentication methods.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinorVersion {
    Default = 0x0,
    V1 = 0x1,
}

/// The full protocol version.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Version(MajorVersion, MinorVersion);

impl Version {
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

            Ok(Self(MajorVersion::TheOnlyVersion, minor_version))
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

#[derive(Debug, PartialEq, Eq)]
pub struct HeaderFlags(u8);

bitflags! {
    impl HeaderFlags: u8 {
        const Unencrypted      = 0x01;
        const SingleConnection = 0x04;
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct HeaderInfo {
    pub version: Version,
    pub sequence_number: u8,
    pub flags: HeaderFlags,
    pub session_id: u32,
}

impl TryFrom<&[u8]> for HeaderInfo {
    type Error = DeserializeError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let version: Version = buffer[0].try_into()?;

        let header = Self {
            version,
            sequence_number: buffer[2],
            flags: HeaderFlags::from_bits(buffer[3]).ok_or(DeserializeError::InvalidWireBytes)?,
            session_id: u32::from_be_bytes(buffer[4..8].try_into()?),
        };

        Ok(header)
    }
}

#[repr(u8)]
pub enum PacketType {
    Authentication = 0x1,
    Authorization = 0x2,
    Accounting = 0x3,
}

pub trait PacketBody {
    /// Type of the packet (one of authentication, authorization, or accounting).
    const TYPE: PacketType;

    /// Minimum length of packet, in bytes.
    const MINIMUM_LENGTH: usize;

    /// Required protocol minor version based on the contents of the packet body.
    /// This really only exists since certain authentication methods are supposed to be gated by minor version.
    fn required_minor_version(&self) -> Option<MinorVersion> {
        None
    }
}

pub trait Serialize {
    /// Returns the current size of the packet as represented on the wire.
    fn wire_size(&self) -> usize;

    /// Serializes data into a buffer, returning the resulting length on success or `NotEnoughSpace` on error.
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace>;
}

// TODO: this is only implemented by authorization reply, remove maybe? I thought accounting did it too but guess not
pub trait DeserializeWithArguments<'raw> {
    fn deserialize_from_buffer(
        buffer: &'raw [u8],
        argument_space: &'raw mut [Argument<'raw>],
    ) -> Result<Self, DeserializeError>
    where
        Self: Sized + 'raw;
}

#[derive(PartialEq, Eq, Debug)]
pub struct Packet<B: PacketBody> {
    header: HeaderInfo,
    body: B,
}

impl<B: PacketBody> Packet<B> {
    pub const HEADER_SIZE_BYTES: usize = 12;

    pub fn new(header: HeaderInfo, body: B) -> Option<Self> {
        match body.required_minor_version() {
            Some(required_version) if header.version.1 != required_version => None,
            _ => Some(Self { header, body }),
        }
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

            buffer[4..8].copy_from_slice(self.header.session_id.to_be_bytes().as_slice());

            let body_length = self
                .body
                .serialize_into_buffer(&mut buffer[Self::HEADER_SIZE_BYTES..])?;
            buffer[8..12].copy_from_slice((body_length as u32).to_be_bytes().as_slice());

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

            let body_length = u32::from_be_bytes(buffer[8..12].try_into()?) as usize;

            if body_length <= buffer[12..].len() {
                let body = buffer[12..].try_into()?;
                Self::new(header, body).ok_or(DeserializeError::VersionMismatch)
            } else {
                Err(DeserializeError::LengthMismatch)
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

impl<'body, B: PacketBody + DeserializeWithArguments<'body> + 'body> DeserializeWithArguments<'body>
    for Packet<B>
{
    fn deserialize_from_buffer(
        buffer: &'body [u8],
        argument_space: &'body mut [Argument<'body>],
    ) -> Result<Self, DeserializeError> {
        if buffer.len() > Self::HEADER_SIZE_BYTES {
            let header: HeaderInfo = buffer[..Self::HEADER_SIZE_BYTES].try_into()?;

            let body_length = u32::from_be_bytes(buffer[8..12].try_into()?) as usize;

            if body_length <= buffer[12..].len() {
                let body =
                    B::deserialize_from_buffer(&buffer[12..12 + body_length], argument_space)?;

                Self::new(header, body).ok_or(DeserializeError::VersionMismatch)
            } else {
                Err(DeserializeError::LengthMismatch)
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
