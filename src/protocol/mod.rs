use bitflags::bitflags;

pub mod accounting;
pub mod authentication;
pub mod authorization;
pub mod common;

#[cfg(test)]
mod tests;

// TODO: move common into here
use common::{DeserializeError, NotEnoughSpace};

use self::common::ArgumentsArray;

// TODO: get version from packet body where it matters? e.g. ASCII vs. PAP auth
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MajorVersion {
    TheOnlyVersion = 0xc,
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinorVersion {
    Default = 0x0,
    V1 = 0x1,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Version(MajorVersion, MinorVersion);

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
    // TODO: method instead?
    pub minor_version: MinorVersion,
    pub sequence_number: u8,
    pub flags: HeaderFlags,
    pub session_id: u32,
}

#[repr(u8)]
pub enum PacketType {
    Authentication = 0x1,
    Authorization = 0x2,
    Accounting = 0x3,
}

pub trait PacketBody {
    const TYPE: PacketType;

    /// Minimum length of packet, in bytes.
    const MINIMUM_LENGTH: usize;

    fn required_minor_version(&self) -> Option<MinorVersion> {
        None
    }
}

// TODO: naming
pub trait Serialize {
    /// Returns the current size of the packet as represented on the wire.
    fn wire_size(&self) -> usize;
    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace>;
}

pub trait DeserializeWithArguments<'raw> {
    fn deserialize_from_buffer(
        buffer: &'raw [u8],
        argument_space: ArgumentsArray<'raw>,
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
            Some(required_version) if header.minor_version != required_version => None,
            _ => Some(Self { header, body }),
        }
    }
}

impl<B: PacketBody + Serialize> Serialize for Packet<B> {
    fn wire_size(&self) -> usize {
        Self::HEADER_SIZE_BYTES + self.body.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<(), NotEnoughSpace> {
        let body_length = self.body.wire_size();

        if buffer.len() >= self.wire_size() {
            // fill in header information
            buffer[0] = ((MajorVersion::TheOnlyVersion as u8) << 4)
                | (self.header.minor_version as u8) & 0xf;
            buffer[1] = B::TYPE as u8;
            buffer[2] = self.header.sequence_number;
            buffer[3] = self.header.flags.bits();

            buffer[4..8].copy_from_slice(self.header.session_id.to_be_bytes().as_slice());
            buffer[8..12].copy_from_slice((body_length as u32).to_be_bytes().as_slice());

            self.body.serialize_into_buffer(&mut buffer[12..])
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

impl<'body, B: PacketBody + DeserializeWithArguments<'body> + 'body> DeserializeWithArguments<'body>
    for Packet<B>
{
    fn deserialize_from_buffer(
        buffer: &'body [u8],
        argument_space: ArgumentsArray<'body>,
    ) -> Result<Self, DeserializeError> {
        if buffer.len() > Self::HEADER_SIZE_BYTES {
            let version: Version = buffer[0].try_into()?;

            let header = HeaderInfo {
                minor_version: version.1,
                sequence_number: buffer[2],
                flags: HeaderFlags::from_bits(buffer[3])
                    .ok_or(DeserializeError::InvalidWireBytes)?,
                session_id: u32::from_be_bytes(buffer[4..8].try_into()?),
            };

            let body_length = u32::from_be_bytes(buffer[8..12].try_into()?);

            if body_length as usize == buffer[12..].len() {
                let body = B::deserialize_from_buffer(
                    &buffer[12..12 + body_length as usize],
                    argument_space,
                )?;

                Self::new(header, body).ok_or(DeserializeError::VersionMismatch)
            } else {
                Err(DeserializeError::LengthMismatch)
            }
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}
