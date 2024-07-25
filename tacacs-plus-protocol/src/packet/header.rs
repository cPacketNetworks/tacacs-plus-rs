use byteorder::{ByteOrder, NetworkEndian};
use getset::{CopyGetters, MutGetters};

use super::{PacketFlags, PacketType};
use crate::{DeserializeError, SerializeError, Version};

/// Information included in a TACACS+ packet header.
#[derive(PartialEq, Eq, Debug, Clone, CopyGetters, MutGetters)]
pub struct HeaderInfo {
    #[getset(get_copy = "pub", get_mut = "pub(super)")]
    /// The protocol major and minor version.
    version: Version,

    #[getset(get_copy = "pub")]
    /// The sequence number of the packet. This should be odd for client packets, and even for server packets.
    sequence_number: u8,

    #[getset(get_copy = "pub", get_mut = "pub(super)")]
    /// Session/packet flags.
    flags: PacketFlags,

    #[getset(get_copy = "pub")]
    /// ID of the current session.
    session_id: u32,
}

impl HeaderInfo {
    /// Size of a full TACACS+ packet header.
    pub const HEADER_SIZE_BYTES: usize = 12;

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
    pub(super) fn serialize(
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
