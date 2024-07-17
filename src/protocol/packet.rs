use core::iter::zip;

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use getset::Getters;
use md5::{Digest, Md5};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

// TODO: move packetflags into here?
use super::{DeserializeError, SerializeError};
use super::{PacketBody, Serialize};

pub(super) mod header;
use header::HeaderInfo;

/// Flags to indicate information about packets or the client/server.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PacketFlags(u8);

bitflags! {
    impl PacketFlags: u8 {
        /// Indicates the body of the packet is unobfuscated.
        ///
        /// Note that RFC 8907 specifies that "this option is deprecated and **MUST NOT** be used in production" ([section 4.5]).
        ///
        /// [section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.5-16
        const UNENCRYPTED       = 0b00000001;

        /// Signals to the server that the client would like to reuse a TCP connection across multiple sessions.
        const SINGLE_CONNECTION = 0b00000100;
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

#[doc(hidden)]
impl From<TryFromPrimitiveError<PacketType>> for DeserializeError {
    fn from(value: TryFromPrimitiveError<PacketType>) -> Self {
        Self::InvalidPacketType(value.number)
    }
}

/// A full TACACS+ protocol packet.
#[derive(Getters, Debug, PartialEq, Eq)]
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
    /// NOTE: Some fields in the provided header may be updated for consistency.
    /// These may include:
    /// - The protocol minor version, depending on authentication method choice
    /// - The [`UNENCRYPTED`](PacketFlags::UNENCRYPTED) flag, depending on if a key is specified
    pub fn new(mut header: HeaderInfo, body: B) -> Self {
        // update minor version to what is required by the body, if applicable
        if let Some(minor) = body.required_minor_version() {
            header.version.1 = minor;
        }

        Self { header, body }
    }
}

/// MD5 hash output size, in bytes.
const MD5_OUTPUT_SIZE: usize = 16;

/// Obfuscates the body of a packet as specified in [RFC8907 section 4.5].
///
/// [RFC8907 section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#name-data-obfuscation
fn obfuscate_body(header: &HeaderInfo, secret_key: &[u8], body_buffer: &mut [u8]) {
    let mut pseudo_pad = [0; MD5_OUTPUT_SIZE];

    // prehash common prefix for all hash invocations
    // prefix: session id -> key -> version -> sequence number
    let mut prefix_hasher = Md5::new();
    prefix_hasher.update(header.session_id.to_be_bytes());
    prefix_hasher.update(secret_key);

    // technically these to_be_bytes calls don't do anything since both fields end up as `u8`s but still
    prefix_hasher.update(u8::from(header.version).to_be_bytes());
    prefix_hasher.update(header.sequence_number.to_be_bytes());

    let mut chunks_iter = body_buffer.chunks_mut(MD5_OUTPUT_SIZE);

    // first chunk just uses hashed prefix
    prefix_hasher
        .clone()
        .finalize_into((&mut pseudo_pad).into());

    // SAFETY: the body of a packet is guaranteed to be nonempty due to checks against REQUIRED_FIELD_SIZE,
    // so this unwrap won't panic
    let first_chunk = chunks_iter.next().unwrap();

    // xor pseudo-pad with chunk
    xor_slices(first_chunk, &pseudo_pad);

    for chunk in chunks_iter {
        // previous pad chunk is appended to prefix prehashed above
        let mut hasher = prefix_hasher.clone();
        hasher.update(pseudo_pad);
        hasher.finalize_into((&mut pseudo_pad).into());

        // xor pseudo-pad with chunk
        xor_slices(chunk, &pseudo_pad);
    }
}

fn xor_slices(output: &mut [u8], pseudo_pad: &[u8]) {
    for (out, pad) in zip(output, pseudo_pad) {
        *out ^= pad;
    }
}

impl<B: PacketBody + Serialize> Packet<B> {
    /// Calculates the size of this packet as encoded into its binary format.
    pub fn wire_size(&self) -> usize {
        HeaderInfo::HEADER_SIZE_BYTES + self.body.wire_size()
    }

    /// Serializes the packet into a buffer, obfuscating the body using a pseudo-pad generated by iterating the MD5 hash function.
    ///
    /// This consumes the packet and also ensures the [`UNENCRYPTED`](PacketFlags::UNENCRYPTED) flag is unset.
    pub fn serialize<K: AsRef<[u8]>>(
        mut self,
        secret_key: K,
        buffer: &mut [u8],
    ) -> Result<usize, SerializeError> {
        // remove unencrypted flag from header
        self.header.flags.remove(PacketFlags::UNENCRYPTED);

        let packet_length = self.serialize_packet(buffer)?;

        obfuscate_body(
            &self.header,
            secret_key.as_ref(),
            &mut buffer[HeaderInfo::HEADER_SIZE_BYTES..packet_length],
        );

        Ok(packet_length)
    }

    /// Serializes the packet into a buffer, leaving the body as cleartext.
    ///
    /// This consumes the packet and sets the [`UNENCRYPTED`](PacketFlags::UNENCRYPTED) flag if necessary.
    ///
    /// Note that RFC8907 deprecated the UNENCRYPTED flag and states that it "**MUST NOT** be used in production" ([section 4.5]).
    ///
    /// [section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.5-16
    pub fn serialize_unobfuscated(mut self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        // ensure unencrypted flag is set
        self.header.flags.insert(PacketFlags::UNENCRYPTED);

        self.serialize_packet(buffer)
    }

    fn serialize_packet(&self, buffer: &mut [u8]) -> Result<usize, SerializeError> {
        let wire_size = self.wire_size();

        if buffer.len() >= wire_size {
            // serialize body first to get its length, which is stored in the header
            let body_length = self
                .body
                .serialize_into_buffer(&mut buffer[HeaderInfo::HEADER_SIZE_BYTES..wire_size])?;

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

// TODO: separate lifetime for key? probably fine to keep the same but still check
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
                    // FIXME: properly deserialize obfuscated packets with key, probably not in TryFrom impl but instead via inherent method
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
