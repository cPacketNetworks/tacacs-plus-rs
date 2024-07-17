use core::iter::zip;

use md5::digest::generic_array::GenericArray;
use md5::{Digest, Md5};

use super::{HeaderInfo, Packet};
use super::{PacketBody, Serialize, SerializeError};

/// MD5 hash output size, in bytes.
const MD5_OUTPUT_SIZE: usize = 16;

// TODO: test
fn xor_slices(output: &mut [u8], pseudo_pad: &[u8]) {
    for (out, pad) in zip(output, pseudo_pad) {
        *out ^= pad;
    }
}

impl<B: PacketBody + Serialize> Packet<B> {
    /// Serializes a packet, obfuscating the body as specified in [RFC8907 section 4.5].
    ///
    /// [RFC8907 section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#name-data-obfuscation
    pub fn serialize_obfuscated(
        &self,
        buffer: &mut [u8],
        key: &[u8],
    ) -> Result<usize, SerializeError> {
        // TODO: ensure unencrypted flag is unset
        let encoded_length = self.serialize_into_buffer(buffer)?;

        let mut pseudo_pad = [0; MD5_OUTPUT_SIZE];

        // prehash common prefix for all hash invocations
        // prefix: session id -> key -> version -> sequence number
        let mut prefix_hasher = Md5::new();
        prefix_hasher.update(self.header.session_id.to_be_bytes());
        prefix_hasher.update(key);

        // technically these to_be_bytes calls don't do anything since both fields end up as `u8`s but still
        prefix_hasher.update(u8::from(self.header.version).to_be_bytes());
        prefix_hasher.update(self.header.sequence_number.to_be_bytes());

        let mut chunks_iter = buffer[HeaderInfo::HEADER_SIZE_BYTES..].chunks_mut(MD5_OUTPUT_SIZE);

        // first chunk just uses hashed prefix
        prefix_hasher
            .clone()
            .finalize_into((&mut pseudo_pad).into());

        // SAFETY: the body of a packet is guaranteed to be nonempty due to checks against REQUIRED_FIELD_SIZE,
        // so this unwrap won't panic
        let first_chunk = chunks_iter.next().unwrap();

        // xor pseudo-pad with chunk
        xor_slices(first_chunk, &pseudo_pad);

        for chunk in buffer[HeaderInfo::HEADER_SIZE_BYTES..].chunks_mut(MD5_OUTPUT_SIZE) {
            // previous pad chunk is appended to prefix prehashed above
            let mut hasher = prefix_hasher.clone();
            hasher.update(pseudo_pad);
            hasher.finalize_into((&mut pseudo_pad).into());

            // xor pseudo-pad with chunk
            xor_slices(chunk, &pseudo_pad);
        }

        Ok(encoded_length)
    }
}
