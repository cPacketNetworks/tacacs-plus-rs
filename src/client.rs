//! An implementation of an RFC8907 TACACS+ client.

// we don't have the std prelude since we're #![no_std], gotta import stuff manually
use std::borrow::ToOwned;
use std::vec;
use std::vec::Vec;

use byteorder::{ByteOrder, NetworkEndian};
use futures::io;
use futures::{AsyncRead, AsyncReadExt};
use futures::{AsyncWrite, AsyncWriteExt};
use thiserror::Error;

use crate::protocol::ToOwnedBody;
use crate::protocol::{self, HeaderInfo};
use crate::protocol::{Packet, PacketBody, Serialize};

/// A TACACS+ client.
pub struct Client<S: AsyncRead + AsyncWrite + Unpin> {
    /// The underlying TCP connection of the client.
    connection: S,

    /// The shared secret used for packet obfuscation, if provided.
    secret: Option<Vec<u8>>, // config necessary fields:
                             // - user info
                             // - obfuscation (or Option<Key>, probably Vec cause I'm so tired of no alloc)
                             // - session id (internal? like generated from randomness per session)
}

/// An error during a TACACS+ exchange.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ClientError {
    /// An error occurred when reading/writing a packet.
    #[error(transparent)]
    IOError(#[from] io::Error),

    // TODO: further specialization via enum?
    /// TACACS+ protocol error, e.g. an authentication failure.
    #[error("error in TACACS+ protocol exchange")]
    ProtocolError,

    /// Error when serializing a packet to the wire.
    #[error(transparent)]
    SerializeError(#[from] protocol::SerializeError),

    /// Invalid packet received from a server.
    #[error("invalid packet received from server: {0}")]
    InvalidPacket(#[from] protocol::DeserializeError),
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Initializes a new TACACS+ client.
    ///
    /// As no secrets is provided in this constructor, it does not obfuscate packets
    /// sent over the provided connection. Per [RFC8907 section 4.5], unobfuscated
    /// packet transfer MUST NOT be used in production; generally, you should prefer to
    /// use [`new_with_secret()`](Client::new_with_secret) instead.
    ///
    /// [RFC8907 section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.5-16
    pub fn new(connection: S) -> Self {
        Self {
            connection,
            secret: None,
        }
    }

    /// Initializes a new TACACS+ client with a shared secret for packet obfuscation.
    pub fn new_with_secret(connection: S, secret: &[u8]) -> Self {
        Self {
            connection,
            secret: Some(secret.to_owned()),
        }
    }

    async fn write_packet<B: PacketBody + Serialize>(
        &mut self,
        packet: Packet<B>,
    ) -> Result<(), ClientError> {
        // allocate zero-filled buffer large enough to hold packet
        let mut packet_buffer = vec![0; packet.wire_size()];

        // obfuscate packet if we have a secret key
        if let Some(secret_key) = &self.secret {
            packet.serialize(secret_key, &mut packet_buffer)?;
        } else {
            packet.serialize_unobfuscated(&mut packet_buffer)?;
        }

        self.connection
            .write_all(&packet_buffer)
            .await
            .map_err(Into::into)
    }

    async fn receive_packet<B>(&mut self) -> Result<Packet<B::Owned>, ClientError>
    where
        B: PacketBody
            + ToOwnedBody
            + for<'raw> TryFrom<&'raw [u8], Error = protocol::DeserializeError>,
        // B: PacketBody + ToOwnedBody + TryFrom<&'raw [u8], Error = protocol::DeserializeError>,
    {
        // start out by reading 12-byte header
        let mut packet_buffer = vec![0u8; HeaderInfo::HEADER_SIZE_BYTES];
        self.connection.read_exact(&mut packet_buffer).await?;

        // read rest of body based on length reported in header
        let body_length = NetworkEndian::read_u32(&packet_buffer[8..12]);
        packet_buffer.resize(HeaderInfo::HEADER_SIZE_BYTES + body_length as usize, 0);
        self.connection
            .read_exact(&mut packet_buffer[HeaderInfo::HEADER_SIZE_BYTES..])
            .await?;

        // unobfuscate packet as necessary
        // TODO: figure out how to return buffer while also referencing it (Pin?)
        let deserialize_result = if let Some(secret_key) = &self.secret {
            Packet::<B>::deserialize(secret_key, &mut packet_buffer)
        } else {
            Packet::deserialize_unobfuscated(&packet_buffer)
        };

        deserialize_result
            .map(|packet| packet.to_owned())
            .map_err(Into::into)
    }

    // TODO: return type?
    /// Authenticates against a TACACS+ server with a plaintext username & password.
    pub async fn authenticate_ascii(&mut self) {
        // TODO: select between (un)obfuscated serialization

        todo!()
    }
}
