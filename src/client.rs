//! An implementation of an RFC8907 TACACS+ client.

// we don't have the std prelude since we're #![no_std], gotta import stuff manually
use std::borrow::ToOwned;
use std::sync::Arc;
use std::vec;
use std::vec::Vec;

use byteorder::{ByteOrder, NetworkEndian};
use futures::io;
use futures::lock::Mutex;
use futures::{AsyncRead, AsyncReadExt};
use futures::{AsyncWrite, AsyncWriteExt};
use rand::Rng;
use thiserror::Error;

use crate::protocol::{self, HeaderInfo, MajorVersion, MinorVersion, Version};
use crate::protocol::{
    AuthenticationContext, AuthenticationService, AuthenticationType, PrivilegeLevel,
    UserInformation,
};
use crate::protocol::{Packet, PacketBody, PacketFlags};
use crate::protocol::{Serialize, ToOwnedBody};

/// A TACACS+ client.
#[derive(Clone)]
pub struct Client<S: AsyncRead + AsyncWrite + Unpin> {
    /// The underlying TCP connection of the client.
    connection: Arc<Mutex<S>>,

    /// The shared secret used for packet obfuscation, if provided.
    secret: Option<Vec<u8>>,
    // config necessary fields:
    // - user info? unless something standard used/supplied per exchange
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
    InvalidPacketReceived(#[from] protocol::DeserializeError),

    // TODO: break out into more specific other types
    /// Invalid packet field when attempting to send a packet.
    #[error("invalid packet field")]
    InvalidPacketField,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Initializes a new TACACS+ client on the given connection (should be TCP).
    ///
    /// A client expects exclusive access to the connection, so avoid cloning it or
    /// reusing the same connection for multiple purposes.
    ///
    /// As no secret is provided in this constructor, it does not obfuscate packets
    /// sent over the provided connection. Per [RFC8907 section 4.5], unobfuscated
    /// packet transfer MUST NOT be used in production; generally, you should prefer to
    /// use [`new_with_secret()`](Client::new_with_secret) instead.
    ///
    /// [RFC8907 section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.5-16
    pub fn new(connection: S) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
            secret: None,
        }
    }

    /// Initializes a new TACACS+ client with a shared secret for packet obfuscation.
    ///
    /// [RFC8907 section 10.5.1] specifies that clients SHOULD NOT allow secret keys less
    /// than 16 characters in length. This constructor does not check for that, but
    /// consider yourself warned.
    ///
    /// [RFC8907 section 10.5.1]: https://www.rfc-editor.org/rfc/rfc8907.html#section-10.5.1-3.8.1
    pub fn new_with_secret(connection: S, secret: &[u8]) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
            secret: Some(secret.to_owned()),
        }
    }

    async fn write_packet<B: PacketBody + Serialize>(
        &self,
        connection: &mut S,
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

        connection
            .write_all(&packet_buffer)
            .await
            .map_err(Into::into)
    }

    // TODO: explain how borrowed packet is used as generic parameter, but owned variant is what's returned
    async fn receive_packet<'raw, B>(
        &self,
        connection: &mut S,
        // TODO: figure out how not to pass buffer, if possible
        buffer: &'raw mut Vec<u8>,
    ) -> Result<Packet<B::Owned>, ClientError>
    where
        B: PacketBody + ToOwnedBody + TryFrom<&'raw [u8], Error = protocol::DeserializeError>,
    {
        // start out by reading 12-byte header
        buffer.resize(HeaderInfo::HEADER_SIZE_BYTES, 0);
        connection.read_exact(buffer).await?;

        // read rest of body based on length reported in header
        let body_length = NetworkEndian::read_u32(&buffer[8..12]);
        buffer.resize(HeaderInfo::HEADER_SIZE_BYTES + body_length as usize, 0);
        connection
            .read_exact(&mut buffer[HeaderInfo::HEADER_SIZE_BYTES..])
            .await?;

        // unobfuscate packet as necessary
        let deserialize_result: Packet<B> = if let Some(secret_key) = &self.secret {
            Packet::deserialize(secret_key, buffer)?
        } else {
            Packet::deserialize_unobfuscated(buffer)?
        };

        Ok(deserialize_result.to_owned())
    }

    /// Authenticates against a TACACS+ server with a plaintext username & password.
    pub async fn authenticate_pap_login(
        &mut self,
        username: &str,
        password: &str,
        privilege_level: PrivilegeLevel,
        // TODO: return type (bool or enum?)
    ) -> Result<bool, ClientError> {
        use protocol::authentication::owned::ReplyOwned;
        use protocol::authentication::{Action, Status};
        use protocol::authentication::{Reply, Start};

        // generate random id for this session
        let session_id: u32 = rand::thread_rng().gen();

        // packet 1: send username + password in START packet
        let start_packet = Packet::new(
            HeaderInfo::new(
                Version::new(MajorVersion::RFC8907, MinorVersion::V1),
                1,                              // first packet in session
                PacketFlags::SINGLE_CONNECTION, // TODO: unencrypted
                session_id,
            ),
            Start::new(
                Action::Login,
                AuthenticationContext {
                    privilege_level,
                    authentication_type: AuthenticationType::Pap,
                    service: AuthenticationService::Login,
                },
                // TODO: provided by caller?
                UserInformation::new(
                    username,
                    // SAFETY: constant strings are known to be valid printable ASCII
                    "tacacs-plus-rs".try_into().unwrap(),
                    "rust-tty0".try_into().unwrap(),
                )
                .ok_or(ClientError::InvalidPacketField)?,
                Some(password.as_bytes()),
            )
            .map_err(|_| ClientError::InvalidPacketField)?,
        );

        // block expression is used here to ensure that the connection mutex is only locked during communication
        let reply: Packet<ReplyOwned> = {
            let mut connection = self.connection.lock().await;

            self.write_packet(&mut connection, start_packet).await?;

            // response: whether authentication succeeded
            {
                let mut packet_buffer = Vec::new();
                self.receive_packet::<Reply<'_>>(&mut connection, &mut packet_buffer)
                    .await?
            }

            // TODO: check if single connection flag is set by server, and close connection based on rules RFC if not
            // also report error if connection is closed (maybe elsewhere?)
            // see https://www.rfc-editor.org/rfc/rfc8907.html#name-single-connection-mode
        };

        // TODO: return more information than just whether authentication succeeded (maybe full reply packet/body?)
        Ok(reply.body().status == Status::Pass)
    }
}
