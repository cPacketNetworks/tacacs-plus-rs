//! An implementation of an RFC8907 TACACS+ client.

use std::sync::Arc;

use byteorder::{ByteOrder, NetworkEndian};
use futures::io;
use futures::lock::Mutex;
use futures::{AsyncRead, AsyncReadExt};
use futures::{AsyncWrite, AsyncWriteExt};
use rand::Rng;
use thiserror::Error;

use tacacs_plus_protocol::Serialize;
use tacacs_plus_protocol::{self as protocol, FieldText};
use tacacs_plus_protocol::{
    AuthenticationContext, AuthenticationService, AuthenticationType, UserInformation,
};
use tacacs_plus_protocol::{HeaderInfo, MajorVersion, MinorVersion, Version};
use tacacs_plus_protocol::{Packet, PacketBody, PacketFlags};

mod inner;
pub use inner::{ConnectionFactory, ConnectionFuture};

mod response;
pub use response::{AuthResponse, AuthStatus};

mod context;
pub use context::{SessionContext, SessionContextBuilder};

/// A TACACS+ client.
#[derive(Clone)]
pub struct Client<S: AsyncRead + AsyncWrite + Unpin> {
    /// The underlying TCP connection of the client.
    inner: Arc<Mutex<inner::ClientInner<S>>>,

    /// The shared secret used for packet obfuscation, if provided.
    secret: Option<Vec<u8>>,
}

/// An error during a TACACS+ exchange.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ClientError {
    /// An error occurred when reading/writing a packet.
    #[error(transparent)]
    IOError(#[from] io::Error),

    /// TACACS+ protocol error, e.g. an authentication failure.
    #[error("error in TACACS+ protocol exchange")]
    ProtocolError {
        /// The data received from the server.
        data: Vec<u8>,

        /// The message sent by the server.
        message: String,
    },

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

    /// Context had invalid field.
    #[error("session context had invalid field(s)")]
    InvalidContext,
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
    pub fn new(connection_factory: ConnectionFactory<S>) -> Self {
        let inner = inner::ClientInner::new(connection_factory);

        Self {
            inner: Arc::new(Mutex::new(inner)),
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
    pub fn new_with_secret(connection_factory: ConnectionFactory<S>, secret: &[u8]) -> Self {
        let inner = inner::ClientInner::new(connection_factory);

        Self {
            inner: Arc::new(Mutex::new(inner)),
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

        connection.write_all(&packet_buffer).await?;
        connection.flush().await.map_err(Into::into)
    }

    /// Receives a packet from the client's connection.
    async fn receive_packet<B>(&self, connection: &mut S) -> Result<Packet<B>, ClientError>
    where
        B: PacketBody + for<'a> protocol::Deserialize<'a>,
    {
        let mut buffer = vec![0; HeaderInfo::HEADER_SIZE_BYTES];
        let buffer = &mut buffer;
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

        Ok(deserialize_result)
    }

    fn make_header(&self, sequence_number: u8, minor_version: MinorVersion) -> HeaderInfo {
        // generate random id for this session
        let session_id: u32 = rand::thread_rng().gen();

        // set single connection/unencrypted flags accordingly
        let flags = if self.secret.is_some() {
            PacketFlags::SINGLE_CONNECTION
        } else {
            PacketFlags::SINGLE_CONNECTION | PacketFlags::UNENCRYPTED
        };

        HeaderInfo::new(
            Version::new(MajorVersion::RFC8907, minor_version),
            sequence_number,
            flags,
            session_id,
        )
    }

    /// Authenticates against a TACACS+ server with a plaintext username & password via the PAP protocol.
    ///
    /// NOTE: Even if this function returns `Ok`, the authentication may not have succeeded; make sure to check the
    /// [`status`](::tacacs_plus_protocol::authentication::ReplyOwned::status) field of the returned reply packet.
    pub async fn authenticate_pap_login(
        &mut self,
        context: SessionContext,
        password: &str,
    ) -> Result<AuthResponse, ClientError> {
        use protocol::authentication::Action;
        use protocol::authentication::{ReplyOwned, Start};

        // packet 1: send username + password in START packet
        let start_packet = Packet::new(
            // sequence number = 1 (first packet in session)
            self.make_header(1, MinorVersion::V1),
            Start::new(
                Action::Login,
                AuthenticationContext {
                    privilege_level: context.privilege_level,
                    authentication_type: AuthenticationType::Pap,
                    service: AuthenticationService::Login,
                },
                UserInformation::new(
                    &context.user,
                    FieldText::try_from(context.port.as_str())
                        .map_err(|_| ClientError::InvalidContext)?,
                    FieldText::try_from(context.remote_address.as_str())
                        .map_err(|_| ClientError::InvalidContext)?,
                )
                .ok_or(ClientError::InvalidContext)?,
                Some(password.as_bytes()),
            )
            .map_err(|_| ClientError::InvalidPacketField)?,
        );

        // block expression is used here to ensure that the connection mutex is only locked during communication
        let reply = {
            let mut inner = self.inner.lock().await;

            inner.ensure_connection().await?;

            // SAFETY: ensure_connection() ensures that inner.connection is non-None (or otherwise returns err, which will lead to an early exit)
            let connection = inner.connection.as_mut().unwrap();

            self.write_packet(connection, start_packet).await?;

            // response: whether authentication succeeded
            // TODO: check sequence number?
            let reply = self.receive_packet::<ReplyOwned>(connection).await?;

            // NOTE: we can't mutably borrow self completely here since the mutex lock borrows the connection field immutably
            inner.update_single_connection(reply.header());
            inner.post_session_cleanup().await?;

            reply
        };

        AuthStatus::try_from(reply.body().status)
            .map(|status| AuthResponse {
                status,
                server_message: reply.body().server_message.clone(),
                data: reply.body().data.clone(),
            })
            .map_err(|_| {
                // data & message are the only relevant fields of an error response
                ClientError::ProtocolError {
                    data: reply.body().data.clone(),
                    message: reply.body().server_message.clone(),
                }
            })
    }
}
