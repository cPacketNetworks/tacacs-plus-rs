//! An implementation of an RFC8907 TACACS+ client.

use std::sync::Arc;

use byteorder::{ByteOrder, NetworkEndian};
use futures::io;
use futures::lock::Mutex;
use futures::{AsyncRead, AsyncReadExt};
use futures::{AsyncWrite, AsyncWriteExt};
use rand::Rng;
use thiserror::Error;

use tacacs_plus_protocol::authentication;
use tacacs_plus_protocol::Serialize;
use tacacs_plus_protocol::{self as protocol, FieldText};
use tacacs_plus_protocol::{AuthenticationContext, AuthenticationService, UserInformation};
use tacacs_plus_protocol::{HeaderInfo, MajorVersion, MinorVersion, Version};
use tacacs_plus_protocol::{Packet, PacketBody, PacketFlags};

mod inner;
pub use inner::{ConnectionFactory, ConnectionFuture};

mod response;
pub use response::{AuthenticationResponse, ResponseStatus};

mod context;
pub use context::{ContextBuilder, SessionContext};

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

    /// TACACS+ protocol error, as reported from a server during authentication.
    #[error("error when performing TACACS+ authentication")]
    AuthenticationError {
        /// The status returned from the server, which will not be `Pass` or `Fail`.
        status: authentication::Status,

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

    /// The provided authentication password's length exceeded the valid range (i.e., 0 to `u8::MAX`).
    #[error("authentication password was longer than 255 bytes")]
    PasswordTooLong,

    /// Context had an invalid field.
    #[error("session context had invalid field(s)")]
    InvalidContext,

    /// Sequence number in reply did not match what was expected.
    #[error("sequence number mismatch: expected {expected}, got {actual}")]
    SequenceNumberMismatch {
        /// The packet sequence number expected from the server.
        expected: u8,
        /// The actual packet sequence number received from the server.
        actual: u8,
    },

    /// Sequence number overflowed in session.
    ///
    /// This termination is required per [section 4.1 of RFC8907].
    ///
    /// [section 4.1 of RFC8907]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.1-13.2.1
    #[error("sequence numberflow overflowed maximum, so session was terminated")]
    SequenceNumberOverflow,
}

/// The type of authentication used for a given session.
///
/// More of these might be added in the future, but the variants here are
/// the only currently supported authentication types with a [`Client`].
#[non_exhaustive]
pub enum AuthenticationType {
    /// Authentication via the Password Authentication Protocol (PAP).
    Pap,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Initializes a new TACACS+ client that uses the provided factory to open connections to a server.
    ///
    /// [RFC8907 section 10.5.1] specifies that clients SHOULD NOT allow secret keys less
    /// than 16 characters in length. This constructor does not check for that, but
    /// consider yourself warned.
    ///
    /// If no secret is provided in this constructor, the returned client does not obfuscate packets
    /// sent over the provided connection. Per [RFC8907 section 4.5], unobfuscated
    /// packet transfer MUST NOT be used in production, so prefer to provide a secret (of the proper length)
    /// where possible.
    ///
    /// [RFC8907 section 4.5]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.5-16
    pub fn new<K: AsRef<[u8]>>(
        connection_factory: ConnectionFactory<S>,
        secret: Option<K>,
    ) -> Self {
        let inner = inner::ClientInner::new(connection_factory);

        Self {
            inner: Arc::new(Mutex::new(inner)),
            secret: secret.map(|s| s.as_ref().to_owned()),
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
    async fn receive_packet<B>(
        &self,
        connection: &mut S,
        expected_sequence_number: u8,
    ) -> Result<Packet<B>, ClientError>
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

        let actual_sequence_number = deserialize_result.header().sequence_number();
        if actual_sequence_number == expected_sequence_number {
            Ok(deserialize_result)
        } else {
            Err(ClientError::SequenceNumberMismatch {
                expected: expected_sequence_number,
                actual: actual_sequence_number,
            })
        }
    }

    fn make_header(&self, sequence_number: u8, minor_version: MinorVersion) -> HeaderInfo {
        // generate random id for this session
        // rand::ThreadRng implements CryptoRng, so it should be suitable for use as a CSPRNG
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

    fn pap_login_start_packet<'packet>(
        &'packet self,
        context: &'packet SessionContext,
        password: &'packet str,
    ) -> Result<Packet<authentication::Start<'packet>>, ClientError> {
        use protocol::authentication::Action;

        Ok(Packet::new(
            // sequence number = 1 (first packet in session)
            self.make_header(1, MinorVersion::V1),
            authentication::Start::new(
                Action::Login,
                AuthenticationContext {
                    privilege_level: context.privilege_level,
                    authentication_type: protocol::AuthenticationType::Pap,
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
            // NOTE: The only possible `BadStart` variant passed to this function is `DataTooLong`,
            // since the authentication type & protocol version are guaranteed to be valid due to
            // being out of user control. The data field of a PAP start packet is exactly the password,
            // hence the conversion to `ClientError::PasswordTooLong`.
            .map_err(|_| ClientError::PasswordTooLong)?,
        ))
    }

    /// Authenticates against a TACACS+ server with a username and password using the specified protocol.
    pub async fn authenticate(
        &mut self,
        context: SessionContext,
        password: &str,
        authentication_type: AuthenticationType,
    ) -> Result<AuthenticationResponse, ClientError> {
        use protocol::authentication::ReplyOwned;

        let start_packet = match authentication_type {
            AuthenticationType::Pap => self.pap_login_start_packet(&context, password),
        }?;

        // block expression is used here to ensure that the connection mutex is only locked during communication
        let reply = {
            let mut inner = self.inner.lock().await;

            let connection = inner.connection().await?;

            self.write_packet(connection, start_packet).await?;

            // response: whether authentication succeeded
            let reply = self.receive_packet::<ReplyOwned>(connection, 2).await?;

            inner.set_internal_single_connect_status(reply.header());
            inner.post_session_cleanup(reply.body().status).await?;

            reply
        };

        let reply_status = ResponseStatus::try_from(reply.body().status);
        let message = reply.body().server_message.clone();
        let data = reply.body().data.clone();

        match reply_status {
            Ok(status) => Ok(AuthenticationResponse {
                status,
                message,
                data,
            }),
            Err(response::BadStatus(status)) => Err(ClientError::AuthenticationError {
                status,
                data,
                message,
            }),
        }
    }
}
