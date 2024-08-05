//! An implementation of an RFC8907 TACACS+ client.

use std::sync::Arc;

use byteorder::{ByteOrder, NetworkEndian};
use futures::lock::Mutex;
use futures::{AsyncRead, AsyncReadExt};
use futures::{AsyncWrite, AsyncWriteExt};
use rand::Rng;

use response::AuthorizationResponse;
use tacacs_plus_protocol as protocol;
use tacacs_plus_protocol::Serialize;
use tacacs_plus_protocol::{authentication, authorization};
use tacacs_plus_protocol::{ArgumentOwned, Arguments};
use tacacs_plus_protocol::{AuthenticationContext, AuthenticationMethod, AuthenticationService};
use tacacs_plus_protocol::{HeaderInfo, MajorVersion, MinorVersion, Version};
use tacacs_plus_protocol::{Packet, PacketBody, PacketFlags};

mod inner;
pub use inner::{ConnectionFactory, ConnectionFuture};

mod response;
pub use response::{AuthenticationResponse, ResponseStatus};

mod context;
pub use context::{ContextBuilder, SessionContext};

mod error;
pub use error::ClientError;

/// A TACACS+ client.
#[derive(Clone)]
pub struct Client<S: AsyncRead + AsyncWrite + Unpin> {
    /// The underlying TCP connection of the client.
    inner: Arc<Mutex<inner::ClientInner<S>>>,

    /// The shared secret used for packet obfuscation, if provided.
    secret: Option<Vec<u8>>,
}

/// The type of authentication used for a given session.
///
/// More of these might be added in the future, but the variants here are
/// the only currently supported authentication types with a [`Client`].
#[non_exhaustive]
pub enum AuthenticationType {
    /// Authentication via the Password Authentication Protocol (PAP).
    Pap,
    /// Authentication via the Challenge-Authentication Protocol (CHAP).
    Chap,
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
        &self,
        context: &'packet SessionContext,
        password: &'packet str,
    ) -> Result<Packet<authentication::Start<'packet>>, ClientError> {
        Ok(Packet::new(
            // sequence number = 1 (first packet in session)
            self.make_header(1, MinorVersion::V1),
            authentication::Start::new(
                authentication::Action::Login,
                AuthenticationContext {
                    privilege_level: context.privilege_level,
                    authentication_type: protocol::AuthenticationType::Pap,
                    service: AuthenticationService::Login,
                },
                context.as_user_information()?,
                Some(password.as_bytes().try_into()?),
            )
            // SAFETY: the version, authentication type & saction fields are hard-coded to valid values so the start constructor will not fail
            .unwrap(),
        ))
    }

    fn chap_login_start_packet<'packet>(
        &self,
        context: &'packet SessionContext,
        password: &'packet str,
    ) -> Result<Packet<authentication::Start<'packet>>, ClientError> {
        use md5::{Digest, Md5};

        // generate random PPP ID/challenge
        let ppp_id: u8 = rand::thread_rng().gen();
        let challenge = uuid::Uuid::new_v4();

        // "The Response Value is the one-way hash calculated over a stream of octets consisting of the Identifier,
        // followed by (concatenated with) the "secret", followed by (concatenated with) the Challenge Value."
        // RFC1334 section 3.2.1 ("Value" subheading): https://www.rfc-editor.org/rfc/rfc1334.html#section-3.2.1
        //
        // "The MD5 algorithm option is always used." (RFC8907 section 5.4.2.3)
        // https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.2.3-4
        let mut hasher = Md5::new();
        hasher.update([ppp_id]);
        hasher.update(password.as_bytes()); // the secret is the password in this case
        hasher.update(challenge);
        let response = hasher.finalize();

        // "the data field is a concatenation of the PPP id, the challenge, and the response"
        // RFC8907 section 5.4.2.3: https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.2.3-2
        let mut data = vec![ppp_id];
        data.extend(challenge.as_bytes());
        data.extend(response);

        Ok(Packet::new(
            self.make_header(1, MinorVersion::V1),
            authentication::Start::new(
                authentication::Action::Login,
                AuthenticationContext {
                    privilege_level: context.privilege_level,
                    authentication_type: protocol::AuthenticationType::Chap,
                    service: AuthenticationService::Login,
                },
                context.as_user_information()?,
                Some(data.try_into()?),
            )
            // SAFETY: the version, authentication type & action fields are hard-coded to valid values so the start constructor will not fail
            .unwrap(),
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
            AuthenticationType::Chap => self.chap_login_start_packet(&context, password),
        }?;

        // block expression is used here to ensure that the connection mutex is only locked during communication
        let reply = {
            let mut inner = self.inner.lock().await;

            let connection = inner.connection().await?;

            self.write_packet(connection, start_packet).await?;

            // response: whether authentication succeeded
            let reply = self.receive_packet::<ReplyOwned>(connection, 2).await?;

            inner.set_internal_single_connect_status(reply.header());
            inner
                .post_session_cleanup(reply.body().status == authentication::Status::Error)
                .await?;

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
            Err(response::BadAuthenticationStatus(status)) => {
                Err(ClientError::AuthenticationError {
                    status,
                    data,
                    message,
                })
            }
        }
    }

    /// Performs TACACS+ authorization against the server with the provided arguments.
    pub async fn authorize(
        &mut self,
        context: SessionContext,
        arguments: Vec<ArgumentOwned>,
    ) -> Result<AuthorizationResponse, ClientError> {
        use authorization::ReplyOwned;

        let borrowed_args = arguments
            .iter()
            .map(ArgumentOwned::borrowed)
            .collect::<Result<Vec<_>, _>>()?;

        let request_packet = Packet::new(
            self.make_header(1, MinorVersion::Default),
            authorization::Request::new(
                // TODO: allow consumer to specify auth method? we're probably not going to support any other methods though
                AuthenticationMethod::TacacsPlus,
                AuthenticationContext {
                    privilege_level: context.privilege_level,
                    authentication_type: protocol::AuthenticationType::NotSet,
                    service: AuthenticationService::Login,
                },
                context.as_user_information()?,
                Arguments::new(&borrowed_args).ok_or(ClientError::TooManyArguments)?,
            ),
        );

        let reply = {
            let mut inner = self.inner.lock().await;
            let connection = inner.connection().await?;

            self.write_packet(connection, request_packet).await?;

            let reply: Packet<ReplyOwned> = self.receive_packet(connection, 2).await?;

            inner.set_internal_single_connect_status(reply.header());
            inner
                .post_session_cleanup(reply.body().status == authorization::Status::Error)
                .await?;

            reply
        };

        let user_message = reply.body().server_message.clone();
        let admin_message = reply.body().data.clone();

        match ResponseStatus::try_from(reply.body().status) {
            // TODO: https://www.rfc-editor.org/rfc/rfc8907.html#section-6.2-3.6.2
            // we treat FOLLOW as failure anyways though so it might be irrelevant?
            Ok(status) => Ok(AuthorizationResponse {
                status,
                arguments: reply.body().arguments.clone(),
                user_message,
                admin_message,
            }),
            Err(response::BadAuthorizationStatus(status)) => Err(ClientError::AuthorizationError {
                status,
                user_message,
                admin_message,
            }),
        }
    }
}
