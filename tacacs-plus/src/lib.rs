//! # tacacs-plus
//!
//! Rust client implementation for the TACACS+ ([RFC8907](https://www.rfc-editor.org/rfc/rfc8907)) protocol.

#![warn(missing_docs)]

use std::fmt;
use std::sync::Arc;

use futures::lock::Mutex;
use futures::{AsyncRead, AsyncWrite};
use rand::Rng;

use tacacs_plus_protocol::Arguments;
use tacacs_plus_protocol::{authentication, authorization};
use tacacs_plus_protocol::{AuthenticationContext, AuthenticationService};
use tacacs_plus_protocol::{HeaderInfo, MajorVersion, MinorVersion, Version};
use tacacs_plus_protocol::{Packet, PacketFlags};

mod inner;
pub use inner::{ConnectionFactory, ConnectionFuture};

mod response;
pub use response::{
    AccountingResponse, AuthenticationResponse, AuthorizationResponse, ResponseStatus,
};

mod context;
pub use context::{ContextBuilder, SessionContext};

mod error;
pub use error::ClientError;

mod task;
pub use task::AccountingTask;

// reexported for ease of access
pub use tacacs_plus_protocol as protocol;
pub use tacacs_plus_protocol::{Argument, AuthenticationMethod, FieldText};

/// A TACACS+ client.
#[derive(Clone)]
pub struct Client<S> {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// If an incorrect secret is provided to this constructor, you might notice
    /// [`ClientError::InvalidPacketReceived`] errors when attempting different TACACS+ operations.
    /// Specific inner error variants in such cases could be
    /// [`WrongBodyBufferSize`](tacacs_plus_protocol::DeserializeError::WrongBodyBufferSize) or
    /// [`BadText`](tacacs_plus_protocol::DeserializeError::BadText).
    ///
    /// Additionally, if a secret is provided in this constructor but one is not configured for the remote TACACS+ server,
    /// or vice versa, you will again see [`ClientError::InvalidPacketReceived`] errors, but rather with an inner error variant of
    /// [`DeserializeError::IncorrectUnencryptedFlag`](tacacs_plus_protocol::DeserializeError::IncorrectUnencryptedFlag).
    ///
    /// If no secret is provided in this constructor, the returned client does not obfuscate packets
    /// sent over the provided connection. Per [RFC8907 section 4.5], unobfuscated
    /// packet transfer MUST NOT be used in production, so prefer to provide a secret (of a secure length)
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
        use protocol::authentication::BadStart;

        Ok(Packet::new(
            // sequence number = 1 (first packet in session)
            // also set minor version accordingly
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
            .map_err(|err| match err {
                // SAFETY: the version, authentication type & saction fields are hard-coded to valid values so neither of these errors can occur
                BadStart::AuthTypeNotSet | BadStart::IncompatibleActionAndType => unreachable!(),
                // we have to have a catch-all case since BadStart is marked #[non_exhaustive]
                _ => ClientError::InvalidPacketData,
            })?,
        ))
    }

    fn chap_login_start_packet<'packet>(
        &self,
        context: &'packet SessionContext,
        password: &'packet str,
    ) -> Result<Packet<authentication::Start<'packet>>, ClientError> {
        use md5::{Digest, Md5};
        use protocol::authentication::BadStart;

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
            .map_err(|err| match err {
                // SAFETY: the version, authentication type & action fields are hard-coded to valid values so the start constructor will not fail
                BadStart::AuthTypeNotSet | BadStart::IncompatibleActionAndType => unreachable!(),
                _ => ClientError::InvalidPacketData,
            })?,
        ))
    }

    /// Authenticates against a TACACS+ server with a username and password using the specified protocol.
    pub async fn authenticate(
        &self,
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
            let secret_key = self.secret.as_deref();

            let mut inner = self.inner.lock().await;
            inner.send_packet(start_packet, secret_key).await?;

            // response: whether authentication succeeded
            let reply = inner.receive_packet::<ReplyOwned>(secret_key, 2).await?;

            inner.set_internal_single_connect_status(reply.header());
            inner
                .post_session_cleanup(reply.body().status == authentication::Status::Error)
                .await?;

            reply
        };

        let reply_status = ResponseStatus::try_from(reply.body().status);
        let user_message = reply.body().server_message.clone();
        let data = reply.body().data.clone();

        match reply_status {
            Ok(status) => Ok(AuthenticationResponse {
                status,
                user_message,
                data,
            }),
            Err(response::BadAuthenticationStatus(status)) => {
                Err(ClientError::AuthenticationError {
                    status,
                    data,
                    user_message,
                })
            }
        }
    }

    /// Performs TACACS+ authorization against the server with the provided arguments.
    ///
    /// A merged `Vec` of all of the sent and received arguments is returned, with values replaced from
    /// the server as necessary. No guarantees are made for the replacement of several arguments with
    /// the same name, however, since even RFC8907 doesn't specify how to handle that case.
    pub async fn authorize(
        &self,
        context: SessionContext,
        arguments: Vec<Argument<'_>>,
    ) -> Result<AuthorizationResponse, ClientError> {
        use authorization::ReplyOwned;

        let request_packet = Packet::new(
            // use default minor version, since there's no reason to use v1 outside of authentication
            self.make_header(1, MinorVersion::Default),
            authorization::Request::new(
                context.authentication_method(),
                AuthenticationContext {
                    privilege_level: context.privilege_level,
                    authentication_type: protocol::AuthenticationType::NotSet,
                    // TODO: allow this to be specified as well? for guest it should probably be none
                    service: AuthenticationService::Login,
                },
                context.as_user_information()?,
                Arguments::new(&arguments).ok_or(ClientError::TooManyArguments)?,
            ),
        );

        // the inner mutex is locked within a block to ensure it's only locked as long as necessary
        let reply = {
            let secret_key = self.secret.as_deref();

            let mut inner = self.inner.lock().await;
            inner.send_packet(request_packet, secret_key).await?;

            let reply: Packet<ReplyOwned> = inner.receive_packet(secret_key, 2).await?;

            // update inner state based on response
            inner.set_internal_single_connect_status(reply.header());
            inner
                .post_session_cleanup(reply.body().status == authorization::Status::Error)
                .await?;

            reply
        };

        let packet_status = reply.body().status;
        let user_message = reply.body().server_message.clone();
        let admin_message = reply.body().data.clone();

        match ResponseStatus::try_from(packet_status) {
            Ok(status) => {
                let owned_arguments = arguments.into_iter().map(Argument::into_owned).collect();

                let merged_arguments = merge_authorization_arguments(
                    packet_status == authorization::Status::PassReplace,
                    owned_arguments,
                    reply.body().arguments.clone(),
                );

                Ok(AuthorizationResponse {
                    status,
                    arguments: merged_arguments,
                    user_message,
                    admin_message,
                })
            }
            Err(response::BadAuthorizationStatus(status)) => Err(ClientError::AuthorizationError {
                status,
                user_message,
                admin_message,
            }),
        }
    }

    /// Starts tracking a task via the TACACS+ accounting mechanism.
    ///
    /// The `task_id` and `start_time` arguments specified in [RFC8907 section 8.3] are set internally in addition
    /// to the provided arguments.
    ///
    /// This function only sends a start record to a TACACS+ server; the [`update()`](AccountingTask::update) and
    /// [`stop()`](AccountingTask::stop) methods on the returned [`AccountingTask`] should be used for sending
    /// additional accounting records.
    ///
    /// [RFC8907 section 8.3]: https://www.rfc-editor.org/rfc/rfc8907.html#name-accounting-arguments
    pub async fn account_begin<'args, A: AsRef<[Argument<'args>]>>(
        &self,
        context: SessionContext,
        arguments: A,
    ) -> Result<(AccountingTask<&Self>, AccountingResponse), ClientError> {
        AccountingTask::start(self, context, arguments).await
    }
}

impl<S: fmt::Debug> fmt::Debug for Client<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // adapted from std mutex impl
        let inner_debug = match self.inner.try_lock() {
            Some(inner) => format!("{inner:?}"),
            None => String::from("(locked)"),
        };

        // we explicitly omit the secret here to avoid exposing it
        f.debug_struct("Client")
            .field("inner", &inner_debug)
            .finish_non_exhaustive()
    }
}

/// Merges the sent & received arguments within a successful authorization session.
///
/// Note that this assumes there are no duplicate arguments, as even RFC8907 is unclear
/// on how to handle that case.
fn merge_authorization_arguments(
    replacing: bool,
    mut sent_arguments: Vec<Argument<'static>>,
    mut received_arguments: Vec<Argument<'static>>,
) -> Vec<Argument<'static>> {
    if replacing {
        for received in received_arguments.into_iter() {
            if let Some(sent) = sent_arguments
                .iter_mut()
                .find(|arg| arg.name() == received.name())
            {
                sent.set_value(received.value().clone());
            } else {
                sent_arguments.push(received);
            }
        }
    } else {
        sent_arguments.append(&mut received_arguments);
    }
    sent_arguments
}
