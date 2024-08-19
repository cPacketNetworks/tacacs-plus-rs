use std::marker::Unpin;
use std::time::{Instant, SystemTime, SystemTimeError, UNIX_EPOCH};

use futures::{AsyncRead, AsyncWrite};
use tacacs_plus_protocol::accounting::{Flags, ReplyOwned, Request, Status};
use tacacs_plus_protocol::Packet;
use tacacs_plus_protocol::{Argument, Arguments, FieldText};
use tacacs_plus_protocol::{
    AuthenticationContext, AuthenticationService, AuthenticationType, MinorVersion,
};

use super::response::AccountingResponse;
use super::{Client, ClientError, SessionContext};

// Arguments specified in RFC8907 section 8.3.
/// Task ID, used for grouping together records from the same task.
const TASK_ID: &str = "task_id";

/// The time this task started as a Unix timestamp (seconds since the epoch).
const START_TIME: &str = "start_time";

/// The time this task stopped as a Unix timestamp.
const STOP_TIME: &str = "stop_time";

/// The time this task has taken so far, in seconds.
const ELAPSED_TIME: &str = "elapsed_time";

/// An ongoing task whose status is tracked via TACACS+ accounting.
#[must_use = "A task should eventually be marked as finished by calling the `stop()` method."]
pub struct AccountingTask<C> {
    /// The client associated with this task.
    client: C,

    /// The unique ID for this task.
    id: String,

    // TODO: this shouldn't be able to change during a task right?
    /// The context associated with this task.
    context: SessionContext,

    /// When this task was created/started.
    start_time: Instant,
}

/// Gets the Unix timestamp (in seconds) as a string, returning an error if
/// the system clock is set before the Unix epoch.
fn get_unix_timestamp_string() -> Result<String, SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> AccountingTask<&'a Client<S>> {
    /// Sends a start accounting record to the TACACS+ server, returning the resulting associated [`Task`].
    ///
    /// The `task_id` and `start_time` arguments from [RFC8907 section 8.3] are added internally.
    /// Note that setting `start_time` requires the system clock to be set after the Unix epoch; otherwise,
    /// an error is returned.
    ///
    /// This method should only be called once per task.
    pub(super) async fn start<'args, A: AsRef<[Argument<'args>]>>(
        client: &'a Client<S>,
        context: SessionContext,
        arguments: A,
    ) -> Result<(Self, AccountingResponse), ClientError> {
        let task = Self {
            client,
            id: uuid::Uuid::new_v4().to_string(),
            context,
            start_time: Instant::now(),
        };

        // prepend a couple of informational arguments specified in RFC 8907 section 8.3
        let mut full_arguments = vec![
            Argument::new(
                // SAFETY: both fields are known to always be valid ASCII (hardcoded/UUID)
                FieldText::try_from(TASK_ID).unwrap(),
                FieldText::try_from(&*task.id).unwrap(),
                true,
            )?,
            Argument::new(
                // SAFETY: both fields are known to always be valid ASCII (hardcoded/purely numeric)
                FieldText::try_from(START_TIME).unwrap(),
                FieldText::try_from(get_unix_timestamp_string()?).unwrap(),
                true,
            )?,
        ];
        full_arguments.extend_from_slice(arguments.as_ref());

        // perform accounting request with task info/arguments
        let response = task
            .make_request(Flags::StartRecord, full_arguments)
            .await?;

        Ok((task, response))
    }

    /// Sends an update to the TACACS+ server about this task with the provided arguments.
    ///
    /// The `task_id` and `elapsed_time` arguments from [RFC8907 section 8.3] are added internally.
    ///
    /// [RFC8907 section 8.3]: https://www.rfc-editor.org/rfc/rfc8907.html#name-accounting-arguments
    pub async fn update<'args, A: AsRef<[Argument<'args>]>>(
        &self,
        arguments: A,
    ) -> Result<AccountingResponse, ClientError> {
        let elapsed_secs = Instant::now().duration_since(self.start_time).as_secs();
        let mut full_arguments = vec![
            Argument::new(
                // SAFETY: both fields are known to always be valid ASCII (hardcoded/UUID)
                FieldText::try_from(TASK_ID).unwrap(),
                FieldText::try_from(&*self.id).unwrap(),
                true,
            )?,
            Argument::new(
                // SAFETY: both fields are known to always be valid ASCII (hardcoded/purely numeric)
                FieldText::try_from(ELAPSED_TIME).unwrap(),
                FieldText::try_from(elapsed_secs.to_string()).unwrap(),
                true,
            )?,
        ];
        full_arguments.extend_from_slice(arguments.as_ref());

        self.make_request(Flags::WatchdogUpdate, full_arguments)
            .await
    }

    /// Signals to the TACACS+ server that this task has completed.
    ///
    /// Since this should only be done once, this consumes the task.
    ///
    /// The `stop_time` and `task_id` arguments from [RFC8907 section 8.3] are also added internally.
    ///
    /// [RFC8907 section 8.3]: https://www.rfc-editor.org/rfc/rfc8907.html#name-accounting-arguments
    pub async fn stop<'args, A: AsRef<[Argument<'args>]>>(
        self,
        arguments: A,
    ) -> Result<AccountingResponse, ClientError> {
        let mut full_arguments = vec![
            // NOTE: TASK_ID + a random uuid should always constitute a valid argument
            // (name is nonempty/doesn't contain delimiter, length shouldn't overflow)
            Argument::new(
                // SAFETY: inputs are known to be valid ascii
                FieldText::try_from(TASK_ID).unwrap(),
                FieldText::try_from(&*self.id).unwrap(),
                true,
            )?,
            // NOTE: as above, this should always constitute a valid argument
            Argument::new(
                // SAFETY: both fields are known to be valid ASCII
                FieldText::try_from(STOP_TIME).unwrap(),
                FieldText::try_from(get_unix_timestamp_string()?).unwrap(),
                true,
            )?,
        ];
        full_arguments.extend_from_slice(arguments.as_ref());

        self.make_request(Flags::StopRecord, full_arguments).await
    }

    async fn make_request(
        &self,
        flags: Flags,
        arguments: Vec<Argument<'_>>,
    ) -> Result<AccountingResponse, ClientError> {
        // send accounting request & ensure reply ok
        let request_packet = Packet::new(
            self.client.make_header(1, MinorVersion::Default),
            Request::new(
                flags,
                self.context.authentication_method(),
                AuthenticationContext {
                    privilege_level: self.context.privilege_level,
                    authentication_type: AuthenticationType::NotSet,
                    // TODO: should we allow externally setting this?
                    service: AuthenticationService::Login,
                },
                self.context.as_user_information()?,
                Arguments::new(&arguments).ok_or(ClientError::TooManyArguments)?,
            ),
        );

        let reply = {
            let secret_key = self.client.secret.as_deref();

            let mut inner = self.client.inner.lock().await;
            inner.send_packet(request_packet, secret_key).await?;

            let reply: Packet<ReplyOwned> = inner.receive_packet(secret_key, 2).await?;

            // update inner state based on response
            inner.set_internal_single_connect_status(reply.header());
            inner
                .post_session_cleanup(reply.body().status == Status::Error)
                .await?;

            reply
        };

        match reply.body().status {
            Status::Success => Ok(AccountingResponse {
                user_message: reply.body().server_message.clone(),
                admin_message: reply.body().data.clone(),
            }),
            // NOTE: this also treats FOLLOW status as an error, which isn't directly specified by the RFC
            // but sort of mirrors the prescribed behavior for a FOLLOW in authentication
            bad_status => Err(ClientError::AccountingError {
                status: bad_status,
                user_message: reply.body().server_message.clone(),
                admin_message: reply.body().data.clone(),
            }),
        }
    }
}
