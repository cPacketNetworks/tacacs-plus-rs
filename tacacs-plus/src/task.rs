use std::marker::Unpin;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::{AsyncRead, AsyncWrite};
use tacacs_plus_protocol::accounting::{Flags, ReplyOwned, Request, Status};
use tacacs_plus_protocol::Arguments;
use tacacs_plus_protocol::Packet;
use tacacs_plus_protocol::{
    AuthenticationContext, AuthenticationService, AuthenticationType, MinorVersion,
};

use super::response::AccountingResponse;
use super::{Argument, Client, ClientError, SessionContext};

/// An ongoing task whose status is tracked via TACACS+ accounting.
pub struct Task<C> {
    /// The client associated with this task.
    client: C,

    /// The unique ID for this task.
    id: String,

    // TODO: this shouldn't be able to change during a task right?
    /// The context associated with this task.
    context: SessionContext,

    /// When this task was created, i.e., when it was started.
    start_time: SystemTime,
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> Task<&'a Client<S>> {
    /// Sends a start accounting record to the TACACS+ server, returning the resulting associated [`Task`].
    ///
    /// This method should only be called once per task.
    pub(super) async fn start<A: AsRef<[Argument]>>(
        client: &'a Client<S>,
        context: SessionContext,
        arguments: A,
    ) -> Result<(Self, AccountingResponse), ClientError> {
        let task = Self {
            client,
            id: uuid::Uuid::new_v4().to_string(),
            context,
            start_time: SystemTime::now(),
        };

        // prepend a couple of informational arguments specified in RFC 8907 section 8.3
        let mut full_arguments = vec![Argument {
            name: "task_id".to_owned(),
            value: task.id.clone(),
            required: true,
        }];
        if let Ok(start_time_epoch) = task.start_time.duration_since(UNIX_EPOCH) {
            full_arguments.push(Argument {
                name: "start_time".to_owned(),
                value: start_time_epoch.as_secs().to_string(),
                required: true,
            });
        }
        full_arguments.extend_from_slice(arguments.as_ref());

        // perform accounting request with task info/arguments
        let response = task
            .make_request(Flags::StartRecord, full_arguments)
            .await?;

        Ok((task, response))
    }

    /// Sends an update to the TACACS+ server about this task with the provided arguments.
    ///
    /// Certain arguments may be added internally, such as `task_id` and `elapsed_time` from [RFC8907 section 8.3].
    ///
    /// [RFC8907 section 8.3]: https://www.rfc-editor.org/rfc/rfc8907.html#name-accounting-arguments
    pub async fn update<A: AsRef<[Argument]>>(
        &self,
        arguments: A,
    ) -> Result<AccountingResponse, ClientError> {
        let mut full_arguments = vec![Argument {
            name: "task_id".to_string(),
            value: self.id.clone(),
            required: true,
        }];
        if let Ok(elapsed_time) = SystemTime::now().duration_since(self.start_time) {
            full_arguments.push(Argument {
                name: "elapsed_time".to_string(),
                value: elapsed_time.as_secs().to_string(),
                required: true,
            });
        }
        full_arguments.extend_from_slice(arguments.as_ref());

        self.make_request(Flags::WatchdogUpdate, full_arguments)
            .await
    }

    /// Signals to the TACACS+ server that this task has completed.
    ///
    /// Since this should only be done once, this consumes the task.
    ///
    /// Certain arguments may also be set internally, such as `stop_time` and `task_id`.
    pub async fn stop<A: AsRef<[Argument]>>(
        self,
        arguments: A,
    ) -> Result<AccountingResponse, ClientError> {
        let mut full_arguments = vec![Argument {
            name: "task_id".to_string(),
            value: self.id.clone(),
            required: true,
        }];

        if let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) {
            full_arguments.push(Argument {
                name: "stop_time".to_string(),
                value: timestamp.as_secs().to_string(),
                required: true,
            })
        }

        full_arguments.extend_from_slice(arguments.as_ref());

        self.make_request(Flags::StopRecord, full_arguments).await
    }

    async fn make_request(
        &self,
        flags: Flags,
        arguments: Vec<Argument>,
    ) -> Result<AccountingResponse, ClientError> {
        // borrow arguments as required by protocol crate
        let borrowed_arguments = arguments
            .iter()
            .map(Argument::borrowed)
            .collect::<Result<Vec<_>, _>>()?;

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
                Arguments::new(&borrowed_arguments).ok_or(ClientError::TooManyArguments)?,
            ),
        );

        let reply = {
            let mut inner = self.client.inner.lock().await;
            let connection = inner.connection().await?;

            self.client.write_packet(connection, request_packet).await?;

            let reply: Packet<ReplyOwned> = self.client.receive_packet(connection, 2).await?;

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
