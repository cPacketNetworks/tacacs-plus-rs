use tacacs_plus_protocol::Argument;
use tacacs_plus_protocol::{authentication, authorization};

/// The final status returned by a server during a TACACS+ session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResponseStatus {
    /// The operation succeeded.
    Success,
    /// The operation failed.
    Failure,
}

/// A server response from an authentication session.
#[must_use = "Authentication failure is not reported as an error, so the status field must be checked."]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct AuthenticationResponse {
    /// Whether the authentication attempt passed or failed.
    pub status: ResponseStatus,

    /// The message returned by the server, intended to be displayed to the user.
    pub user_message: String,

    /// Extra data returned by the server.
    pub data: Vec<u8>,
}

/// A TACACS+ server response from an authorization session.
#[must_use = "The status of the response should be checked, since a failure is not reported as an error."]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct AuthorizationResponse {
    /// Whether the authorization attempt succeeded.
    pub status: ResponseStatus,

    /// The arguments returned from the server, if any.
    pub arguments: Vec<Argument<'static>>,

    /// A message that may be presented to a user connected to this client. (`server_msg` from RFC8907)
    pub user_message: String,

    /// Administrative console message from the server. (`data` from RFC8907)
    pub admin_message: String,
}

/// The response from a successful TACACS+ accounting operation.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccountingResponse {
    /// The message that can be displayed to the user, if any.
    pub user_message: String,

    /// An administrative log message.
    pub admin_message: String,
}

#[doc(hidden)]
pub struct BadAuthenticationStatus(pub(super) authentication::Status);

#[doc(hidden)]
impl TryFrom<authentication::Status> for ResponseStatus {
    type Error = BadAuthenticationStatus;

    fn try_from(value: authentication::Status) -> Result<Self, Self::Error> {
        match value {
            authentication::Status::Pass => Ok(ResponseStatus::Success),
            authentication::Status::Fail => Ok(ResponseStatus::Failure),

            // this is a lowercase "should" from RFC8907
            // (see section 5.4.3: https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.3-3)
            #[allow(deprecated)]
            authentication::Status::Follow => Ok(ResponseStatus::Failure),

            // we don't support restart status for now, so we treat it as a failure per RFC 8907
            // (see section 5.4.3 of RFC 8907: https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.3-6)
            authentication::Status::Restart => Ok(ResponseStatus::Failure),

            bad_status => Err(BadAuthenticationStatus(bad_status)),
        }
    }
}

#[doc(hidden)]
pub struct BadAuthorizationStatus(pub(super) authorization::Status);

#[doc(hidden)]
impl TryFrom<authorization::Status> for ResponseStatus {
    type Error = BadAuthorizationStatus;

    fn try_from(value: authorization::Status) -> Result<Self, Self::Error> {
        match value {
            authorization::Status::PassAdd | authorization::Status::PassReplace => {
                Ok(ResponseStatus::Success)
            }

            authorization::Status::Fail => Ok(ResponseStatus::Failure),

            // treat follow status as failure like in authentication
            // this might not be required by the RFC but is done for consistency
            #[allow(deprecated)]
            authorization::Status::Follow => Ok(ResponseStatus::Failure),

            bad_status => Err(BadAuthorizationStatus(bad_status)),
        }
    }
}
