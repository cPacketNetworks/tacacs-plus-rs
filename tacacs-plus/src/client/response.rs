use tacacs_plus_protocol::authentication;

#[doc(hidden)]
pub struct BadStatus(pub(super) authentication::Status);

/// The final status returned by a server during a TACACS+ session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResponseStatus {
    /// The operation succeeded.
    Success,
    /// The operation failed.
    Failure,
}

#[doc(hidden)]
impl TryFrom<authentication::Status> for ResponseStatus {
    type Error = BadStatus;

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

            bad_status => Err(BadStatus(bad_status)),
        }
    }
}

/// A server response from an authentication session.
#[must_use = "Authentication failure is not reported as an error, so the status field must be checked."]
#[derive(PartialEq, Eq, Debug)]
pub struct AuthenticationResponse {
    /// Whether the authentication attempt passed or failed.
    pub status: ResponseStatus,

    /// The message returned by the server, intended to be displayed to the user.
    pub message: String,

    /// Extra data returned by the server.
    pub data: Vec<u8>,
}
