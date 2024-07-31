use tacacs_plus_protocol::authentication;

#[doc(hidden)]
pub struct BadStatus;

// NOTE (for future): we could expose the same status for authentication/authorization,
// but accounting is called success instead so reusing that wouldn't be strictly correct
/// The status returned by a server during an authentication exchange.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthStatus {
    /// The authentication succeeded.
    Pass,
    /// The authentication attempt failed.
    Fail,
}

#[doc(hidden)]
impl TryFrom<authentication::Status> for AuthStatus {
    type Error = BadStatus;

    fn try_from(value: authentication::Status) -> Result<Self, Self::Error> {
        match value {
            authentication::Status::Pass => Ok(AuthStatus::Pass),
            authentication::Status::Fail => Ok(AuthStatus::Fail),

            // this is a lowercase "should" from RFC8907
            // (see section 5.4.3: https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.3-3)
            #[allow(deprecated)]
            authentication::Status::Follow => Ok(AuthStatus::Fail),

            // we don't support restart status for now, so we treat it as a failure per RFC 8907
            // (see section 5.4.3 of RFC 8907: https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.3-6)
            authentication::Status::Restart => Ok(AuthStatus::Fail),

            _ => Err(BadStatus),
        }
    }
}

/// A server response from an authentication session.
#[must_use = "At the very least, the authentication status must be checked, as an authentication failure is not reported as an error."]
#[derive(PartialEq, Eq, Debug)]
pub struct AuthResponse {
    /// Whether the authentication attempt passed or failed.
    pub status: AuthStatus,

    /// The message returned by the server, intended to be displayed to the user.
    pub server_message: String,

    /// Extra data returned by the server.
    pub data: Vec<u8>,
}
