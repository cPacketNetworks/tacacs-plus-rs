use futures::io;
use thiserror::Error;

use tacacs_plus_protocol as protocol;
use tacacs_plus_protocol::{accounting, authentication, authorization};

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
        user_message: String,
    },

    // TODO: more descriptive error message
    /// Error when performing authorization.
    #[error("error when performing TACACS+ authorization")]
    AuthorizationError {
        /// The status received from the server.
        status: authorization::Status,

        /// The message returned by the server, to be displayed to the user.
        user_message: String,

        /// The administrative log message returned from the server.
        admin_message: String,
    },

    /// Error when performing accounting.
    #[error("error when performing TACACS+ accounting")]
    AccountingError {
        /// The status returned by the server.
        status: accounting::Status,

        /// The message that can be displayed to the user connected to the client.
        user_message: String,

        /// An administrative log message from the server.
        admin_message: String,
    },

    /// Error when serializing a packet to the wire.
    #[error(transparent)]
    SerializeError(#[from] protocol::SerializeError),

    /// Invalid packet received from a server.
    #[error("invalid packet received from server: {0}")]
    InvalidPacketReceived(#[from] protocol::DeserializeError),

    /// Supplied data could not be encoded into a packet.
    #[error("packet could not be constructed from provided data")]
    InvalidPacketData,

    /// The provided authentication password's length exceeded the valid range (i.e., 0 to `u8::MAX`, less some other data stored in the same field).
    #[error("authentication data field (including password) was longer than 255 bytes")]
    PasswordTooLong,

    /// Too many arguments were provided to fit in a packet.
    #[error("only up to 255 (i.e., `u8::MAX`) arguments fit in a packet")]
    TooManyArguments,

    /// An invalid argument was provided.
    #[error(transparent)]
    InvalidArgument(#[from] protocol::InvalidArgument),

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

    /// The system time was set before the Unix epoch, which is problematic for generating
    /// timestamps during accounting.
    #[error("system time was set before Unix epoch")]
    SystemTimeBeforeEpoch(#[from] std::time::SystemTimeError),
}

// authentication data being too long is a direct result of the password being too long
// hidden since this is an implementation detail that isn't important to library consumers
#[doc(hidden)]
impl From<authentication::DataTooLong> for ClientError {
    fn from(_value: authentication::DataTooLong) -> Self {
        Self::PasswordTooLong
    }
}
