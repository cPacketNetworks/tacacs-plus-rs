//! The non-thread-safe internals of a client.

use std::future::Future;
use std::io;
use std::pin::Pin;

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tacacs_plus_protocol::{HeaderInfo, PacketFlags};

/// A (pinned, boxed) future that returns a client connection or an error, as returned from a [`ConnectionFactory`].
pub type ConnectionFuture<S> = Pin<Box<dyn Future<Output = io::Result<S>>>>;

/// An async factory that returns connections used by a [`Client`](super::Client).
///
/// The `Box` allows both closures and function pointers.
///
/// [Async closures are currently unstable](https://github.com/rust-lang/rust/issues/62290),
/// but you can emulate them with normal functions or closures that return `Box::pin`ned async blocks.
///
/// Rust's closure type inference can also fail sometimes, so either explicitly annotating
/// the type of a closure or passing it directly to a function call (e.g., [`Client::new()`](super::Client::new))
/// can fix that.
///
/// # Examples
///
/// ```
/// use futures::io::{Cursor, Result};
///
/// use tacacs_plus::client::{ConnectionFactory, ConnectionFuture};
///
/// // function that returns a connection (in this case just a Cursor)
/// fn function_factory() -> ConnectionFuture<Cursor<Vec<u8>>> {
///     Box::pin(async {
///         let vec = Vec::new();
///         Ok(Cursor::new(vec))
///     })
/// }
///
/// fn typechecks() {
///     // boxed function pointer
///     let _: ConnectionFactory<_> = Box::new(function_factory);
///
///     // closures work too
///     let _: ConnectionFactory<_> = Box::new(
///         || Box::pin(
///             async {
///                 let vec: Vec<u8> = Vec::new();
///                 Ok(Cursor::new(vec))
///             }
///         )
///     );
/// }
/// ```
pub type ConnectionFactory<S> = Box<dyn Fn() -> ConnectionFuture<S> + Send>;

pub(super) struct ClientInner<S: AsyncRead + AsyncWrite + Unpin> {
    /// The underlying (TCP per RFC8907) connection for this client, if present.
    connection: Option<S>,

    /// A factory for opening new connections internally, so the library consumer doesn't have to.
    ///
    /// The factory is invoked whenever a new connection needs to be established, including when an ERROR status
    /// is reported by the server as well as for each new session if the server doesn't support single connection mode.
    connection_factory: ConnectionFactory<S>,

    /// Whether a session has been completed on the contained connection.
    first_session_completed: bool,

    /// Whether single connection mode has been established for this connection.
    ///
    /// The single connection flag is meant to be ignored after the first two packets
    /// in a session according to [RFC8907 section 4.3], so we have to keep track of
    /// that internally.
    ///
    /// [RFC8907 section 4.3]: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.3-5
    single_connection_established: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ClientInner<S> {
    pub(super) fn new(factory: ConnectionFactory<S>) -> Self {
        Self {
            connection: None,
            connection_factory: factory,
            first_session_completed: false,
            single_connection_established: false,
        }
    }

    /// NOTE: This function will open a new connection with the stored factory as needed.
    pub(super) async fn connection(&mut self) -> io::Result<&mut S> {
        // obtain new connection from factory
        if self.connection.is_none() {
            let new_conn = (self.connection_factory)().await?;
            self.connection = Some(new_conn);
        }

        // SAFETY: self.connection is guaranteed to be non-None by the above check
        let conn = self.connection.as_mut().unwrap();

        Ok(conn)
    }

    /// NOTE: This function is separate from post_session_cleanup since it has to be done after the first reply/second packet
    /// in a session, but ASCII authentication can span more packets.
    pub(super) fn set_internal_single_connect_status(&mut self, header: &HeaderInfo) {
        // only update single connection status if this is the first reply of the first session of this connection
        if !self.first_session_completed
            && header.sequence_number() == 2
            && header.flags().contains(PacketFlags::SINGLE_CONNECTION)
        {
            self.single_connection_established = true;
        }
    }

    pub(super) async fn post_session_cleanup(&mut self, status_is_error: bool) -> io::Result<()> {
        // close session if server doesn't agree to SINGLE_CONNECTION negotiation, or if an error occurred (since a mutex guarantees only one session is going at a time)
        if !self.single_connection_established || status_is_error {
            // SAFETY: ensure_connection should be called before this function, and guarantees inner.connection is non-None
            let mut connection = self.connection.take().unwrap();
            connection.close().await?;

            // reset connection status "flags", as a new one will be opened for the next session
            self.single_connection_established = false;
            self.first_session_completed = false;
        } else {
            // connection was not closed, so we indicate that a session was completed on this connection to ignore
            // the single connection mode flag for future sessions on this connection, as required by RFC 8907.
            // (see section 4.3: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.3-5)
            self.first_session_completed = true;
        }

        Ok(())
    }
}
