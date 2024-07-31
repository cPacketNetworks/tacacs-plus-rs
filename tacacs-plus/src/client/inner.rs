//! The non-thread-safe internals of a client.

use std::future::Future;
use std::io;
use std::pin::Pin;

use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tacacs_plus_protocol::PacketFlags;

/// An async factory that returns connections used by a [`Client`](super::Client).
// pub type ConnectionFactory<S> = fn() -> Pin<Box<dyn Future<Output = io::Result<S>>>>;
pub type ConnectionFactory<S> = Box<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<S>>>>>;
// pub type ConnectionFactory<S, F: Future<Output = io::Result<S>>> = fn() -> Pin<Box<F>>;
// pub type ConnectionFactory2<S, F: Future<Output = io::Result<S>>> = fn() -> Pin<Box<F>>;

pub(super) struct ClientInner<S: AsyncRead + AsyncWrite + Unpin> {
    /// The underlying (normally TCP) connection for this client, if present.
    pub(super) connection: Option<S>,

    /// A factory for opening new connections internally, so the library consumer doesn't have to.
    connection_factory: ConnectionFactory<S>,

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
            single_connection_established: false,
        }
    }

    pub(super) async fn ensure_connection(&mut self) -> io::Result<()> {
        if self.connection.is_none() {
            let new_conn = (self.connection_factory)().await?;
            self.connection = Some(new_conn);
        }

        Ok(())
    }

    /// NOTE: This function is separate from post_session_cleanup since it has to be done after the first reply/second packet
    /// in a session, but ASCII authentication can span more packets.
    pub(super) fn update_single_connection(&mut self, flags: PacketFlags, sequence_number: u8) {
        if sequence_number == 2 && flags.contains(PacketFlags::SINGLE_CONNECTION) {
            self.single_connection_established = true;
        }
    }

    pub(super) async fn post_session_cleanup(&mut self) -> io::Result<()> {
        // close session if server doesn't agree to SINGLE_CONNECTION negotiation
        if !self.single_connection_established {
            // SAFETY: ensure_connection should be called before this function, and guarantees inner.connection is non-None
            let mut connection = self.connection.take().unwrap();
            connection.close().await?;
        }

        Ok(())
    }
}
