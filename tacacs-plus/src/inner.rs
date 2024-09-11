//! The non-thread-safe internals of a client.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::Poll;

use byteorder::{ByteOrder, NetworkEndian};
use futures::poll;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tacacs_plus_protocol::{Deserialize, PacketBody, Serialize};
use tacacs_plus_protocol::{HeaderInfo, Packet, PacketFlags};

use super::ClientError;

#[cfg(test)]
mod tests;

/// A (pinned, boxed) future that returns a client connection or an error, as returned from a [`ConnectionFactory`].
///
/// This is roughly equivalent to the [`BoxFuture`](futures::future::BoxFuture) type in the `futures` crate, but without
/// the lifetime parameter.
pub type ConnectionFuture<S> = Pin<Box<dyn Future<Output = io::Result<S>> + Send>>;

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
/// use tacacs_plus::{ConnectionFactory, ConnectionFuture};
///
/// // function that returns a connection (in this case just a Cursor)
/// fn function_factory() -> ConnectionFuture<Cursor<Vec<u8>>> {
///     Box::pin(async {
///         let vec = Vec::new();
///         Ok(Cursor::new(vec))
///     })
/// }
///
/// // boxed function pointer
/// let _: ConnectionFactory<_> = Box::new(function_factory);
///
/// // closures work too
/// let _: ConnectionFactory<_> = Box::new(
///     || Box::pin(
///         async {
///             let vec: Vec<u8> = Vec::new();
///             Ok(Cursor::new(vec))
///         }
///     )
/// );
/// ```
pub type ConnectionFactory<S> = Box<dyn Fn() -> ConnectionFuture<S> + Send>;

pub(super) struct ClientInner<S> {
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

impl<S: fmt::Debug> fmt::Debug for ClientInner<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientInner")
            .field("connection", &self.connection)
            .field("first_session_completed", &self.first_session_completed)
            .field(
                "single_connection_established",
                &self.single_connection_established,
            )
            .finish_non_exhaustive()
    }
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
    async fn connection(&mut self) -> io::Result<&mut S> {
        // obtain new connection from factory
        if self.connection.is_none() {
            let new_conn = (self.connection_factory)().await?;
            self.connection = Some(new_conn);
        }

        // SAFETY: self.connection is guaranteed to be non-None by the above check
        let conn = self.connection.as_mut().unwrap();

        Ok(conn)
    }

    /// Writes a packet to the underlying connection, reconnecting if necessary.
    pub(super) async fn send_packet<B: PacketBody + Serialize>(
        &mut self,
        packet: Packet<B>,
        secret_key: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        // check if other end closed our connection, and reopen it accordingly
        let connection = self.connection().await?;
        if !is_connection_open(connection).await? {
            self.post_session_cleanup(true).await?;
        }

        // send the packet after ensuring the connection is valid (or dropping
        // it if it's invalid)
        self._send_packet(packet, secret_key).await
    }

    /// Writes a packet to the underlying connection.
    async fn _send_packet<B: PacketBody + Serialize>(
        &mut self,
        packet: Packet<B>,
        secret_key: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        // allocate zero-filled buffer large enough to hold packet
        let mut packet_buffer = vec![0; packet.wire_size()];

        // obfuscate packet if we have a secret key
        if let Some(key) = secret_key {
            packet.serialize(key, &mut packet_buffer)?;
        } else {
            packet.serialize_unobfuscated(&mut packet_buffer)?;
        }

        let connection = self.connection().await?;
        connection.write_all(&packet_buffer).await?;
        connection.flush().await.map_err(Into::into)
    }

    /// Receives a packet from the underlying connection.
    pub(super) async fn receive_packet<B>(
        &mut self,
        secret_key: Option<&[u8]>,
        expected_sequence_number: u8,
    ) -> Result<Packet<B>, ClientError>
    where
        B: PacketBody + for<'a> Deserialize<'a>,
    {
        let mut buffer = vec![0; HeaderInfo::HEADER_SIZE_BYTES];
        let buffer = &mut buffer;

        let connection = self.connection().await?;
        connection.read_exact(buffer).await?;

        // read rest of body based on length reported in header
        let body_length = NetworkEndian::read_u32(&buffer[8..12]);
        buffer.resize(HeaderInfo::HEADER_SIZE_BYTES + body_length as usize, 0);
        connection
            .read_exact(&mut buffer[HeaderInfo::HEADER_SIZE_BYTES..])
            .await?;

        // unobfuscate packet as necessary
        let deserialize_result: Packet<B> = if let Some(key) = secret_key {
            Packet::deserialize(key, buffer)?
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
            // SAFETY: connection() should be called before this function, and guarantees inner.connection is non-None
            let mut connection = self.connection.take().unwrap();
            connection.close().await?;

            // reset connection status "flags", as a new one will be opened for the next session
            self.single_connection_established = false;
            self.first_session_completed = false;
        } else if !self.first_session_completed {
            // connection was not closed, so we indicate that a session was completed on this connection to ignore
            // the single connection mode flag for future sessions on this connection, as required by RFC 8907.
            // (see section 4.3: https://www.rfc-editor.org/rfc/rfc8907.html#section-4.3-5)
            self.first_session_completed = true;
        }

        Ok(())
    }
}

/// Checks if the provided connection is still open on both sides.
///
/// This is accomplished by attempting to read a single byte from the connection
/// and checking for an EOF condition or specific errors (broken pipe/connection reset).
///
/// This might be overkill, but during testing I encountered a case where a write succeeded
/// and a subsequent read hung due to the connection being closed on the other side, so
/// avoiding that is preferable.
async fn is_connection_open<C>(connection: &mut C) -> io::Result<bool>
where
    C: AsyncRead + Unpin,
{
    // read into a 1-byte buffer, since a 0-byte buffer might return 0 besides just on EOF
    let mut buffer = [0];

    // poll the read future exactly once to see if anything is ready immediately
    match poll!(connection.read(&mut buffer)) {
        // something ready on first poll likely indicates something wrong, since we aren't
        // expecting any data to actually be ready
        Poll::Ready(ready) => match ready {
            // read of length 0 indicates an EOF, which happens when the other side closes a TCP connection
            Ok(0) => Ok(false),

            Err(e) => match e.kind() {
                // these errors indicate that the connection is closed, which is the exact
                // situation we're trying to recover from
                //
                // BrokenPipe seems to be Linux-specific (?), ConnectionReset is more general though
                // (checked TCP & read(2) man pages for MacOS/FreeBSD/Linux)
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => Ok(false),

                // bubble up any other errors to the caller
                _ => Err(e),
            },

            // if there's data still available, the connection is still open, although
            // this shouldn't happen in the context of TACACS+
            Ok(_) => Ok(true),
        },

        // nothing ready to read -> connection is still open
        Poll::Pending => Ok(true),
    }
}
