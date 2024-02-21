use futures::{AsyncRead, AsyncWrite};

pub struct AsyncClientSession<S: AsyncRead + AsyncWrite + Unpin + Send> {
    // pub(crate) connection: Connection<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncClientSession<S> {
    pub async fn connect(tcp_stream: S) -> Result<AsyncClientSession<S>> {
        Ok(AsyncClientSession {
            // connection: Connection::connect(_
        })
    }
}
