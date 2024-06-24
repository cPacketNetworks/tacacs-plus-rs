use std::marker::PhantomData;
use futures::{AsyncRead, AsyncWrite};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unknown Connection error")]
    Unknown,
}


pub struct AsyncClientSession<S: AsyncRead + AsyncWrite + Unpin + Send> {
    // The type parameter for the stream is unused until the TCP stream abstraction is in place
    // TODO: Remove
    connection: PhantomData<S>
    // pub(crate) connection: Connection<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncClientSession<S> {
    pub async fn connect(tcp_stream: S) -> Result<AsyncClientSession<S>, Error> {
        let _ = tcp_stream; // TODO: remove
        todo!();
    }
}
