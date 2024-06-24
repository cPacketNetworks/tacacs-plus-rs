use std::io::{Read, Write};
use std::marker::PhantomData;

use crate::TacacsError;


pub struct ClientSession<S: Read + Write + Unpin + Send> {
    // The type parameter for the stream is unused until the TCP stream abstraction is in place
    // TODO: Remove
    connection: PhantomData<S>
    // pub(crate) connection: Connection<S>,
}

impl<S: Read + Write + Unpin + Send> ClientSession<S> {
    pub fn connect(tcp_stream: S) -> Result<ClientSession<S>, TacacsError> {
        let _ = tcp_stream; // TODO: remove
        todo!();
    }
}
