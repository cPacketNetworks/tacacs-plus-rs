use std::io::{Read, Write};

use crate::TacacsError;

pub struct ClientSession<S: Read + Write + Unpin + Send> {
    // pub(crate) connection: Connection<S>,
}

impl<S: Read + Write + Unpin + Send> ClientSession<S> {
    pub fn connect(tcp_stream: S) -> Result<ClientSession<S>, TacacsError> {
        Ok(ClientSession {
            // connection: Connection::connect(_
        })
    }
}
