use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use super::Reply;
use super::Status;
use crate::ArgumentOwned;
use crate::ToOwnedBody;

/// An authorization reply packet with owned fields.
pub struct ReplyOwned {
    /// The status returned by the TACACS+ server.
    pub status: Status,

    /// The message to present to the user connected to this client.
    pub server_message: String,

    /// An administrative/console log message.
    pub data: String,

    /// The arguments sent by the server.
    pub arguments: Vec<ArgumentOwned>,
}

impl ToOwnedBody for Reply<'_> {
    type Owned = ReplyOwned;

    fn to_owned(&self) -> Self::Owned {
        let arguments_vec = self.iter_arguments().map(|arg| arg.to_owned()).collect();

        ReplyOwned {
            status: self.status,
            server_message: self.server_message.as_ref().to_owned(),
            data: self.data.as_ref().to_owned(),
            arguments: arguments_vec,
        }
    }
}
