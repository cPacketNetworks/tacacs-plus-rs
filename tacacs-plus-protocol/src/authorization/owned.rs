use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use super::{Reply, Status};
use crate::owned::FromBorrowedBody;
use crate::sealed::Sealed;
use crate::Argument;

/// An authorization reply packet with owned fields.
pub struct ReplyOwned {
    /// The status returned by the TACACS+ server.
    pub status: Status,

    /// The message to present to the user connected to this client.
    pub server_message: String,

    /// An administrative/console log message.
    pub data: String,

    /// The arguments sent by the server.
    pub arguments: Vec<Argument<'static>>,
}

impl Sealed for ReplyOwned {}

impl FromBorrowedBody for ReplyOwned {
    type Borrowed<'b> = Reply<'b>;

    fn from_borrowed(borrowed: &Self::Borrowed<'_>) -> Self {
        let arguments_vec = borrowed
            .iter_arguments()
            .map(Argument::into_owned)
            .collect();

        ReplyOwned {
            status: borrowed.status,
            server_message: borrowed.server_message.as_ref().to_owned(),
            data: borrowed.data.as_ref().to_owned(),
            arguments: arguments_vec,
        }
    }
}
