use std::borrow::ToOwned;
use std::string::String;

use super::{Reply, Status};
use crate::owned::FromBorrowedBody;
use crate::sealed::Sealed;

/// An owned version of a [`Reply`](super::Reply).
pub struct ReplyOwned {
    /// The status returned by the server.
    pub status: Status,

    /// The message to display to the user.
    pub server_message: String,

    /// The console/administrative message from the server.
    pub data: String,
}

impl Sealed for ReplyOwned {}

impl FromBorrowedBody for ReplyOwned {
    type Borrowed<'b> = Reply<'b>;

    fn from_borrowed(borrowed: &Self::Borrowed<'_>) -> Self {
        ReplyOwned {
            status: borrowed.status,
            server_message: borrowed.server_message.as_ref().to_owned(),
            data: borrowed.data.as_ref().to_owned(),
        }
    }
}
