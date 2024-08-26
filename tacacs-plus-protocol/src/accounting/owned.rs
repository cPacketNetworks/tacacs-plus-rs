use std::string::String;
use std::string::ToString;

use super::{Reply, Status};
use crate::owned::FromBorrowedBody;
use crate::sealed::Sealed;

/// An owned version of a [`Reply`](super::Reply).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            server_message: borrowed.server_message.to_string(),
            data: borrowed.data.to_string(),
        }
    }
}
