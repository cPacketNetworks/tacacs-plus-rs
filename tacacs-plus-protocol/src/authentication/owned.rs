use std::borrow::ToOwned;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

use super::Reply;
use super::{ReplyFlags, Status};
use crate::owned::FromBorrowedBody;
use crate::sealed::Sealed;

/// An authentication reply packet with owned fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplyOwned {
    /// The status, as returned by the server.
    pub status: Status,

    /// The flags set in the server response.
    pub flags: ReplyFlags,

    /// The message to be displayed to the user.
    pub server_message: String,

    /// The domain-specific data included in the reply.
    pub data: Vec<u8>,
}

impl Sealed for ReplyOwned {}

impl FromBorrowedBody for ReplyOwned {
    type Borrowed<'b> = Reply<'b>;

    fn from_borrowed(borrowed: &Self::Borrowed<'_>) -> Self {
        ReplyOwned {
            status: borrowed.status,
            flags: borrowed.flags,
            server_message: borrowed.server_message.to_string(),
            data: borrowed.data.to_owned(),
        }
    }
}
