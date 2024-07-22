use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use crate::protocol::ToOwnedBody;

use super::Reply;
use super::{ReplyFlags, Status};

/// An authentication reply packet with owned fields.
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

impl ToOwnedBody for Reply<'_> {
    type Owned = ReplyOwned;

    fn to_owned(&self) -> Self::Owned {
        ReplyOwned {
            status: self.status,
            flags: self.flags,
            server_message: self.server_message.as_ref().to_owned(),
            data: self.data.to_owned(),
        }
    }
}
