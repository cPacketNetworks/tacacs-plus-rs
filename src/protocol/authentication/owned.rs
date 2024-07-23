use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use crate::protocol::ToOwnedBody;

use super::Reply;
use super::{ReplyFlags, Status};

/// An authentication reply packet with owned fields.
// TODO: stop ignoring dead_code lint when fields are actually used
#[allow(dead_code)]
pub(crate) struct ReplyOwned {
    /// The status, as returned by the server.
    pub(crate) status: Status,

    /// The flags set in the server response.
    pub(crate) flags: ReplyFlags,

    /// The message to be displayed to the user.
    pub(crate) server_message: String,

    /// The domain-specific data included in the reply.
    pub(crate) data: Vec<u8>,
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
