use std::borrow::ToOwned;
use std::string::String;

use super::{Reply, Status};
use crate::protocol::ToOwnedBody;

/// An owned version of a [`Reply`](super::Reply).
pub struct ReplyOwned {
    /// The status returned by the server.
    pub status: Status,

    // TODO: string or separate FieldTextOwned (?) type?
    /// The message to display to the user.
    pub server_message: String,

    /// The console/administrative message from the server.
    pub data: String,
}

impl ToOwnedBody for Reply<'_> {
    type Owned = ReplyOwned;

    fn to_owned(&self) -> Self::Owned {
        ReplyOwned {
            status: self.status,
            server_message: self.server_message.as_ref().to_owned(),
            data: self.data.as_ref().to_owned(),
        }
    }
}
