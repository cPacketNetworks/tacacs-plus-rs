use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use super::{Reply, Status};
use crate::protocol::ToOwnedBody;

/// An owned version of a [`Reply`](super::Reply).
pub struct ReplyOwned {
    pub status: Status,
    // TODO: string or separate FieldTextOwned (?) type?
    pub server_message: String,
    pub data: Vec<u8>,
}

impl ToOwnedBody for Reply<'_> {
    type Owned = ReplyOwned;

    fn to_owned(&self) -> Self::Owned {
        ReplyOwned {
            status: self.status,
            server_message: self.server_message.as_ref().to_owned(),
            data: self.data.to_owned(),
        }
    }
}
