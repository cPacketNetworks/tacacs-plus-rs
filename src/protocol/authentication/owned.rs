use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use crate::protocol::ToOwnedBody;

use super::Reply;
use super::{ReplyFlags, Status};

pub struct ReplyOwned {
    pub status: Status,
    pub flags: ReplyFlags,
    pub server_message: String,
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
