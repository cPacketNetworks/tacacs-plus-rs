use getset::Getters;

use super::{header::HeaderInfo, Packet};
use crate::protocol::ToOwnedBody;

// TODO: body bounds? may not be necessary if only way to construct is via to_owned() though
/// A packet that owns its field data.
#[derive(Getters)]
pub struct PacketOwned<B> {
    /// Information contained in the packet header.
    #[getset(get = "pub")]
    header: HeaderInfo,

    /// The body of the packet.
    #[getset(get = "pub")]
    body: B,
}

impl<B: ToOwnedBody> Packet<B> {
    /// Converts this packet into one that owns its body's fields.
    pub fn to_owned(&self) -> PacketOwned<B::Owned> {
        PacketOwned {
            header: self.header.clone(),
            body: self.body.to_owned(),
        }
    }
}
