use super::DeserializeError;
use super::PacketType;
use super::{sealed::Sealed, Deserialize, PacketBody};

#[cfg(feature = "std")]
/// Converts a reference-based packet to a packet that owns its fields.
///
/// A [`Borrow`](std::borrow::Borrow) impl for the different packet types would be nontrivial, if even possible,
/// which is why the [`ToOwned`](std::borrow::ToOwned) trait isn't used.
///
/// This is also a From-style trait due to a blanket impl for [`Deserialize`] that it is used for.
pub trait FromBorrowedBody: Sealed {
    /// The borrowed variant of this packet body.
    type Borrowed<'b>: PacketBody;

    /// Converts the borrowed variant of this packet body to its owned variant.
    fn from_borrowed(borrowed: &Self::Borrowed<'_>) -> Self;
}

impl<'b, B: FromBorrowedBody> Deserialize<'b> for B
where
    B::Borrowed<'b>: Deserialize<'b>,
{
    fn deserialize_from_buffer(buffer: &'b [u8]) -> Result<Self, DeserializeError> {
        let borrowed = <B as FromBorrowedBody>::Borrowed::deserialize_from_buffer(buffer)?;
        Ok(Self::from_borrowed(&borrowed))
    }
}

// boilerplate but necessary for above blanket Deserialize impl
// NOTE: this also ignores the required_minor_version function which is irrelevant for every
// packet type except authentication::Start, which doesn't have an owned variant as of now
impl<B: FromBorrowedBody> PacketBody for B {
    const TYPE: PacketType = <<B as FromBorrowedBody>::Borrowed<'_> as PacketBody>::TYPE;
    const REQUIRED_FIELDS_LENGTH: usize =
        <<B as FromBorrowedBody>::Borrowed<'_> as PacketBody>::REQUIRED_FIELDS_LENGTH;
}
