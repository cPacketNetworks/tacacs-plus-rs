use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Ord, Hash)]
enum PacketDataInner<'data> {
    Borrowed(&'data [u8]),

    #[cfg(feature = "std")]
    Owned(std::vec::Vec<u8>),
}

impl PartialOrd for PacketDataInner<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.as_ref().cmp(other.as_ref()))
    }
}

/// Supplementary authentication data included in an authentication start packet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketData<'data>(PacketDataInner<'data>);

impl PacketData<'_> {
    /// Creates an empty [`PacketData`].
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for PacketData<'_> {
    fn default() -> Self {
        Self(PacketDataInner::Borrowed(&[]))
    }
}

/// An error indicating that the provided supplementary authentication was too long to fit in a packet.
#[derive(Debug, PartialEq, Eq)]
pub struct DataTooLong(pub(super) ());

impl fmt::Display for DataTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "data was too long for the data field of an authentication start packet"
        )
    }
}

impl<'data> TryFrom<&'data [u8]> for PacketData<'data> {
    type Error = DataTooLong;

    fn try_from(value: &'data [u8]) -> Result<Self, Self::Error> {
        // do length check on data, since the encoded length has to fit in a single byte
        if u8::try_from(value.len()).is_ok() {
            Ok(Self(PacketDataInner::Borrowed(value)))
        } else {
            Err(DataTooLong(()))
        }
    }
}

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<u8>> for PacketData<'_> {
    type Error = DataTooLong;

    fn try_from(value: std::vec::Vec<u8>) -> Result<Self, Self::Error> {
        // as above, encoded length must fit in a single octet
        if u8::try_from(value.len()).is_ok() {
            Ok(Self(PacketDataInner::Owned(value)))
        } else {
            Err(DataTooLong(()))
        }
    }
}

impl AsRef<[u8]> for PacketDataInner<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,

            #[cfg(feature = "std")]
            Self::Owned(vec) => vec,
        }
    }
}

impl PacketData<'_> {
    // the len_without_is_empty lint is suppressed since we already effectively have an AsRef impl via as_bytes
    /// Returns the length of the underlying data, which is guaranteed to fit in a `u8`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u8 {
        // SAFETY: the length of the inner data is checked to fit in a u8 in the TryFrom impls
        u8::try_from(self.as_bytes().len()).unwrap()
    }

    /// Returns the byte representation of this packet data.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}
