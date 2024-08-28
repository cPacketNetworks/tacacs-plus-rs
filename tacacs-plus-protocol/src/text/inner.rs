use core::fmt;
use core::ops::Deref;

/// Effectively a `Cow<'_, str>` that works in a no_std context, and
/// also allows for conversion between borrowed/owned in-place (which
/// `Cow` cannot do).
#[derive(Debug, Clone, Eq, Hash)]
pub(super) enum FieldTextInner<'data> {
    Borrowed(&'data str),

    #[cfg(feature = "std")]
    Owned(std::string::String),
}

impl FieldTextInner<'_> {
    /// Extends the lifetime of a `FieldTextInner` by converting it to a variant
    /// that owns its internal data.
    #[cfg(feature = "std")]
    pub(super) fn into_owned(self) -> FieldTextInner<'static> {
        use std::borrow::ToOwned;

        match self {
            Self::Borrowed(str) => FieldTextInner::Owned(str.to_owned()),
            Self::Owned(str) => FieldTextInner::Owned(str),
        }
    }
}

// FieldTextInner is effectively a smart pointer now, so we implement Deref
impl Deref for FieldTextInner<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(str) => str,
            #[cfg(feature = "std")]
            Self::Owned(owned) => owned,
        }
    }
}

impl AsRef<str> for FieldTextInner<'_> {
    fn as_ref(&self) -> &str {
        match self {
            Self::Borrowed(str) => str,
            #[cfg(feature = "std")]
            Self::Owned(owned) => owned,
        }
    }
}

// equality should work regardless of owned/borrowed status of each other
impl PartialEq for FieldTextInner<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

// also allow comparisons to &strs
impl PartialEq<&str> for FieldTextInner<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.as_ref() == *other
    }
}

impl PartialEq<FieldTextInner<'_>> for &str {
    fn eq(&self, other: &FieldTextInner<'_>) -> bool {
        *self == other.as_ref()
    }
}

impl PartialOrd for FieldTextInner<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FieldTextInner<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl Default for FieldTextInner<'_> {
    fn default() -> Self {
        Self::Borrowed("")
    }
}

impl fmt::Display for FieldTextInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Borrowed(s) => <_ as fmt::Display>::fmt(s, f),
            #[cfg(feature = "std")]
            Self::Owned(s) => <_ as fmt::Display>::fmt(s, f),
        }
    }
}
