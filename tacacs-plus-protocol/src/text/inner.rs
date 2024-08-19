use core::fmt;
use core::ops::Deref;

/// Effectively a `Cow<'_, str>` that works in a no_std context.
#[derive(Debug, Clone, Eq, PartialOrd, Ord, Hash)]
pub(super) enum FieldTextInner<'data> {
    Borrowed(&'data str),

    #[cfg(feature = "std")]
    Owned(std::string::String),
}

impl FieldTextInner<'_> {
    // a lifetime parameter is necessary since the compiler can't infer from just self
    #[cfg(feature = "std")]
    pub(super) fn into_owned<'out>(self) -> FieldTextInner<'out> {
        use std::borrow::ToOwned;

        match self {
            Self::Borrowed(str) => FieldTextInner::Owned(str.to_owned()),
            Self::Owned(str) => FieldTextInner::Owned(str),
        }
    }
}

// FieldTextInner is effectively a smart pointer now, so we implement Deref
impl<'a> Deref for FieldTextInner<'a> {
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
