use std::borrow::ToOwned;
use std::string::String;

use super::Argument;

/// An argument that owns its name and value.
#[derive(Debug, PartialEq, Eq)]
pub struct ArgumentOwned {
    /// The name of the argument.
    pub(in crate::protocol) name: String,

    /// The value of the argument.
    pub(in crate::protocol) value: String,

    /// Whether this argument is required.
    pub(in crate::protocol) required: bool,
}

impl ArgumentOwned {
    /// Gets the name of this argument.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the value of this argument
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns `true` if this argument is required, and `false` if it's optional.
    pub fn is_required(&self) -> bool {
        self.required
    }
}

impl Argument<'_> {
    /// Converts this `Argument` to one which owns its fields.
    pub fn to_owned(&self) -> ArgumentOwned {
        ArgumentOwned {
            name: self.name.as_ref().to_owned(),
            value: self.value.as_ref().to_owned(),
            required: self.required,
        }
    }
}
