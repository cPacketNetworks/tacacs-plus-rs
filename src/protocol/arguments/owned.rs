use std::borrow::ToOwned;
use std::string::String;

use super::Argument;

/// An argument that owns its name and value.
#[derive(Debug, PartialEq, Eq)]
pub struct ArgumentOwned {
    /// The name of the argument.
    pub name: String,

    /// The value of the argument.
    pub value: String,

    /// Whether this argument is required.
    pub required: bool,
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
