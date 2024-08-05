use std::borrow::ToOwned;
use std::string::String;

use super::{Argument, InvalidArgument};

/// An argument that owns its name and value.
#[derive(Debug, PartialEq, Eq, Clone)]
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

impl ArgumentOwned {
    /// Returns an [`Argument`](super::Argument) whose fields are borrowed from this owned argument.
    ///
    /// This conversion can fail if the name/value fields are not printable ASCII.
    pub fn borrowed(&self) -> Result<Argument<'_>, InvalidArgument> {
        Argument::new(
            self.name
                .as_str()
                .try_into()
                .map_err(|_| InvalidArgument::BadText)?,
            self.value
                .as_str()
                .try_into()
                .map_err(|_| InvalidArgument::BadText)?,
            self.required,
        )
    }
}
