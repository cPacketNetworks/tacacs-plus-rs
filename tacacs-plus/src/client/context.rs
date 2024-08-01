use tacacs_plus_protocol::{PrivilegeLevel, UserInformation};

use super::ClientError;

pub(super) struct InvalidContext(());

impl From<InvalidContext> for ClientError {
    fn from(_value: InvalidContext) -> Self {
        ClientError::InvalidContext
    }
}

/// Some information associated with all sessions, regardless of the action.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub(super) user: String,
    pub(super) port: String,
    pub(super) remote_address: String,
    pub(super) privilege_level: PrivilegeLevel,
}

impl SessionContext {
    pub(super) fn as_user_information(&self) -> Result<UserInformation<'_>, InvalidContext> {
        UserInformation::new(
            self.user.as_str(),
            self.port
                .as_str()
                .try_into()
                .map_err(|_| InvalidContext(()))?,
            self.remote_address
                .as_str()
                .try_into()
                .map_err(|_| InvalidContext(()))?,
        )
        .ok_or(InvalidContext(()))
    }
}

/// Builder for [`SessionContext`] objects.
pub struct ContextBuilder {
    user: String,
    port: String,
    remote_address: String,
    privilege_level: PrivilegeLevel,
}

impl ContextBuilder {
    /// Creates a new builder with default values for the various fields.
    pub fn new(user: &str) -> Self {
        Self {
            user: user.to_owned(),
            port: String::from("rust_client"),
            remote_address: String::from("tacacs_plus_rs"),
            privilege_level: Default::default(),
        }
    }

    /// Sets the port of the resulting context.
    pub fn port(mut self, port: String) -> Self {
        self.port = port;
        self
    }

    /// Sets the remote address of the resulting context.
    pub fn remote_address(mut self, remote_address: String) -> Self {
        self.remote_address = remote_address;
        self
    }

    /// Sets the privilege level of the resulting context.
    pub fn privilege_level(mut self, privilege_level: PrivilegeLevel) -> Self {
        self.privilege_level = privilege_level;
        self
    }

    /// Consumes this builder and turns it into a [`SessionContext`].
    pub fn build(self) -> SessionContext {
        SessionContext {
            user: self.user,
            port: self.port,
            remote_address: self.remote_address,
            privilege_level: self.privilege_level,
        }
    }
}
