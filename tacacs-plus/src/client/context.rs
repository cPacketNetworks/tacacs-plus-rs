use tacacs_plus_protocol::PrivilegeLevel;

/// Some information associated with all sessions, regardless of the action.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub(super) user: String,
    pub(super) port: String,
    pub(super) remote_address: String,
    pub(super) privilege_level: PrivilegeLevel,
}

/// Builder for [`SessionContext`] objects.
pub struct SessionContextBuilder {
    user: String,
    port: String,
    remote_address: String,
    privilege_level: PrivilegeLevel,
}

impl Default for SessionContextBuilder {
    fn default() -> Self {
        Self {
            user: String::from(""),
            port: String::from("rust_client"),
            remote_address: String::from("tacacs_plus_rs"),
            privilege_level: Default::default(),
        }
    }
}

impl SessionContextBuilder {
    /// Creates a new builder with default values for the various fields.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the user of the resulting context.
    pub fn user(mut self, user: String) -> Self {
        self.user = user;
        self
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
