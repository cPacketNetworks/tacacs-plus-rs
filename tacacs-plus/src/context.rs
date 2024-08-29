use tacacs_plus_protocol::{AuthenticationMethod, PrivilegeLevel, UserInformation};

use super::ClientError;

pub(super) struct InvalidContext(());

impl From<InvalidContext> for ClientError {
    fn from(_value: InvalidContext) -> Self {
        ClientError::InvalidContext
    }
}

/// Some information associated with all sessions, regardless of the action.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SessionContext {
    pub(super) user: String,
    pub(super) port: String,
    pub(super) remote_address: String,
    pub(super) privilege_level: PrivilegeLevel,
    authentication_method: Option<AuthenticationMethod>,
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

    /// Gets the authentication method for this context object, defaulting to [`NotSet`](tacacs_plus_protocol::AuthenticationMethod::NotSet).
    ///
    /// This should not be used within an authentication session.
    pub(super) fn authentication_method(&self) -> AuthenticationMethod {
        self.authentication_method
            .unwrap_or(AuthenticationMethod::NotSet)
    }
}

/// Builder for [`SessionContext`] objects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextBuilder {
    user: String,
    port: String,
    remote_address: String,
    privilege_level: PrivilegeLevel,
    authentication_method: Option<AuthenticationMethod>,
}

// TODO: don't consume builder at each step
impl ContextBuilder {
    /// Creates a new builder with default values for the various fields.
    pub fn new(user: String) -> Self {
        Self {
            user,
            port: String::from("rust_client"),
            remote_address: String::from("tacacs_plus_rs"),
            privilege_level: Default::default(),
            authentication_method: None,
        }
    }

    /// Sets the port of the resulting context.
    pub fn port(&mut self, port: String) -> &mut Self {
        self.port = port;
        self
    }

    /// Sets the remote address of the resulting context.
    pub fn remote_address(&mut self, remote_address: String) -> &mut Self {
        self.remote_address = remote_address;
        self
    }

    /// Sets the privilege level of the resulting context.
    pub fn privilege_level(&mut self, privilege_level: PrivilegeLevel) -> &mut Self {
        self.privilege_level = privilege_level;
        self
    }

    /// Sets the authentication method of the resulting context.
    ///
    /// Note that this field is ignored in an authentication session.
    pub fn auth_method(&mut self, method: AuthenticationMethod) -> &mut Self {
        self.authentication_method = Some(method);
        self
    }

    /// Consumes this builder and turns it into a [`SessionContext`].
    pub fn build(&self) -> SessionContext {
        SessionContext {
            user: self.user.clone(),
            port: self.port.clone(),
            remote_address: self.remote_address.clone(),
            privilege_level: self.privilege_level,
            authentication_method: self.authentication_method,
        }
    }
}
