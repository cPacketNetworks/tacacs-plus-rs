/// The TACACS+ secret key configured for integration tests.
pub const SECRET_KEY: &str = "very secure key that is super secret";

/// The default TACACS+ server address, which is the one expected by test-assets/run-client-tests.sh.
const DEFAULT_ADDRESS: &str = "localhost:5555";

/// Gets the TACACS+ server address from the `TACACS_SERVER` environment variable, or a default if it isn't set.
pub fn get_server_address() -> String {
    std::env::var("TACACS_SERVER").unwrap_or(DEFAULT_ADDRESS.to_owned())
}
