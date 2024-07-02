#![cfg_attr(not(feature = "std"), no_std)]

pub mod protocol;
// mod session;

// TODO: error impl? error in core will be stabilized in 1.81 supposedly
#[derive(Debug)]
pub enum TacacsError {
    // #[error("Connection to TACACS+ server failed")]
    ConnectionError,

    // #[error("The TACACS+ server sent an invalid or corrupt response")]
    BadResponse,
    // #[error(transparent)]
    // IOError(#[from] std::io::Error),
}

mod types;
pub use types::{AsciiStr, InvalidAscii};
