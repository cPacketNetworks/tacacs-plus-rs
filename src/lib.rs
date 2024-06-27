#![cfg_attr(not(feature = "std"), no_std)]

mod protocol;
mod session;

// #[cfg(feature = "std")]
// use thiserror::Error;

// TODO: figure out conditional error impl (probably by hand)
// #[cfg_attr(feature = "std", derive(Error))]
// #[derive(Debug)]
// pub enum TacacsError {
//     #[error("Connection to TACACS+ server failed")]
//     ConnectionError,

//     #[error("The TACACS+ server sent an invalid or corrupt response")]
//     BadResponse,

//     #[error(transparent)]
//     IOError(#[from] std::io::Error),
// }

mod types;
pub use types::{AsciiStr, InvalidAscii};
