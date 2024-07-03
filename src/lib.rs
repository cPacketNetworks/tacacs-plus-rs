//! # tacacs-plus
//!
//! Rust library implementation of a TACACS+ ([RFC-8907](https://www.rfc-editor.org/rfc/rfc8907)) client.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod protocol;
// mod session;

#[derive(Debug)]
pub enum TacacsError {
    // #[error("Connection to TACACS+ server failed")]
    ConnectionError,

    // #[error("The TACACS+ server sent an invalid or corrupt response")]
    BadResponse,
    // #[error(transparent)]
    // IOError(#[from] std::io::Error),
}

pub mod ascii;
pub use ascii::AsciiStr;
