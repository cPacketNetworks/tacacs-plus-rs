//! # tacacs-plus
//!
//! Rust library implementation of a TACACS+ ([RFC-8907](https://www.rfc-editor.org/rfc/rfc8907)) client.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

pub mod protocol;
// mod session;

/// An error that occurred during a TACACS+ session.
#[derive(Debug)]
pub enum TacacsError {
    /// Connection to TACACS+ server failed
    ConnectionError,

    /// Invalid/corrupt response received from TACACS+ server
    BadResponse,
    // TODO: I/O error (perhaps in session/client module, as core::io does not exist)
}

mod ascii;
pub use ascii::AsciiStr;
