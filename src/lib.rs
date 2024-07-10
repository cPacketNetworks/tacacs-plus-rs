//! # tacacs-plus
//!
//! Rust library implementation of a TACACS+ ([RFC-8907](https://www.rfc-editor.org/rfc/rfc8907)) client.

#![no_std]
#![cfg_attr(feature = "docsrs", feature(doc_auto_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

pub mod protocol;

mod ascii;
pub use ascii::AsciiStr;
