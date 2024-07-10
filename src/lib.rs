//! # tacacs-plus
//!
//! Rust implementation of the TACACS+ ([RFC8907](https://www.rfc-editor.org/rfc/rfc8907)) and TACACS+ over TLS 1.3 ([IETF draft](https://datatracker.ietf.org/doc/draft-ietf-opsawg-tacacs-tls13/)) protocols.

#![no_std]
#![cfg_attr(feature = "docsrs", feature(doc_auto_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

pub mod protocol;

mod ascii;
pub use ascii::AsciiStr;
