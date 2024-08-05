//! # tacacs-plus
//!
//! Rust implementation of the TACACS+ ([RFC8907](https://www.rfc-editor.org/rfc/rfc8907)) protocol.

#![cfg_attr(feature = "docsrs", feature(doc_auto_cfg))]
#![warn(missing_docs)]

pub mod client;
pub use client::{Client, ClientError};

pub use tacacs_plus_protocol as protocol;
