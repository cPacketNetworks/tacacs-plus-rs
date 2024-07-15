//! # tacacs-plus
//!
//! Rust implementation of the TACACS+ ([RFC8907](https://www.rfc-editor.org/rfc/rfc8907)) protocol.

#![no_std]
#![cfg_attr(feature = "docsrs", feature(doc_auto_cfg))]
#![warn(missing_docs)]
#![warn(clippy::cast_lossless)]
#![warn(clippy::cast_possible_truncation)]

#[cfg(feature = "std")]
extern crate std;

pub mod protocol;

mod text;
pub use text::FieldText;
