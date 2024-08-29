# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(with some modifications per [Rust's Cargo](https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility)).

## [Unreleased]

(no changes yet)

## [0.3.0] - 2024-08-29

### tacacs-plus

#### Added

- CI tests are also run against [TACACS+ NG], an actively maintained TACACS+ server implementation (#30)
- Common std trait implementations (e.g. `Hash`, `PartialOrd`/`PartialEq`, `Debug`, `Display`) to publicly exposed types

#### Changed

- `ContextBuilder` methods now take references instead of consuming the builder (#34)
- `ContextBuilder::new()` takes a `String` instead of an `&str`

[TACACS+ NG]: https://projects.pro-bono-publico.de/event-driven-servers/doc/tac_plus-ng.html

### tacacs-plus-protocol

#### Added

- `FieldText::from_string_lossy()` constructor that automatically escapes any non-printable-ASCII characters (#31)
- `InvalidText` type, for `FieldText` construction errors
- Common core trait implementations (e.g. `Hash`, `PartialOrd`/`PartialEq`, `Debug`, `Display`) to publicly exposed types

#### Changed

- `FieldText`'s `TryFrom` & `FromStr` implementation error types were changed to `InvalidText` (#35)
- `authentication::Action::SendAuth` is no longer marked as `#[deprecated]`, since [RFC8907 section 10.5.3] only recommends against
  its use, not deprecates it

[RFC8907 section 10.5.3]: https://www.rfc-editor.org/rfc/rfc8907.html#section-10.5.3-4

## [0.2.2] - 2024-08-20

### tacacs-plus

#### Fixed

- Argument values are now properly merged between request & response packets, per [RFC8907 section 6.1] (#27)

[RFC8907 section 6.1]: https://www.rfc-editor.org/rfc/rfc8907.html#section-6.1-18

### tacacs-plus-protocol

#### Added

- `FromStr` implementation for `FieldText` (std-only) (#26)

## [0.2.1] - 2024-08-20

### tacacs-plus

#### Removed

- Outbound PAP authentication test, since it was redundant with other tests (#18)

### tacacs-plus-protocol

#### Fixes

- `Argument` field getters are now properly generated (#24)

## [0.2.0] - 2024-08-19

### tacacs-plus

#### Added

- `Client::account_begin()` method to perform TACACS+ accounting
- `AccountingTask` type to represent an in-progress task being tracked via TACACS+ accounting
- `AccountingError` and `SystemTimeBeforeEpoch` variants for `ClientError`
- Test of client accounting against Shrubbery TACACS+ server, together with validation of resulting log file

#### Changed

- `Client` methods take `&self` instead of `&mut self`, as the latter wasn't necessary
- `arguments` field of `AuthorizationResponse` is now of type `Vec<Argument<'static>>` instead of `Vec<ArgumentOwned>`

### tacacs-plus-protocol

#### Added

- `FieldText::into_owned()` method to allow for use in owned context (std-only)
- `TryFrom<String>` implementation for `FieldText` such that it owns its contained data (std-only)
- `PartialEq` implementations against `&str` for `FieldText` (both directions)
- Other `FieldText` trait implementations: `PartialOrd`/`Ord`, `Hash`, `Default`

#### Changed

- Any getters for fields of type `FieldText` now return `&FieldText`, as `FieldText` is no longer `Copy`
  due to internal representation changes
- `required` field of `Argument` renamed to `mandatory` to match RFC8907

#### Removed

- `ArgumentOwned` type, with the `Argument` type being expanded to fill the same purpose (#20)
- `Copy` implementation for `FieldText`, as it no longer makes sense due to implementation changes

## [0.1.0] - 2024-08-07

### tacacs-plus-protocol

#### Added

- Parsing/serializing capabilities for RFC8907 TACACS+ protocol packets in no-std/no-alloc context
- Validation of different packet fields both when deserializing and serializing

### tacacs-plus

#### Added

- TACACS+ `Client` capable of PAP/CHAP authentication as well as authorization
- Client tests against the [Shrubbery TACACS+ daemon] for authentication/authorization (#13)

[Shrubbery TACACS+ daemon]: https://shrubbery.net/tac_plus/

[Unreleased]: https://github.com/cPacketNetworks/tacacs-plus-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cPacketNetworks/tacacs-plus-rs/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/cPacketNetworks/tacacs-plus-rs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/cPacketNetworks/tacacs-plus-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/cPacketNetworks/tacacs-plus-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cPacketNetworks/tacacs-plus-rs/releases/tag/v0.1.0
