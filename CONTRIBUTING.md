# Contributing

Thank you for your contribution to `tacacs-plus-rs`! To help maintain quality and consistency, the following are our
guidelines for commits to this repository

## Signoff

By contributing to this repository, you agree that you are authorized to make this contribution per the terms of the
[Developer Certificate of Origin][DCO]

## Code of Conduct

While you are here, make sure everyone's experience is a good one by following the [contributor covenant](./CODE_OF_CONDUCT.md)

## Issue Reporting

Please report any non-security issues via the issues page in GitHub. For any security issues, see our
[security disclosure policy](./SECURITY.md)

## Pull Requests

Pull requests will be reviewed by our maintainers to ensure that they meet our quality expectations and conform to our
code style guidelines. If all build & test actions pass and approvals are met, your contribution will be merged. Thank
you!

## Code Style

> [!Note]
> Style rule language adopted from [RFC-2119][RFC-2119]

* All code MUST be formatted with rustfmt
* All code MUST be checked by rust-lang/rust-clippy 
* Code SHOULD conform to the emerging [Rust Style Guidelines][Rust Style Guide]

### Additional guidellines:

* Prefer nested structures over larger ones (over 7 properties is probably too much, consider splitting)
* All types SHOULD implement Sync + Send whenever possible
* Types SHOULD implement Debug, Clone where possible
* Consider implementing the traits  Debug, Display, Eq, PartialEq, Ord, PartialOrd, From for user defined structs
* Avoid specifying lifetimes if possible
* In places where the full context of a lifetime is known, that lifetime SHOULD use a name reflective of the expected lifetime. Example:
```
struct RequestContext<'request> {}
```
* Where not in conflict with other well known rust conventions, abbreviations and word shortenings should be avoided

[DCO]: https://developercertificate.org/
[RFC-2119]: https://datatracker.ietf.org/doc/html/rfc2119
[Rust Style Guide]: https://doc.rust-lang.org/stable/style-guide/index.html
