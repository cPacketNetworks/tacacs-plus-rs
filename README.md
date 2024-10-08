# tacacs-plus-rs

Rust implementation of the TACACS+ ([RFC8907](https://www.rfc-editor.org/rfc/rfc8907)) protocol.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Repository Structure

### .github/workflows

Contains the GitHub Actions workflows for the repository.
There is one workflow for running tests (unit and integration) on every PR/push to main.
There is another workflow for formatting/clippy checks on every PR/push to main.

### tacacs-plus-protocol

Library with the struct protocol definitions for the wire format of TACACS+ packets, as well as means to (de)serialize them. (optionally no-std & no-alloc)

### tacacs-plus

Async and runtime-agnostic library for performing message exchanges with a TACACS+ server.

## Testing

Both crates have unit testing throughout the codebase. Integration tests are also present in the `tacacs-plus` crate. Both of these tests are run on every PR/push to main. The integration tests are run against [shrubbery's tac_plus](https://shrubbery.net/pub/tac_plus/), as well as [tacacs-ng](https://github.com/MarcJHuber/event-driven-servers.git). See the `test-assessment` directory for the configuration files used for these servers.

Should you need to run the integration tests locally follow the logic in `.github/workflows/build-test.yml`
