# tacacs-plus-rs

Rust implementation of the TACACS+ ([RFC8907](https://www.rfc-editor.org/rfc/rfc8907)) protocol.

## Crates

`tacacs-plus-protocol`: Library with the struct protocol definitions for the wire format of TACACS+ packets, as well as means to (de)serialize them. (optionally no-std & no-alloc)
`tacacs-plus`: Async and runtime-agnostic library for performing message exchanges with a TACACS+ server.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)
