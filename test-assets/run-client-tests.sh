#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

# build image
docker buildx build --tag tacacs-test-server --file Dockerfile.test_server "${REPO_ROOT}/test-assets"

# run container
docker run --rm --detach --publish 5555:5555 --name tacacs-server tacacs-test-server

# run tests against server
# syntax from https://github.com/rust-lang/cargo/issues/8396#issuecomment-713126649
cargo test --package tacacs-plus --test '*' --verbose

# stop container
docker stop tacacs-server
