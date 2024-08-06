#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

# build server image
docker build --tag tacacs-test-server --file "${REPO_ROOT}/test-assets/Dockerfile.test_server" "${REPO_ROOT}/test-assets"

# run server container in background
docker run --rm --detach --publish 5555:5555 --name tacacs-server tacacs-test-server

# stop container on exit, including if/when a test fails
trap "docker stop tacacs-server" EXIT

# run all integration tests against server
cargo test --package tacacs-plus --test '*' --no-fail-fast
