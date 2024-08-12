#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
TMPDIR=$(mktemp -d)

if [ ! -v CI ]; then
    # build server image
    echo "Building test server Docker image..."
    docker build --tag localhost/tacacs-test-server --file "${REPO_ROOT}/test-assets/Dockerfile.test_server" "${REPO_ROOT}/test-assets"
    echo "Build finished!"
fi

# run server container in background
echo "Running server container in background"
docker run --rm --detach --publish 5555:5555 --name tacacs-server localhost/tacacs-test-server >/dev/null

# stop container on exit, including if/when a test fails
trap "echo 'Stopping server container'; docker stop tacacs-server >/dev/null" EXIT

# run all integration tests against server
echo "Running tests..."
cargo test --package tacacs-plus --test '*' --no-fail-fast

# copy accounting file out of container & verify contents
# TODO: more specific validation?
docker cp tacacs-server:/tmp/accounting.log $TMPDIR/accounting.log
test $(wc -l $TMPDIR/accounting.log | awk '{print $1}') -eq 3
