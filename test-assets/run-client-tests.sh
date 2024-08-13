#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
TMPDIR=$(mktemp -d)

if [ ! -v CI ]; then
    # build server image
    echo "Building test server Docker image..."
    docker build --tag localhost/tacacs-test-server "${REPO_ROOT}/test-assets"
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

# copy accounting file out of container
docker cp tacacs-server:/tmp/accounting.log $TMPDIR/accounting.log

# display contents of accounting file if verification fails
trap "echo 'accounting file:'; cat $TMPDIR/accounting.log" ERR

# verify contents of accounting file
$REPO_ROOT/test-assets/validate_accounting_file.py $TMPDIR/accounting.log
