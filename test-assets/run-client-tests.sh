#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

if [ ! -v CI ]; then
    # create temporary directory for tests
    TMPDIR=$(mktemp -d)

    # build server image
    echo "Building test server Docker image..."
    docker build --tag localhost/tacacs-test-server --file "${REPO_ROOT}/test-assets/Dockerfile.test_server" "${REPO_ROOT}/test-assets"
    echo "Build finished!"
else
    # if this script is running in CI, the image will already have been built so we don't build it again

    # use subdirectory of allocated runner temporary directory in CI
    TMPDIR="$RUNNER_TEMP/client-tests"
    mkdir -p $TMPDIR
fi

# create accounting file
touch $TMPDIR/accounting.log

# run server container in background
echo "Running server container in background"
docker run --rm --detach --publish 5555:5555 --volume $TMPDIR/accounting.log:/tmp/accounting.log --name tacacs-server localhost/tacacs-test-server >/dev/null

# stop container on exit, including if/when a test fails
trap "echo 'Stopping server container'; docker stop tacacs-server >/dev/null; rm -rf $TMPDIR" EXIT

# run all integration tests against server
echo "Running tests..."
cargo test --package tacacs-plus --test '*' --no-fail-fast

# verify accounting was done properly based on file contents
# TODO: more specific validation?
test $(wc -l $TMPDIR/accounting.log | awk '{print $1}') -eq 3
