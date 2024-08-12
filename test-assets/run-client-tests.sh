#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

# ensure temporary directory exists for tests
if [ ! -v TMPDIR ]; then
    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT
fi
mkdir -p $TMPDIR

if [ ! -v CI ]; then
    # build server image
    echo "Building test server Docker image..."
    docker build --tag localhost/tacacs-test-server --file "${REPO_ROOT}/test-assets/Dockerfile.test_server" "${REPO_ROOT}/test-assets"
    echo "Build finished!"
fi

# create accounting file
touch $TMPDIR/accounting.log

# run server container in background
echo "Running server container in background"
# TODO: revert after debugging
# docker run --rm --detach --publish 5555:5555 --volume $TMPDIR/accounting.log:/tmp/accounting.log --name tacacs-server localhost/tacacs-test-server >/dev/null
# debug flags: ACCT
docker run --rm --detach --publish 5555:5555 --name tacacs-server localhost/tacacs-test-server -C /srv/tac_plus/tac_plus.conf -g -d 64 >/dev/null

# stop container on exit, including if/when a test fails
# TODO: revert after debugging
# trap "echo 'Stopping server container'; docker stop tacacs-server >/dev/null" EXIT
trap "docker logs tacacs-server; echo 'Stopping server container'; docker stop tacacs-server >/dev/null" EXIT

# run all integration tests against server
echo "Running tests..."
cargo test --package tacacs-plus --test '*' --no-fail-fast

# copy accounting file out of container & verify contents
# TODO: more specific validation?
docker cp tacacs-server:/tmp/accounting.log $TMPDIR/accounting.log
test $(wc -l $TMPDIR/accounting.log | awk '{print $1}') -eq 3
