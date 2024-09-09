#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
TMPDIR=$(mktemp -d)
export docker=${docker:-docker}
export SERVER_CONTAINER=tacacs-server

if [ ! -v CI ]; then
    # build server image
    echo "Building test server Docker images..."
    $docker build --tag localhost/tacacs-shrubbery-server --target tacacs-shrubbery-configured "${REPO_ROOT}/test-assets"
    $docker build --tag localhost/tacacs-ng-server --target tacacs-ng-configured "${REPO_ROOT}/test-assets"
    echo "Build finished!"
fi

stop_running_containers() {
    running=$($docker ps -q)

    if [ ! -z $running ]; then
        $docker stop $running >/dev/null
    fi
}

test_against_server_image() {
    image=$1

    # ensure nothing is running already
    stop_running_containers

    echo "Testing against image: $image"

    echo "Running server container in background"
    $docker run --rm --detach --publish 5555:5555 --name $SERVER_CONTAINER "$image" >/dev/null

    # run integration tests against server
    echo "Running tests..."
    cargo test --package tacacs-plus --test '*' --no-fail-fast

    # copy accounting file out of container
    $docker cp $SERVER_CONTAINER:/tmp/accounting.log $TMPDIR/accounting.log

    # verify contents of accounting file, printing if invalid
    if ! $REPO_ROOT/test-assets/validate_accounting_file.py $TMPDIR/accounting.log; then
        echo 'accounting file:'
        cat $TMPDIR/accounting.log
        return 1
    fi

    # test reconnection by restarting server mid test-run
    cargo test --package tacacs-plus --test pap_login connection_reestablishment -- --ignored
}

trap "stop_running_containers" EXIT

test_against_server_image localhost/tacacs-shrubbery-server
test_against_server_image localhost/tacacs-ng-server
