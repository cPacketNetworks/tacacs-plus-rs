#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

# build server image & cache to GitHub Actions cache in CI
# (the CI environment variable is always set while a workflow is running)
if [ -v CI ]; then
    # create docker-container driver builder, since default docker driver doesn't support GitHub Actions cache export
    docker buildx create --name container --driver docker-container

    # delete builder on exit
    trap "docker buildx rm container" EXIT

    # mode=max caches both Dockerfile stages, not just final one
    docker buildx build --builder container \
        --tag tacacs-test-server \
        --cache-to type=gha,mode=max \
        --cache-from type=gha,mode=max \
        --file Dockerfile.test_server "${REPO_ROOT}/test-assets"
else
    # just build image normally (without caching) if running outside of CI
    docker buildx build --tag tacacs-test-server --file Dockerfile.test_server "${REPO_ROOT}/test-assets"
fi

# run server container in background
docker run --rm --detach --publish 5555:5555 --name tacacs-server tacacs-test-server

# stop container on exit, including if/when a test fails
trap "docker stop tacacs-server" EXIT

# run all integration tests against server
cargo test --package tacacs-plus --test '*' --no-fail-fast
