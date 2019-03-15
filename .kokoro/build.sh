#!/bin/bash
set -eo pipefail

# Debug: show build environment
env | grep KOKORO

cd github/signet/

versions=($RUBY_VERSIONS)

# Temporary workaround for a known bundler+docker issue:
# https://github.com/bundler/bundler/issues/6154
export BUNDLE_GEMFILE=

# Capture failures
EXIT_STATUS=0 # everything passed
function set_failed_status {
    EXIT_STATUS=1
}

if [ "$JOB_TYPE" = "release" ]; then
    git fetch --depth=10000
    python3 -m pip install gcp-releasetool
    python3 -m releasetool publish-reporter-script > /tmp/publisher-script; source /tmp/publisher-script
    (bundle update && bundle exec rake release) || set_failed_status
else
    for version in "${versions[@]}"; do
        rbenv global "$version"
        echo "Using Ruby $version"
        bundle update
        (bundle exec rake ci) || set_failed_status
    done
fi

exit $EXIT_STATUS
