#!/usr/bin/env bash
#
# Keeps running the tests in a loop, using a different random seed every time.
# This can cause different behavior within the tests.
# Most notably, the tests in tests/simulation.rs will use different random node IDs for each seed,
# which will mean that each node will order themselves in the network in a different way.

while true; do
    SEED=$(date)
    if ! RUST_BACKTRACE=full RUST_LOG=debug STONENET_TEST_RANDOM_SEED="$SEED" cargo test; then
        echo Tests failed with seed: \""$SEED"\"
        exit 1
    fi
done
