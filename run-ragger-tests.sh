#!/usr/bin/env bash

set -eu

for device in nanosplus nanox
do
    export DEVICE=$device
    nix-shell -A $DEVICE.rustShell --run ' \
      set -x
      cd rust-app; \
      cargo build --release --target=$TARGET_JSON; \
      cd ..; \
      pytest ragger-tests --tb=short -v --device ${DEVICE/nanosplus/nanosp};
    '
done
