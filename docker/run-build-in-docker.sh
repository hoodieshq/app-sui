#!/usr/bin/env bash
set -eu

OUT_DIR=/app/docker-outputs

for device in nanosplus nanox
do
    cd rust-app
    cargo ledger build $device
    cd ..
    pytest ragger-tests --tb=short -v --device ${device/nanosplus/nanosp};
    cp rust-app/target/$device/release/$APP_NAME $OUT_DIR/$device
    chown $HOST_UID:$HOST_GID $OUT_DIR/$device/$APP_NAME
done
