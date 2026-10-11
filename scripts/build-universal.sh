#!/bin/sh
# Build an optimised universal (arm64 + x86_64) macOS binary at dist/sshweb.
set -eu
cd "$(dirname "$0")/.."
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
mkdir -p dist
lipo -create -output dist/sshweb \
  target/aarch64-apple-darwin/release/sshweb \
  target/x86_64-apple-darwin/release/sshweb
lipo -info dist/sshweb
