all:
  cargo run --bin gateryx-server -F server --release -- -c ./t/config.toml

check:
  cargo fmt --check
  clippy
  clippy -F server
  cargo audit

build-x86_64-unknown-linux-gnu:
    CARGO_TARGET_DIR="./target-x86_64" \
    cross build --target x86_64-unknown-linux-gnu --release -F server

build-aarch64-unknown-linux-gnu:
    CARGO_TARGET_DIR="./target-aarch64" \
    cross build --target aarch64-unknown-linux-gnu --release -F server

deb-amd64: build-x86_64-unknown-linux-gnu pack-deb-amd64

deb-arm64: build-aarch64-unknown-linux-gnu pack-deb-arm64

pack-deb-amd64:
  cd make-deb && TARGET_DIR=target-x86_64 RUST_TARGET=x86_64-unknown-linux-gnu DEB_ARCH=amd64 ./build.sh

pack-deb-arm64:
  cd make-deb && TARGET_DIR=target-aarch64 RUST_TARGET=aarch64-unknown-linux-gnu DEB_ARCH=arm64 ./build.sh

auth-web:
  cd auth && npm i && npm run build

system-web:
  cd system && npm i && npm run build

pub-lab: build-x86_64-unknown-linux-gnu copy-lab

copy-lab:
  scp ./target-x86_64/x86_64-unknown-linux-gnu/release/gateryx gateryx-lab:/usr/local/bin/gateryx
  ssh gateryx-lab 'sudo systemctl stop gateryx'
  scp ./target-x86_64/x86_64-unknown-linux-gnu/release/gateryx-server gateryx-lab:/usr/local/bin/gateryx-server
  ssh gateryx-lab 'sudo systemctl start gateryx'
