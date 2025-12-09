VERSION := `grep ^version Cargo.toml|cut -d\" -f2`

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

deb: deb-amd64 deb-arm64

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

pub: deb-amd64 deb-arm64 pub-deb docker pub-docker

docker:
  cd docker && rm -rf _build && mkdir _build
  cd docker && cp ../make-deb/gateryx-server-{{ VERSION }}-arm64.deb ./_build/gateryx-server-arm64.deb
  cd docker && cp ../make-deb/gateryx-client-{{ VERSION }}-arm64.deb ./_build/gateryx-client-arm64.deb
  cd docker && cp ../make-deb/gateryx-server-{{ VERSION }}-amd64.deb ./_build/gateryx-server-amd64.deb
  cd docker && cp ../make-deb/gateryx-client-{{ VERSION }}-amd64.deb ./_build/gateryx-client-amd64.deb
  cd docker && docker build --pull --no-cache -t bmauto/gateryx-arm64:{{ VERSION }} -f ./Dockerfile.arm64 .
  cd docker && docker build --pull --no-cache -t bmauto/gateryx:{{ VERSION }} -f ./Dockerfile.amd64 .
  docker tag bmauto/gateryx-arm64:{{ VERSION }} bmauto/gateryx-arm64:latest
  docker tag bmauto/gateryx:{{ VERSION }} bmauto/gateryx:latest

pub-docker:
  docker push bmauto/gateryx-arm64:{{ VERSION }}
  docker push bmauto/gateryx-arm64:latest
  docker push bmauto/gateryx:{{ VERSION }}
  docker push bmauto/gateryx:latest

pub-deb:
  cd ~/src/apt/repo && reprepro includedeb stable ~/src/gateryx/make-deb/gateryx-client-{{ VERSION }}-arm64.deb
  cd ~/src/apt/repo && reprepro includedeb stable ~/src/gateryx/make-deb/gateryx-server-{{ VERSION }}-arm64.deb
  cd ~/src/apt/repo && reprepro includedeb stable ~/src/gateryx/make-deb/gateryx-client-{{ VERSION }}-amd64.deb
  cd ~/src/apt/repo && reprepro includedeb stable ~/src/gateryx/make-deb/gateryx-server-{{ VERSION }}-amd64.deb
  cd ~/src/apt/repo && just pub

copy-lab:
  scp ./target-x86_64/x86_64-unknown-linux-gnu/release/gateryx gateryx-lab:/usr/local/bin/gateryx
  ssh gateryx-lab 'sudo systemctl stop gateryx'
  scp ./target-x86_64/x86_64-unknown-linux-gnu/release/gateryx-server gateryx-lab:/usr/local/bin/gateryx-server
  ssh gateryx-lab 'sudo systemctl start gateryx'
