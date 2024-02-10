#!/usr/bin/env just --justfile

release:
  cargo build --release

lint:
  cargo clippy

run:
  cargo run -- run -c config.toml

geoio:
  wget https://git.io/GeoLite2-Country.mmdb
