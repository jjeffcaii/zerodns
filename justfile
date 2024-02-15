#!/usr/bin/env just --justfile

alias r := run

release:
  @cargo build --release

lint:
  @cargo clippy

run: geoip
  @cargo run -- run -c config.toml

geoip:
  @if [[ ! -f GeoLite2-Country.mmdb ]]; then echo 'download GeoLite2-Country.mmdb...' && wget --quiet https://git.io/GeoLite2-Country.mmdb; fi
