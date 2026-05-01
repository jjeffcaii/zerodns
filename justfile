#!/usr/bin/env just --justfile

alias r := run
alias i := install
alias l := lint
alias n := init

release:
  @cargo build --release

install:
    @cargo install --path .

lint:
  @cargo clippy

run: geoip
  @cargo run -- run -c config.toml

init:
  @cargo run -- init

geoip:
  @if [[ ! -f GeoLite2-Country.mmdb ]]; then echo 'download GeoLite2-Country.mmdb...' && wget --quiet https://git.io/GeoLite2-Country.mmdb; fi
