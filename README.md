![logo](./docs/logo.jpg)

# ZeroDNS

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/jjeffcaii/zerodns/rust.yml)
[![Codecov](https://img.shields.io/codecov/c/github/jjeffcaii/zerodns)](https://app.codecov.io/gh/jjeffcaii/zerodns)
[![Crates.io Version](https://img.shields.io/crates/v/zerodns)](https://crates.io/crates/zerodns)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/zerodns)](https://crates.io/crates/zerodns)
![GitHub Tag](https://img.shields.io/github/v/tag/jjeffcaii/zerodns)
![GitHub License](https://img.shields.io/github/license/jjeffcaii/zerodns)

a DNS server in Rust, which is inspired from chinadns/dnsmasq.

> WARNING: still in an active development!!!

## Goals

- multiple protocols: UDP/TCP/DoT/DoT/DNSCrypt
- user-defined filters, includes lua or native rust codes

## Quick Start

> Notice: ensure you have [just](https://github.com/casey/just) installed on your machine!

run an example:

```shell
$ just r
$ dig @127.0.0.1 -p5454 www.youtube.com
```

## Configuration

Here's an example configuration file:

```toml

# The settings of server
[server]
# will listen on tcp+udp
listen = "0.0.0.0:5454"
# use LRU cache with 1000 capacity
cache_size = 1000

##### FILTERS BEGIN #####

# alidns over udp
[filters.alidns]
kind = "proxyby"
props = { servers = ["223.5.5.5", "223.6.6.6"] }

# opendns over tcp
[filters.opendns]
kind = "proxyby"
props = { servers = ["tcp://208.67.222.222:443", "tcp://208.67.220.220:443"] }

# a chinadns filter:
#  - use trusted dns servers for oversea domain
#  - use mistrusted dns servers for Chinese domain
# NOTICE: require 'geoip_database', you can download from https://git.io/GeoLite2-Country.mmdb
[filters.chinadns]
kind = "chinadns"
props = { trusted = ["tcp://208.67.222.222:443", "tcp://208.67.220.220:443"], mistrusted = ["223.5.5.5", "223.6.6.6"], geoip_database = "GeoLite2-Country.mmdb" }

##### FILTERS END #####

##### RULES BEGIN #####

# NOTICE:
# - will check rules below one by one
# - the 'domain' field follows the glob syntax

# for domain of '*.cn', use alidns filter
[[rules]]
domain = "*.cn"
filter = "alidns"

# for domain of '*apple.com', use alidns filter
[[rules]]
domain = "*.apple.com"
filter = "alidns"

# for domain of '*google*', use opendns filter
[[rules]]
domain = "*google*"
filter = "opendns"

# FINAL: use chinadns for others
[[rules]]
domain = "*"
filter = "chinadns"

##### RULES END #####


```
