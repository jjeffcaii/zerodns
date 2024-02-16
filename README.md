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
```
