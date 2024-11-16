FROM rust:1.81 AS builder

WORKDIR /usr/src/zerodns

COPY . .

RUN cargo build --release && \
    cp target/release/zerodns /usr/local/cargo/bin/zerodns && \
    cargo clean

FROM ubuntu:jammy

LABEL maintainer="jjeffcaii@outlook.com"

VOLUME /etc/zerodns /var/log/zerodns

COPY --from=builder /usr/local/cargo/bin/zerodns /usr/local/bin/zerodns

ENTRYPOINT ["zerodns"]
