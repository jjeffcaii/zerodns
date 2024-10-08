FROM rust:1.76-alpine as builder
WORKDIR /usr/src/zerodns
COPY . .

RUN apk add musl-dev luajit-dev --no-cache

RUN cargo install --path .

FROM alpine:3

LABEL maintainer="jjeffcaii@outlook.com"

RUN apk add luajit --no-cache

COPY --from=builder /usr/local/cargo/bin/zerodns /usr/local/bin/zerodns

ENTRYPOINT ["zerodns"]
