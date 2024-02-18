FROM rust:1.76-alpine as builder
WORKDIR /usr/src/zerodns
COPY . .

RUN apk add --no-cache musl-dev

RUN cargo install --path .

FROM alpine:3

LABEL maintainer="jjeffcaii@outlook.com"

COPY --from=builder /usr/local/cargo/bin/zerodns /usr/local/bin/zerodns

ENTRYPOINT ["zerodns"]
