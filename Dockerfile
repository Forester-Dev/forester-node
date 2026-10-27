FROM rust:1.99.0-alpine3.23 AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Fully static binary: runs on any Linux, any libc
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --locked --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/forester-node /forester-node && strip /forester-node

FROM alpine:3.23
RUN addgroup -S -g 10001 forester && adduser -S -u 10001 -G forester forester \
    && mkdir -p /data && chown forester:forester /data
COPY --from=build /forester-node /usr/local/bin/forester-node
USER forester
ENV FORESTER_DATA_DIR=/data \
    FORESTER_RTC_PORT=8096
VOLUME ["/data"]
# Direct browser and LAN transfers (WebRTC over UDP)
EXPOSE 8096/udp
ENTRYPOINT ["forester-node"]
CMD ["run"]
