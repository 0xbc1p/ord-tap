# syntax=docker/dockerfile:1.7
FROM rust:1.89-bookworm AS builder

WORKDIR /usr/src/ord

# RE2 is required for DMT regex parity (see README).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libre2-dev pkg-config clang \
 && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --bin ord --release

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl libre2-9 \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -m -d /var/lib/ord-tap ord \
 && mkdir -p /var/lib/ord-tap \
 && chown -R ord:ord /var/lib/ord-tap

COPY --from=builder /usr/src/ord/target/release/ord /usr/local/bin/ord
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER ord
WORKDIR /var/lib/ord-tap

ENV RUST_BACKTRACE=1 \
    RUST_LOG=info \
    ORD_TAP_INDEX=/var/lib/ord-tap/index.redb \
    ORD_TAP_HTTP_PORT=3333 \
    ORD_TAP_HTTP_HOST=0.0.0.0

EXPOSE 3333
VOLUME ["/var/lib/ord-tap"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["server"]
