FROM rust:1.100-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release -p watchdog-native

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home watchdog \
    && mkdir -p /data \
    && chown watchdog:watchdog /data
COPY --from=build /src/target/release/nostr-watchdog /usr/local/bin/nostr-watchdog
USER watchdog
WORKDIR /data
VOLUME /data
ENV DATABASE_PATH=/data/watchdog.sqlite
ENV LISTEN_ADDR=0.0.0.0:8787
EXPOSE 8787
ENTRYPOINT ["nostr-watchdog"]
