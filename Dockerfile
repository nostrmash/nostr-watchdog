FROM rust:1.100-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --locked -p watchdog-native \
    && cargo build --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml --bin watchdog-marmot

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home watchdog \
    && mkdir -p /data /var/lib/watchdog/marmot /usr/local/share/nostr-watchdog \
    && chown -R watchdog:watchdog /data /var/lib/watchdog \
    && chmod 0700 /data /var/lib/watchdog /var/lib/watchdog/marmot
COPY LICENSE /usr/local/share/nostr-watchdog/LICENSE
COPY --from=build /src/target/release/nostr-watchdog /usr/local/bin/nostr-watchdog
COPY --from=build /src/crates/watchdog-marmot/target/release/watchdog-marmot /usr/local/bin/watchdog-marmot
USER watchdog
WORKDIR /data
VOLUME /data
ENV DATABASE_PATH=/data/watchdog.sqlite
ENV LISTEN_ADDR=0.0.0.0:8787
ENV MARMOT_HELPER=/usr/local/bin/watchdog-marmot
ENV MARMOT_ROOT=/var/lib/watchdog/marmot
EXPOSE 8787
ENTRYPOINT ["nostr-watchdog"]
