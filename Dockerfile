# linux/amd64 only. The pinned Odin compiler is the official linux amd64 tarball.
# A build for another architecture stops here instead of linking a binary that
# cannot run.
FROM --platform=linux/amd64 rust:1.100-bookworm AS build
ARG TARGETARCH=amd64
RUN test "$TARGETARCH" = "amd64" || (echo "unsupported architecture: $TARGETARCH (linux/amd64 only)" && exit 1)
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates clang curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/odin.tar.gz \
        https://github.com/odin-lang/Odin/releases/download/dev-2026-10/odin-linux-amd64-dev-2026-10.tar.gz \
    && echo "c3c8b095621fd0c75f7f73e3a0829f1b4d45324225f20ba11ed8dc4da310a8ab  /tmp/odin.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/odin \
    && tar -xzf /tmp/odin.tar.gz -C /opt/odin --strip-components=1 \
    && rm /tmp/odin.tar.gz \
    && /opt/odin/odin version | tee /tmp/odin-version.txt \
    && grep -E "dev-2026-10|84bc3fc" /tmp/odin-version.txt
ENV PATH="/opt/odin:${PATH}"
# marmot-markdown's build script links the Odin backend with the toolchain's
# opt, rust-lld, and llvm-ar. Those ship in the llvm-tools component.
RUN rustup component add llvm-tools
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --locked -p watchdog-native \
    && cargo build --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml --bin watchdog-marmot

# Optional build target for the Linux image qualification driver.
FROM build AS image-test-driver-build
RUN mkdir -p /out \
    && cargo test --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml \
         --test fixture_exchange --no-run --message-format=json > /tmp/test-artifacts.jsonl \
    && driver="$(sed -n 's@.*"executable":"\([^"]*/fixture_exchange-[^"]*\)".*@\1@p' /tmp/test-artifacts.jsonl)" \
    && test -x "$driver" \
    && cp "$driver" /out/fixture_exchange

FROM scratch AS image-test-driver
COPY --from=image-test-driver-build /out/fixture_exchange /out/fixture_exchange
ENTRYPOINT ["/out/fixture_exchange"]

FROM --platform=linux/amd64 debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home watchdog \
    && mkdir -p /data/marmot /usr/local/share/nostr-watchdog \
    && chown -R watchdog:watchdog /data \
    && chmod 0700 /data /data/marmot
COPY LICENSE /usr/local/share/nostr-watchdog/LICENSE
COPY --from=build /src/target/release/nostr-watchdog /usr/local/bin/nostr-watchdog
COPY --from=build /src/crates/watchdog-marmot/target/release/watchdog-marmot /usr/local/bin/watchdog-marmot
USER watchdog
WORKDIR /data
VOLUME /data
ENV DATABASE_PATH=/data/watchdog.sqlite
ENV LISTEN_ADDR=0.0.0.0:8787
ENV MARMOT_HELPER=/usr/local/bin/watchdog-marmot
ENV MARMOT_ROOT=/data/marmot
EXPOSE 8787
ENTRYPOINT ["nostr-watchdog"]
