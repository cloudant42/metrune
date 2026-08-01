FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release -p metrune-api -p metrune
# A manifest covering the Linux client this image carries, so a fresh
# deployment can mirror and verify one platform with no operator setup. Mount a
# release manifest over /usr/share/metrune/downloads to mirror every platform —
# see docs/CLIENT_DISTRIBUTION.md.
ARG METRUNE_CLIENT_VERSION=0.0.0-source
ARG METRUNE_RELEASE_BASE_URL=https://github.com/cloudant42/metrune/releases/download/client-v0.1.0
RUN cd /src/target/release \
    && sha256sum metrune > SHA256SUMS.tmp \
    && sed 's/ metrune$/ metrune-linux-x86_64/' SHA256SUMS.tmp > SHA256SUMS \
    && ./metrune release manifest \
        --version "${METRUNE_CLIENT_VERSION}" \
        --minimum-version "${METRUNE_CLIENT_VERSION}" \
        --checksums SHA256SUMS \
        --upstream-base-url "${METRUNE_RELEASE_BASE_URL}" \
        --output client-manifest.json

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/metrune/secrets && chown -R 65532:65532 /var/lib/metrune
COPY --from=builder /src/target/release/metrune-api /usr/local/bin/metrune-api
COPY --from=builder /src/target/release/metrune /usr/share/metrune/downloads/metrune-linux-x86_64
COPY --from=builder /src/target/release/client-manifest.json /usr/share/metrune/downloads/client-manifest.json
COPY pricing/openrouter.catalog.json /usr/share/metrune/pricing/openrouter.catalog.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["metrune-api"]
