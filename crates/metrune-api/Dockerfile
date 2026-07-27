FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release -p metrune-api -p metrune

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/metrune/secrets && chown -R 65532:65532 /var/lib/metrune
COPY --from=builder /src/target/release/metrune-api /usr/local/bin/metrune-api
COPY --from=builder /src/target/release/metrune /tmp/metrune-downloads/metrune-linux-x86_64
COPY pricing/openrouter.catalog.json /usr/share/metrune/pricing/openrouter.catalog.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["metrune-api"]
