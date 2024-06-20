FROM rust:1.77 AS builder
WORKDIR app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR app
COPY --from=builder /app/target/release/deoptimizer /usr/local/bin
ENTRYPOINT ["/usr/local/bin/deoptimizer"]
