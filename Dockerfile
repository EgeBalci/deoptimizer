FROM rust:1.77

COPY ./ ./
RUN cargo build --release
CMD ["./target/release/deoptimizer"]
