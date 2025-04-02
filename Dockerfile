# ---- Build Stage ----
FROM rust:1.85.1-slim AS builder

WORKDIR /app
COPY . .

# Update Cargo to the latest stable version
RUN rustup update

# Create the user in the builder stage
RUN useradd -m coentrovpn

# Build the app
RUN cargo build --release

# ---- Runtime Stage ----
FROM gcr.io/distroless/cc AS runtime

WORKDIR /app

# Copy the binary and user from the builder stage
COPY --from=builder /app/target/release/coentrovpn .
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Expose UDP port
EXPOSE 1194/udp

# Label the image
LABEL maintainer="Thales Claro Pereira" \
        version="0.1" \
        description="CoentroVPN Server"

# Change the user and run as non-root
USER coentrovpn:coentrovpn

COPY Config.toml ./Config.toml
ENTRYPOINT ["/app/coentrovpn"]
CMD ["--config", "Config.toml"]