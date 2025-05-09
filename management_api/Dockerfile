FROM rust:1.86-slim-bullseye

# Update package lists and install security updates
RUN apt-get update && apt-get upgrade -y && apt-get clean

WORKDIR /app

COPY . .

RUN cargo build --release

CMD ["./target/release/management_api"]