# Builds a static (musl) xdr-agent-rs that runs on any Linux distribution:
#   docker build -f agent-rs/Dockerfile --output type=local,dest=bin agent-rs
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p xdr-agent && cp target/release/xdr-agent-rs /xdr-agent-rs

FROM scratch
COPY --from=build /xdr-agent-rs /xdr-agent-rs
