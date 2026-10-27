# Builds a static (musl) xdr-agent-rs that runs on any Linux distribution:
#   make agent-rs  (works with the legacy builder and with BuildKit)
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p xdr-agent && cp target/release/xdr-agent-rs /xdr-agent-rs

FROM scratch
COPY --from=build /xdr-agent-rs /xdr-agent-rs
# Only so `docker create` accepts the image; make copies the binary out.
CMD ["/xdr-agent-rs"]
