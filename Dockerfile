FROM ekidd/rust-musl-builder AS builder
COPY . ./
RUN sudo chown -R rust:rust /home/rust
RUN cargo build --release

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder \
    /home/rust/src/target/x86_64-unknown-linux-musl/release/owhois \
    /usr/local/bin
COPY --from=builder \
    /home/rust/src/target/x86_64-unknown-linux-musl/release/process-public-data \
    /usr/local/bin
COPY ./get-public-data /usr/local/bin
CMD /usr/local/bin/owhois
