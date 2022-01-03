FROM docker.io/rust:latest as builder
WORKDIR /usr/src/app
COPY Cargo.* .
COPY src/ src
RUN ls -al && cargo build --release

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest
COPY --from=builder /usr/src/app/target/release/cf-dns-record-update /usr/local/bin/cf-dns-record-update
ENTRYPOINT ["cf-dns-record-update"]
CMD ["help"]
