# Supply reviewed, digest-pinned images through Compose/build arguments.
ARG RUST_IMAGE=rust@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea
ARG RUNTIME_IMAGE=debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
FROM ${RUST_IMAGE} AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked

FROM ${RUNTIME_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 vault \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin vault \
    && install -d -o vault -g vault -m 0700 /data
WORKDIR /app
COPY --from=builder /build/target/release/private-vault /usr/local/bin/private-vault
COPY scripts/snapshot.py /app/scripts/snapshot.py
USER 10001:10001
ENV VAULT_DATABASE=/data/vault.sqlite
ENTRYPOINT ["private-vault"]
CMD ["serve"]
