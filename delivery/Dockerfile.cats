FROM ubuntu:21.10 as builder

ARG TIMEOUT
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /root

RUN apt-get update \
    && apt-get install --no-install-recommends -qq -y \
    curl \
    build-essential \
    libssl-dev \
    ca-certificates \
    libclang-dev \
    libsodium-dev \
    pkg-config \
    && apt-get -y -q upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "nightly-x86_64-unknown-linux-gnu"

COPY . /root/kms

WORKDIR /root/kms
RUN /root/.cargo/bin/cargo build --release --features dev

#
# KMS Server
#
FROM ubuntu:21.10 as kms

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -qq -y \
    ca-certificates \
    libssl-dev \
    libsodium-dev \
    && apt-get -y -q upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/kms/target/release/cosmian_kms_server /usr/bin/cosmian_kms_server
COPY --from=builder /root/kms/target/release/cosmian_kms_cli /usr/bin/cosmian_kms_cli

ENTRYPOINT ["cosmian_kms_server"]