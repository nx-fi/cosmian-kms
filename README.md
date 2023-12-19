# Cosmian KMS

![Build status](https://github.com/Cosmian/kms/actions/workflows/ci.yml/badge.svg?branch=main)

Cosmian KMS is an open-source implementation of a high-performance, massively scalable, **Key Management System** that presents some unique features, such as

- the ability to run in a public cloud - or any zero-trust environment - using application-level encryption (see [Redis-Findex](https://docs.cosmian.com/cosmian_key_management_system/replicated_mode/))
- a JSON KMIP 2.1 compliant interface
- support for object tagging to easily manage keys and secrets
- a full-featured command line interface ([CLI](https://docs.cosmian.com/cosmian_key_management_system/cli/cli/))
- Python, Javascript, Dart, Rust, C/C++ and Java clients (see the `cloudproof` libraries on [Cosmian Github](https://github.com/Cosmian))

It has extensive [documentation](https://docs.cosmian.com/cosmian_key_management_system/) and is also available packaged as docker images (`docker pull ghcr.io/cosmian/kms`) to get you started quickly.

The KMS can manage keys and secrets used with a comprehensive list of common (AES, ECIES, ...) and Cosmian advanced cryptographic stacks such as [Covercrypt](https://github.com/Cosmian/cover_crypt). Keys can be wrapped and unwrapped using ECIES or RFC5649.

## Repository content

The server is written in [Rust](https://www.rust-lang.org/) and is broken down into several binaries:

- A server (`cosmian_kms_server`) which is the KMS itself
- A CLI (`ckms`) to interact with this server

And also some libraries:

- `cosmian_kms_client` to query the server
- `cosmian_kms_utils` to create KMIP requests for the crypto-systems designed by _Cosmian_
- `cosmian_kmip` which is an implementation of the KMIP standard
- `cosmian_kms_pyo3` a KMS client in Python.

**Please refer to the README of the inner directories to have more
information.**

You can build a docker containing the KMS server as follow:

```sh
# Example with auth and https features
docker build . --network=host \
               --build-arg  \
               -t kms
```

The `delivery` directory contains all the requirements to proceed with a KMS delivery based on a docker creation.

Find the public documentation of the KMS in the `documentation` directory.

## Build quick start

From the root of the project, on your local machine, for developing:

```sh
cargo build --no-default-features
cargo test --no-default-features
```

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com/kms/).

## Setup as a `Supervisor` service

Copy the binary `target/release/cosmian_kms` to the remote machine folder according to [cosmian_kms.ini](./resources/supervisor/cosmian_kms.ini) statement (ie: `/usr/sbin/cosmian_kms`).

Copy the [cosmian_kms.ini](./resources/supervisor/cosmian_kms.ini) config file as `/etc/supervisord.d/cosmian_kms.ini` in the remote machine.

Run:

```console
supervisorctl reload
supervisorctl start cosmian_kms
supervisorctl status cosmian_kms
```

## Server parameters

Order of variables for server configuration:
- args in command line
- env var
- conf file
- default (set on struct)
