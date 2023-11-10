#!/bin/bash

SGX_SIGNER_KEY="/opt/cosmian-internal/cosmian-signer-key.pem"

mkdir -p /root/public_data/
mkdir -p /root/private_data/

if [ $# -eq 0 ]; then
    if ! [ -e "/dev/sgx_enclave" ]; then
        echo "You are not running on an sgx machine"
        echo "If you want to compute the MR_ENCLAVE, re-run with --emulation parameter"
        exit 1
    fi
    make SGX=1 SGX_SIGNER_KEY=$SGX_SIGNER_KEY KMS_USE_BOOTSTRAP_SERVER="${KMS_USE_BOOTSTRAP_SERVER}" KMS_USE_CERTBOT="${KMS_USE_CERTBOT}" KMS_CERTBOT_HOSTNAME="${KMS_CERTBOT_HOSTNAME}" KMS_CERTBOT_EMAIL="${KMS_CERTBOT_EMAIL}" KMS_CERTBOT_USE_TEE_KEY="${KMS_CERTBOT_USE_TEE_KEY}" && gramine-sgx ./kms
elif [ $# -eq 1 ] && [ "$1" = "--emulation" ]; then
    mkdir /opt/cosmian-internal
    # Generate a dummy key. `MR_ENCLAVE` does not depend on it.
    openssl genrsa -3 -out $SGX_SIGNER_KEY 3072
    # Compile but don't start
    make SGX=1 SGX_SIGNER_KEY=$SGX_SIGNER_KEY KMS_USE_BOOTSTRAP_SERVER="${KMS_USE_BOOTSTRAP_SERVER}" KMS_USE_CERTBOT="${KMS_USE_CERTBOT}" KMS_CERTBOT_HOSTNAME="${KMS_CERTBOT_HOSTNAME}" KMS_CERTBOT_EMAIL="${KMS_CERTBOT_EMAIL}" KMS_CERTBOT_USE_TEE_KEY="${KMS_CERTBOT_USE_TEE_KEY}"
    # Note: if `public_data` is mounted inside the docker, the user can read `kms.manifest.kms` from outside the docker
else
    echo "Usage: $0 [--emulation]"
    echo ""
    echo "Using --emulation enables you to get the MR_ENCLAVE of the enclave server"
    echo "You don't need to use an SGX machine to use --emulation param"
fi
