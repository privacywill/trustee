#!/bin/bash
ARCH=x86_64

mkdir -p output/bin

cargo build --bin restful-as --features restful-bin,tdx-verifier,snp-verifier,gcp-snp-vtpm-verifier --release

cp target/release/restful-as output/bin/restful-as
cp attestation-service/config.json output/bin/config.json