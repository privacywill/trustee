use anyhow::{bail, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use log::info;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::{PKey, Public};
use openssl::{hash::MessageDigest, sign::Verifier};
use serde::{Deserialize, Deserializer, Serialize};
use tss_esapi::structures::{Attest, Signature};
use tss_esapi::traits::UnMarshall;

pub fn base64_to_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Quote {
    pub ak_cert: String,
    #[serde(deserialize_with = "base64_to_vec")]
    pub message: Vec<u8>,
    #[serde(deserialize_with = "base64_to_vec")]
    pub signature: Vec<u8>,
    pub pcr: u32,
}

impl Quote {
    /// Retrieve PCR values from a Quote
    pub fn pcrs(&self) -> u32 {
        self.pcr
    }

    /// Extract nonce from a Quote
    pub fn nonce(&self) -> Result<Vec<u8>> {
        let attest = Attest::unmarshall(&self.message)?;
        let nonce = attest.extra_data().to_vec();
        Ok(nonce)
    }

    /// Extract message from a Quote
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    pub fn verify_signature(&self, pub_key: &PKey<Public>) -> Result<()> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
        verifier.update(&self.message)?;

        // Convert signature to der
        let sig: Signature = Signature::unmarshall(&self.signature).unwrap();
        let Signature::EcDsa(ecc_sig) = sig else {
            bail!("invalid signature method");
        };
        let r = ecc_sig.signature_r().to_vec();
        let s = ecc_sig.signature_s().to_vec();
        let ecdsa_sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&r).unwrap(),
            BigNum::from_slice(&s).unwrap(),
        )
        .unwrap();
        let der_sig = ecdsa_sig.to_der().unwrap();
        let is_verified = verifier.verify(&der_sig)?;
        if !is_verified {
            bail!("quote is not signed by key");
        }
        info!("TPM quote verification completed successfully");
        Ok(())
    }

    pub fn verify_nonce(&self, report_data: &[u8]) -> Result<()> {
        let nonce = self.nonce()?;
        if nonce != report_data[0..48] {
            bail!("nonce mismatch");
        }
        info!("TPM report_data verification completed successfully");
        Ok(())
    }
}
