use super::{TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
use crate::snp::{
    get_common_name, get_oid_int, get_oid_octets, ProcessorGeneration, CERT_CHAINS, HW_ID_OID,
    LOADER_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, UCODE_SPL_OID,
};
use crate::{InitDataHash, ReportData};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use az_snp_vtpm::certs::{AmdChain, Vcek};
use az_snp_vtpm::report::AttestationReport;
use az_snp_vtpm::vtpm::QuoteError;
use base64::{engine::general_purpose::STANDARD, Engine};
use eventlog::cel::{Cel, MrBank, TPM_ALG_SHA384};
use log::info;
use openssl::{ec::EcKey, ecdsa, sha::sha384};
use quote::Quote;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sev::{
    certs::snp::Certificate,
    firmware::host::{CertTableEntry, CertType},
};
use std::collections::HashMap;
use std::mem::offset_of;
use thiserror::Error;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;
use uuid::Uuid;
use x509_parser::prelude::*;

pub mod quote;
const HCL_VMPL_VALUE: u32 = 0;
const COS_EVENT_PCR: u8 = 13;
const CERT_TABLE_ENTRY_SIZE: usize = 16 + 4 + 4; // 24

struct GcpVendorCertificates {
    ca_chain: AmdChain,
}

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: Quote,
    report: Vec<u8>,
    vcek: String,
    canoical_event_log: Vec<u8>,
}

pub struct GcpSnpVtpm {
    vendor_certs: GcpVendorCertificates,
}

#[derive(Debug)]
struct CertTableHeaderEntry {
    guid: Uuid,
    offset: u32,
    length: u32,
}

#[derive(Error, Debug)]
pub enum CertError {
    #[error("Failed to load Milan cert chain")]
    LoadMilanCert,
    #[error("TPM quote nonce doesn't match expected report_data")]
    NonceMismatch,
    #[error("SNP report report_data mismatch")]
    SnpReportMismatch,
    #[error("VMPL of SNP report is not {0}")]
    VmplIncorrect(u32),
    #[error(transparent)]
    Quote(#[from] QuoteError),
    #[error(transparent)]
    JsonWebkey(#[from] jsonwebkey::ConversionError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

// Gcp vTPM still initialized to Milan only certs until az_snp_vtpm crate gets updated.
impl GcpSnpVtpm {
    pub fn new() -> Result<Self, CertError> {
        let vendor_certs = CERT_CHAINS
            .get(&ProcessorGeneration::Milan)
            .ok_or(CertError::LoadMilanCert)?
            .clone();
        Ok(Self {
            vendor_certs: GcpVendorCertificates {
                ca_chain: AmdChain {
                    ask: vendor_certs.ask.into(),
                    ark: vendor_certs.ark.into(),
                },
            },
        })
    }
}

#[async_trait]
impl Verifier for GcpSnpVtpm {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let evidence = serde_json::from_value::<Evidence>(evidence)
            .context("Failed to deserialize Gcp vTPM SEV-SNP evidence")?;

        // 1. Verify SNP Report
        let snp_report: AttestationReport =
            bincode::deserialize(&STANDARD.decode(&evidence.report)?)?;

        let cert_table = unmarshal_cert_table(&STANDARD.decode(&evidence.vcek)?).unwrap();

        self.vendor_certs
            .ca_chain
            .validate()
            .context("Failed to validate CA chain")?;
        let vek = Certificate::from_bytes(cert_table[0].data()).unwrap();
        let vcek = Vcek::from_pem(std::str::from_utf8(&vek.to_pem().unwrap()).unwrap()).unwrap();

        vcek.validate(&self.vendor_certs.ca_chain)
            .context("Failed to validate VCEK")?;

        verify_snp_report(&snp_report, &vcek)?;

        // 2. Verify Tpm Quote Signature
        let ak_cert_str = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            evidence.quote.ak_cert
        );
        let ak_cert = Certificate::from_pem(ak_cert_str.as_bytes()).unwrap();
        let ak_pub = ak_cert.public_key().unwrap();

        evidence.quote.verify_signature(&ak_pub)?;
        evidence.quote.verify_nonce(&snp_report.report_data)?;

        let mut pcr_value = Vec::new();
        if let AttestInfo::Quote { info } = Attest::unmarshall(&evidence.quote.message)?.attested()
        {
            pcr_value = info.pcr_digest().to_vec();
        } else {
            bail!("unsupported attest type");
        };

        // 3. Verify Canonical Event Log
        let cel = Cel::from_bytes(&evidence.canoical_event_log).unwrap();
        for (i, record) in cel.records.iter().enumerate() {
            record
                .verify_digests()
                .context(format!("Record {} digest verification failed", i))?;
        }

        let mut registers = HashMap::new();
        registers.insert(COS_EVENT_PCR - 1, pcr_value.clone());
        let mr_bank = MrBank {
            hash_alg: TPM_ALG_SHA384,
            registers: registers,
        };

        cel.replay(&mr_bank)?;
        info!("Canonical event log replayed successfully!");

        let mut claim = parse_tee_evidence_gcp(&snp_report);
        let Value::Object(ref mut map) = claim else {
            bail!("failed to extend the claim, not an object");
        };

        let mut tpm_values = serde_json::Map::new();
        tpm_values.insert(
            format!("pcr{:02}", 13),
            Value::String(hex::encode(&pcr_value)),
        );
        map.insert("tpm".to_string(), Value::Object(tpm_values));
        let cel_map = cel.to_parsed_claims();
        map.insert("canonical_eventlog".to_string(), Value::Object(cel_map));

        Ok((claim, "cpu".to_string()))
    }
}

/// Verifies the signature of the attestation report using the provided certificate chain and vendor certificates.
fn verify_report_signature(report: &AttestationReport, vcek: &Vcek) -> Result<()> {
    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser

    let endorsement_key_der = &vcek.0.to_der()?;
    let parsed_endorsement_key = X509Certificate::from_der(endorsement_key_der)?
        .1
        .tbs_certificate;

    let common_name = get_common_name(&vcek.0).context("No common name found in certificate")?;

    // if the common name is "VCEK", then the key is a VCEK
    // so lets check the chip id
    if common_name == "VCEK"
        && get_oid_octets::<64>(&parsed_endorsement_key, HW_ID_OID)? != report.chip_id
    {
        bail!("Chip ID mismatch");
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_endorsement_key, UCODE_SPL_OID)? != report.reported_tcb.microcode {
        bail!("Microcode version mismatch");
    }

    if get_oid_int(&parsed_endorsement_key, SNP_SPL_OID)? != report.reported_tcb.snp {
        bail!("SNP version mismatch");
    }

    if get_oid_int(&parsed_endorsement_key, TEE_SPL_OID)? != report.reported_tcb.tee {
        bail!("TEE version mismatch");
    }

    if get_oid_int(&parsed_endorsement_key, LOADER_SPL_OID)? != report.reported_tcb.bootloader {
        bail!("Boot loader version mismatch");
    }

    // verify report signature
    let sig = ecdsa::EcdsaSig::try_from(&report.signature)?;
    // Get the offset of the signature field in the report struct
    let signature_offset = offset_of!(AttestationReport, signature);
    let data = &bincode::serialize(&report)?[..signature_offset];

    let pub_key = EcKey::try_from(vcek.0.public_key()?)?;
    let signed = sig.verify(&sha384(data), &pub_key)?;
    if !signed {
        bail!("Signature validation failed.");
    }

    Ok(())
}

fn verify_snp_report(snp_report: &AttestationReport, vcek: &Vcek) -> Result<(), CertError> {
    verify_report_signature(snp_report, vcek)?;

    if snp_report.vmpl != HCL_VMPL_VALUE {
        return Err(CertError::VmplIncorrect(HCL_VMPL_VALUE));
    }

    Ok(())
}

/// Parses the attestation report and extracts the TEE evidence claims.
/// Returns a JSON-formatted map of parsed claims.
pub(crate) fn parse_tee_evidence_gcp(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", report.reported_tcb.bootloader),
        "reported_tcb_tee": format!("{}", report.reported_tcb.tee),
        "reported_tcb_snp": format!("{}", report.reported_tcb.snp),
        "reported_tcb_microcode": format!("{}", report.reported_tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurements
        "measurement": format!("{}", STANDARD.encode(report.measurement)),
        "report_data": format!("{}", STANDARD.encode(report.report_data)),
        "init_data": format!("{}", STANDARD.encode(report.host_data)),
    });

    claims_map as TeeEvidenceParsedClaim
}

fn parse_snp_cert_table_header(certs: &[u8]) -> Result<Vec<CertTableHeaderEntry>, String> {
    if certs.is_empty() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<CertTableHeaderEntry> = Vec::new();
    let mut slice = certs;
    let mut index_bytes_consumed: usize = 0;
    loop {
        if slice.len() < CERT_TABLE_ENTRY_SIZE {
            return Err(format!(
                "truncated cert table header: need {} bytes but have {}",
                CERT_TABLE_ENTRY_SIZE,
                slice.len()
            ));
        }
        let guid_bytes = &slice[0..16];
        let offset_bytes: [u8; 4] = slice[16..20].try_into().unwrap();
        let length_bytes: [u8; 4] = slice[20..24].try_into().unwrap();
        let offset = u32::from_le_bytes(offset_bytes);
        let length = u32::from_le_bytes(length_bytes);
        // advance slice and index (note: increment happens before checking terminator, same as Go)
        slice = &slice[CERT_TABLE_ENTRY_SIZE..];
        index_bytes_consumed += CERT_TABLE_ENTRY_SIZE;
        // detect zero terminator: guid all zero + offset==0 + length==0
        let is_guid_zero = guid_bytes.iter().all(|&b| b == 0);
        if offset == 0 && length == 0 && is_guid_zero {
            break;
        }
        let guid = Uuid::from_slice(guid_bytes)
            .map_err(|e| format!("invalid GUID at header index {}: {}", entries.len(), e))?;
        entries.push(CertTableHeaderEntry {
            guid,
            offset,
            length,
        });
    }
    // After reading header (including terminator), index_bytes_consumed is header size.
    for (i, e) in entries.iter().enumerate() {
        if (e.offset as usize) < index_bytes_consumed {
            return Err(format!(
                "cert table entry {} has invalid offset into header (header size {}): {}",
                i, index_bytes_consumed, e.offset
            ));
        }
    }
    Ok(entries)
}

pub fn unmarshal_cert_table(certs: &[u8]) -> Result<Vec<CertTableEntry>, String> {
    let header_entries = parse_snp_cert_table_header(certs)?;
    let mut result_entries: Vec<CertTableEntry> = Vec::with_capacity(header_entries.len());
    for (i, he) in header_entries.into_iter().enumerate() {
        let off = he.offset as usize;
        let len = he.length as usize;
        if off.checked_add(len).is_none() {
            return Err(format!(
                "cert entry {} offset+length overflow: offset={}, length={}",
                i, he.offset, he.length
            ));
        }
        if off + len > certs.len() {
            return Err(format!(
                "cert table entry {} specifies a byte range outside the certificate data block (size {}): offset={}, length={}",
                i, certs.len(), he.offset, he.length
            ));
        }
        let raw = certs[off..off + len].to_vec();
        result_entries.push(CertTableEntry {
            cert_type: CertType::try_from(&he.guid).unwrap(),
            data: raw,
        });
    }
    Ok(result_entries)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use eventlog::cel::Cel;
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;
    use openssl::{hash::MessageDigest, sha::Sha256, sign::Verifier as SslVerifier};
    use tss_esapi::structures::Signature;

    const REPORT: &str = include_str!("../../test_data/gcp-snp-vtpm/report.bin");
    const VCEK: &str = include_str!("../../test_data/gcp-snp-vtpm/vcek.bin");
    const CEL: &str = include_str!("../../test_data/gcp-snp-vtpm/cel.bin");
    const QUOTE: &str = include_str!("../../test_data/gcp-snp-vtpm/quote.bin");

    #[test]
    fn test_new_gcp_snp_vtpm() {
        GcpSnpVtpm::new().unwrap();
    }

    #[test]
    fn test_hcl_report() {
        let report_bin = STANDARD.decode(REPORT).unwrap();
        let report: AttestationReport = bincode::deserialize(&report_bin)
            .context("Deserialize SNP Report failed")
            .unwrap();
        let vcek_bin = STANDARD.decode(VCEK).unwrap();
        // cert_table[0] is vcek
        let cert_table = unmarshal_cert_table(&vcek_bin).unwrap();

        let vendor_certs = CERT_CHAINS
            .get(&ProcessorGeneration::Milan)
            .unwrap()
            .clone();
        let vek = Certificate::from_bytes(cert_table[0].data()).unwrap();
        let vcek = Vcek::from_pem(std::str::from_utf8(&vek.to_pem().unwrap()).unwrap()).unwrap();
        let amd_chain = AmdChain {
            ask: vendor_certs.ask.into(),
            ark: vendor_certs.ark.into(),
        };
        amd_chain.validate().unwrap();
        vcek.validate(&amd_chain).unwrap();
        verify_snp_report(&report, &vcek).unwrap();
    }

    #[test]
    fn test_cel() {
        let cel = Cel::from_str(CEL).unwrap();
        for record in cel.records {
            println!("{:?}", record);
        }
    }

    #[test]
    fn test_quote() {
        let quote = STANDARD.decode(QUOTE).unwrap();
        let quote_str = std::str::from_utf8(&quote).unwrap();
        let tpm_quote: Quote = serde_json::from_str(quote_str).unwrap();
        let message = STANDARD.decode(tpm_quote.message).unwrap();
        let signature = STANDARD.decode(tpm_quote.signature).unwrap();
        let ak_cert_str = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            tpm_quote.ak_cert
        );
        println!("ak_cert_str {}", ak_cert_str);
        let ak_cert = Certificate::from_pem(ak_cert_str.as_bytes()).unwrap();
        let ak_pub = ak_cert.public_key().unwrap();
        let sig: Signature = Signature::unmarshall(&signature).unwrap();
        let Signature::EcDsa(ecc_sig) = sig else {
            panic!("unsupported signature method");
        };
        let r = ecc_sig.signature_r().to_vec();
        let s = ecc_sig.signature_s().to_vec();
        let sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&r).unwrap(),
            BigNum::from_slice(&s).unwrap(),
        )
        .unwrap();
        let der_sig = sig.to_der().unwrap();
        let mut verifier = SslVerifier::new(MessageDigest::sha256(), &ak_pub).unwrap();
        verifier.update(&message).unwrap();
        let is_verified = verifier.verify(&der_sig).unwrap();
        assert!(!is_verified, "signature is not verified");
    }

    #[test]
    fn test_signature() {
        let sig_bytes = STANDARD.decode("ABgACwAgPxlrlBI6dWBQIXwCQ9RFNjWUEN9PG1TdIiT+pWeyKcoAIDSSkNdirFUoVzXf6O2dPuHIJX4TEmnb7pgqPVXpptYC").unwrap();
        let sig: Signature = Signature::unmarshall(&sig_bytes).unwrap();
        let Signature::EcDsa(ecc_sig) = sig else {
            panic!("unsupported signature method");
        };
        let r = ecc_sig.signature_r().to_vec();
        let s = ecc_sig.signature_s().to_vec();
        let sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&r).unwrap(),
            BigNum::from_slice(&s).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_attest() {
        let attest_bytes = STANDARD.decode("/1RDR4AYACIACwiPvWKV13hmR87GGn/mXQcLvxSwxACGLWjYWAQMbfiTADA/PcYppHUJU4iXec3ypIp9BmnrWEtGtQ4sIVmv2gR7obPPTIrVKsobCLGvDcAiDTUAAAAANg3BswAAAFYAAAAAASAWBREAFigAAAAAAQAMAwAgAAAgAzFTYkGgucW7q1UEk24dxeO1+cE+D15Rf3v+5K6diK4=").unwrap();
        let attest = Attest::unmarshall(&attest_bytes).unwrap();
        let AttestInfo::Quote { info } = attest.attested() else {
            panic!("unsupported attest type");
        };
    }
}
