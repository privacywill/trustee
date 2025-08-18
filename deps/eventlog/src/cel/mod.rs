use anyhow::{anyhow, bail, Result};
use base64::Engine;
use log::error;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::io::{self, Cursor, Read};
use std::str::FromStr;

// --- 1. Constants and Enums (matching Go) ---
// Corresponds to the Go constants for TLV types
const RECNUM_TYPE_VALUE: u8 = 0;
const PCR_TYPE_VALUE: u8 = 1;
const DIGESTS_TYPE_VALUE: u8 = 3;
const CCMR_TYPE_VALUE: u8 = 108;
// Corresponds to the Go `crypto.Hash` enum. We'll use the TPM algorithm IDs as keys.
// TPM 2.0 Spec, Part 2, Table 13 – Definition of TPM_ALG_ID Constants
// We only need the ones that map to crypto.Hash in the Go TPM library.
// Example: SHA256 is 0x0B, SHA384 is 0x0C
type TpmAlgId = u16;

const TPM_ALG_SHA256: TpmAlgId = 0x000B;
pub const TPM_ALG_SHA384: TpmAlgId = 0x000C;
const TPM_ALG_SHA512: TpmAlgId = 0x000D;

/// Represents a bank of Measurement Registers (like PCRs or RTMRs).
/// This holds the expected final values for verification.
pub struct MrBank {
    /// The hash algorithm used by this bank (e.g., TPM_ALG_SHA384).
    pub hash_alg: TpmAlgId,
    /// A map from register index to its expected final digest.
    pub registers: HashMap<u8, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexType {
    Pcr,
    Ccmr,
}
// --- 2. Data Structures (matching Go) ---
#[derive(Clone)]
pub struct Tlv {
    pub t: u8,
    pub v: Vec<u8>,
}
impl fmt::Debug for Tlv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to interpret the value as an ASCII string.
        // `escape_ascii()` handles non-printable characters gracefully.
        let value_as_string: String = String::from_utf8(self.v.clone()).unwrap();
        f.debug_struct("Tlv")
            .field("t", &self.t)
            .field("v (as_string)", &value_as_string) // Custom field name for clarity
            .finish()
    }
}
impl Tlv {
    /// Serializes the TLV into its binary representation (Type + Length + Value).
    /// This is the Rust equivalent of the Go `MarshalBinary` method.
    pub fn marshal_binary(&self) -> Vec<u8> {
        // Pre-allocate a buffer of the correct size for efficiency.
        // Size = 1 (type) + 4 (length) + value length.
        let mut buf = Vec::with_capacity(1 + 4 + self.v.len());
        // 1. Write the Type (1 byte)
        buf.push(self.t);
        // 2. Write the Length (4 bytes, Big Endian)
        let len_bytes = (self.v.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len_bytes);
        // 3. Write the Value
        buf.extend_from_slice(&self.v);
        buf
    }
}

#[derive(Clone)]
pub struct Record {
    pub rec_num: u64,
    pub index_type: IndexType,
    pub index: u8,
    pub digests: HashMap<TpmAlgId, Vec<u8>>,
    pub content: Tlv,
}
impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Create a temporary map to hold the hex-encoded digests for printing.
        let digests_hex: HashMap<TpmAlgId, String> = self
            .digests
            .iter()
            .map(|(alg_id, digest_bytes)| {
                // Convert byte slice to a hex string
                let hex_string = digest_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                (*alg_id, hex_string)
            })
            .collect();
        f.debug_struct("Record")
            .field("rec_num", &self.rec_num)
            .field("index_type", &self.index_type)
            .field("index", &self.index)
            .field("digests (hex)", &digests_hex) // Use the hex-encoded map
            .field("content", &self.content) // This will use the custom Tlv Debug impl
            .finish()
    }
}

impl Record {
    /// Verifies that the record's content matches its stored digests.
    /// This is the Rust equivalent of the free function `VerifyDigests` in Go.
    pub fn verify_digests(&self) -> Result<()> {
        // 1. Marshal the entire content TLV into its binary form.
        let content_bytes_to_hash = self.content.marshal_binary();

        for (alg_id, stored_digest) in &self.digests {
            // Calculate the digest of the content TLV's value.
            let calculated_digest = match *alg_id {
                TPM_ALG_SHA256 => Sha256::digest(&content_bytes_to_hash).to_vec(),
                TPM_ALG_SHA384 => Sha384::digest(&content_bytes_to_hash).to_vec(),
                TPM_ALG_SHA512 => Sha512::digest(&content_bytes_to_hash).to_vec(),
                // Add other hash algorithms as needed
                _ => {
                    bail!("Unsupported hash algorithm ID: {}", alg_id);
                }
            };
            if calculated_digest != *stored_digest {
                bail!(
                    "Digest verification failed for algorithm ID {}. Expected {}, got {}",
                    alg_id,
                    hex::encode(stored_digest),
                    hex::encode(&calculated_digest)
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Cel {
    pub records: Vec<Record>,
}
impl fmt::Debug for Cel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cel")
            .field("records", &self.records)
            .finish()
    }
}

impl Cel {
    /// Replays the event log against a given bank of measurement registers.
    /// This is the Rust equivalent of the `Replay` method in Go.
    pub fn replay(&self, bank: &MrBank) -> Result<()> {
        let mut replayed_digests: HashMap<u8, Vec<u8>> = HashMap::new();
        for record in &self.records {
            // Get the digest from the record that matches the bank's hash algorithm.
            let event_digest = record.digests.get(&bank.hash_alg).ok_or_else(|| {
                anyhow!(
                    "Record {} does not contain a digest for algorithm {}",
                    record.rec_num,
                    bank.hash_alg
                )
            })?;
            // Get the current value of the replayed register, or an initial value of all zeros.
            let current_digest = replayed_digests.entry(record.index).or_insert_with(|| {
                // Determine the size of the zeroed buffer from the hash algorithm.
                let hash_size = match bank.hash_alg {
                    TPM_ALG_SHA256 => 32,
                    TPM_ALG_SHA384 => 48,
                    TPM_ALG_SHA512 => 64,
                    _ => 0, // Will cause an error below, which is intended.
                };
                vec![0u8; hash_size]
            });
            // Perform the extend operation: new_digest = HASH(current_digest || event_digest)
            let new_digest = match bank.hash_alg {
                TPM_ALG_SHA256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&current_digest);
                    hasher.update(event_digest);
                    hasher.finalize().to_vec()
                }
                TPM_ALG_SHA384 => {
                    let mut hasher = Sha384::new();
                    hasher.update(&current_digest);
                    hasher.update(event_digest);
                    hasher.finalize().to_vec()
                }
                TPM_ALG_SHA512 => {
                    let mut hasher = Sha512::new();
                    hasher.update(&current_digest);
                    hasher.update(event_digest);
                    hasher.finalize().to_vec()
                }
                _ => bail!(
                    "Unsupported hash algorithm ID for replay: {}",
                    bank.hash_alg
                ),
            };
            // Update the replayed value.
            *current_digest = new_digest;
        }
        // Now, compare the final replayed digests with the provided bank.
        let mut failed_indices = Vec::new();
        for (index, replayed_digest) in &replayed_digests {
            match bank.registers.get(index) {
                Some(expected_digest) => {
                    if replayed_digest != expected_digest {
                        error!(
                            "Mismatch for index {}: expected {}, got {}",
                            index,
                            hex::encode(expected_digest),
                            hex::encode(replayed_digest)
                        );
                        failed_indices.push(*index);
                    }
                }
                None => {
                    bail!(
                        "Replayed digest for index {} but no corresponding register in the bank to verify",
                        index
                    );
                }
            }
        }
        if !failed_indices.is_empty() {
            bail!("CEL replay failed for registers: {:?}", failed_indices);
        }

        Ok(())
    }

    /// Parses the event log records into a structured map of claims.
    /// This version correctly parses the nested structure within the content TLV.
    pub fn to_parsed_claims(&self) -> Map<String, Value> {
        let mut claims_map = Map::new();
        for record in &self.records {
            // The content TLV's value field (`v`) contains the nested data.
            let content_data = &record.content.v;
            // --- CORE LOGIC CHANGE IS HERE ---
            // Check if the content data is long enough to contain at least a type byte.
            if content_data.is_empty() {
                // Skip this record or handle as an error if it's malformed.
                eprintln!(
                    "Warning: Record {} has an empty content field, skipping.",
                    record.rec_num
                );
                continue;
            }
            // The first byte of the content's value is the actual CosType.
            let cos_type_byte = content_data[0];
            // The rest of the slice is the actual value.
            let actual_value_bytes = &content_data[5..];
            // --- END OF CORE LOGIC CHANGE ---
            // Try to interpret the parsed type byte as a known CosType.
            if let Some(cos_type) = CosType::from_u8(cos_type_byte) {
                // The key is the string name of the event type.
                let key = cos_type.as_str().to_string();
                // The value is the rest of the content, interpreted as a string.
                let content_string = String::from_utf8_lossy(actual_value_bytes).to_string();
                let item = Value::String(content_string);
                // Insert or update the array in the map.
                claims_map
                    .entry(key)
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .unwrap()
                    .push(item);
            } else {
                // Handle cases where the type byte is unknown.
                eprintln!(
                    "Warning: Record {} has an unknown content type byte: {}",
                    record.rec_num, cos_type_byte
                );
            }
        }
        claims_map
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let cel = decode_to_cel(input)?;
        Ok(cel)
    }
}

impl FromStr for Cel {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let binary_data = base64::engine::general_purpose::STANDARD.decode(&input)?;
        let cel = decode_to_cel(&binary_data)?;
        Ok(cel)
    }
}

// Add this enum definition to your code
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosType {
    ImageRefType = 0,
    ImageDigestType = 1,
    RestartPolicyType = 2,
    ImageIDType = 3,
    ArgType = 4,
    EnvVarType = 5,
    OverrideArgType = 6,
    OverrideEnvType = 7,
    LaunchSeparatorType = 8,
    MemoryMonitorType = 9,
    GpuCCModeType = 10,
}
impl CosType {
    /// Tries to convert a u8 into a CosType.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ImageRefType),
            1 => Some(Self::ImageDigestType),
            2 => Some(Self::RestartPolicyType),
            3 => Some(Self::ImageIDType),
            4 => Some(Self::ArgType),
            5 => Some(Self::EnvVarType),
            6 => Some(Self::OverrideArgType),
            7 => Some(Self::OverrideEnvType),
            8 => Some(Self::LaunchSeparatorType),
            9 => Some(Self::MemoryMonitorType),
            10 => Some(Self::GpuCCModeType),
            _ => None,
        }
    }
    /// Returns a string representation of the enum variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ImageRefType => "image_ref",
            Self::ImageDigestType => "image_digest",
            Self::RestartPolicyType => "restart policy",
            Self::ImageIDType => "image_id",
            Self::ArgType => "args",
            Self::EnvVarType => "env",
            Self::OverrideArgType => "override_arg",
            Self::OverrideEnvType => "override_env",
            Self::LaunchSeparatorType => "launch_separator",
            Self::MemoryMonitorType => "memory_monitor",
            Self::GpuCCModeType => "gpu_cc_mode",
        }
    }
}

// --- 3. Decoding Logic ---
/// Reads and parses the first TLV from the cursor.
/// This function is critical and now correctly handles the 4-byte length.
fn unmarshal_first_tlv(cursor: &mut Cursor<&[u8]>) -> io::Result<Tlv> {
    let mut type_buf = [0u8; 1];
    cursor.read_exact(&mut type_buf)?;
    let mut len_buf = [0u8; 4]; // CRITICAL FIX: Length is 4 bytes (u32)
    cursor.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut value_buf = vec![0u8; len];
    cursor.read_exact(&mut value_buf)?;
    Ok(Tlv {
        t: type_buf[0],
        v: value_buf,
    })
}
/// Decodes a TLV into a record number (u64).
fn unmarshal_rec_num(tlv: &Tlv) -> io::Result<u64> {
    if tlv.t != RECNUM_TYPE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid type for rec_num: expected {}, got {}",
                RECNUM_TYPE_VALUE, tlv.t
            ),
        ));
    }
    if tlv.v.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rec_num length invalid: expected 8 bytes",
        ));
    }
    Ok(u64::from_be_bytes(tlv.v[..8].try_into().unwrap()))
}
/// Decodes a TLV into an index type and index number.
fn unmarshal_index(tlv: &Tlv) -> io::Result<(IndexType, u8)> {
    let index_type = match tlv.t {
        PCR_TYPE_VALUE => IndexType::Pcr,
        CCMR_TYPE_VALUE => IndexType::Ccmr,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid type for index: got {}", tlv.t),
            ))
        }
    };
    if tlv.v.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "index length invalid: expected 1 byte",
        ));
    }
    Ok((index_type, tlv.v[0]))
}
/// Decodes a TLV containing nested digest TLVs.
fn unmarshal_digests(tlv: &Tlv) -> io::Result<HashMap<TpmAlgId, Vec<u8>>> {
    if tlv.t != DIGESTS_TYPE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid type for digests field",
        ));
    }
    let mut digests_map = HashMap::new();
    // The value of the digests TLV is a new buffer containing more TLVs.
    let mut inner_cursor = Cursor::new(tlv.v.as_slice());
    while (inner_cursor.position() as usize) < tlv.v.len() {
        let digest_tlv = unmarshal_first_tlv(&mut inner_cursor)?;
        // In the Go code, the nested TLV's type is a TPM_ALG_ID.
        // We use a u16 here to represent it.
        let tpm_alg_id = digest_tlv.t as TpmAlgId; // Note: This is a simplification. Go maps crypto.Hash to TPM_ALG_ID. Here we just use the raw type byte.
        digests_map.insert(tpm_alg_id, digest_tlv.v);
    }
    Ok(digests_map)
}
/// Decodes a single Record (CELR) from the cursor.
fn decode_to_celr(cursor: &mut Cursor<&[u8]>) -> io::Result<Record> {
    // 1. Decode RecNum
    let recnum_tlv = unmarshal_first_tlv(cursor)?;
    let rec_num = unmarshal_rec_num(&recnum_tlv)?;
    // 2. Decode Index
    let index_tlv = unmarshal_first_tlv(cursor)?;
    let (index_type, index) = unmarshal_index(&index_tlv)?;
    // 3. Decode Digests
    let digests_tlv = unmarshal_first_tlv(cursor)?;
    let digests = unmarshal_digests(&digests_tlv)?;
    // 4. Decode Content
    let content = unmarshal_first_tlv(cursor)?;
    Ok(Record {
        rec_num,
        index_type,
        index,
        digests,
        content,
    })
}
/// Decodes a full byte buffer into a CEL struct.
pub fn decode_to_cel(buf: &[u8]) -> io::Result<Cel> {
    let mut cursor = Cursor::new(buf);
    let mut records = Vec::new();
    while (cursor.position() as usize) < buf.len() {
        match decode_to_celr(&mut cursor) {
            Ok(record) => records.push(record),
            Err(e) => {
                // If we hit EOF in the middle of a record, it's an error.
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "buffer ends unexpectedly in the middle of a record",
                    ));
                }
                return Err(e);
            }
        }
    }
    Ok(Cel { records })
}
