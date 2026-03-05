use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver};
use anyhow::anyhow;
use wasm_bindgen::prelude::wasm_bindgen;


/// Initialize the prover by loading a decompressed circuit file.
///
/// @param {Uint8Array} circuit - The decompressed circuit file.
/// @param {CircuitVersion} circuit_version - The version of the mdoc_zk circuit interface.
/// @param {number} num_attributes - The number of attributes to be disclosed in the presentation.
/// @returns {MdocZkProver}
#[uniffi::export]
pub fn initialize_prover(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: u16,
) -> Result<MdocZkProver, MdocZkError> {
    let num_attributes = usize::try_from(num_attributes).map_err(|_| anyhow!("couldnt convert from u16 to usize"))?;
    MdocZkProver::new(circuit, circuit_version, num_attributes).map_err(convert_error)
}

/// Create a proof for a credential presentation.
///
/// @param {MdocZkProver} prover - The prover returned from `initialize()`.
/// @param {Uint8Array} device_response - The mdoc's DeviceResponse, as CBOR data.
/// @param {string} namespace -  The namespace of the claims.
/// @param {string[]} requested_claims - The identifiers of the claims to be disclosed.
/// @param {Uint8Array} session_transcript - The `SessionTranscript`, as CBOR data.
/// @param {string} time - The current time. This must be in RFC 3339 format, in UTC, with no time zone offset.
/// @returns {Uint8Array} The serialized proof.
#[uniffi::export]
// We have to use `Box<[String]>` because wasm-bindgen does not support `&[String]` arguments.
#[allow(clippy::boxed_local)]
pub fn prove(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: &[String],
    session_transcript: &[u8],
    time: &str,
) -> Result<Vec<u8>, MdocZkError> {
    let requested_claims = requested_claims
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    prover
        .prove(
            device_response,
            namespace,
            &requested_claims,
            session_transcript,
            time,
        )
        .map_err(convert_error)
}

#[derive(Debug,  thiserror::Error, uniffi::Object)]
#[error("{e:?}")] // default message is from anyhow.
pub struct MdocZkError {
    e: anyhow::Error,
}

#[uniffi::export]
impl MdocZkError {
    fn message(&self) -> String { self.e.to_string() }
}

impl From<anyhow::Error> for MdocZkError {
    fn from(e: anyhow::Error) -> Self {
        Self { e }
    }
}


fn convert_error(error: anyhow::Error) -> MdocZkError {
    let message = format!("{error:#}");
    error.into()
}
