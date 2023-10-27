use crate::{BatchDeserializer, Error};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Validate, Write};
use ark_std::{cfg_iter, Zero};

#[cfg(not(feature = "wasm"))]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tracing::error;

use std::fmt;

/// Determines if point compression should be used.
pub type UseCompression = Compress;

/// Determines if points should be checked to be infinity.
#[derive(Copy, Clone, PartialEq)]
pub enum CheckForCorrectness {
    Full,
    OnlyNonZero,
    OnlyInGroup,
    No,
}

impl fmt::Display for CheckForCorrectness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CheckForCorrectness::Full => write!(f, "Full"),
            CheckForCorrectness::OnlyNonZero => write!(f, "OnlyNonZero"),
            CheckForCorrectness::OnlyInGroup => write!(f, "OnlyInGroup"),
            CheckForCorrectness::No => write!(f, "No"),
        }
    }
}

impl From<CheckForCorrectness> for Validate {
    fn from(value: CheckForCorrectness) -> Self {
        match value {
            CheckForCorrectness::OnlyNonZero | CheckForCorrectness::No => Validate::No,
            CheckForCorrectness::OnlyInGroup | CheckForCorrectness::Full => Validate::Yes,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ElementType {
    TauG1,
    TauG2,
    AlphaG1,
    BetaG1,
    BetaG2,
}

impl fmt::Display for ElementType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ElementType::TauG1 => write!(f, "TauG1"),
            ElementType::TauG2 => write!(f, "TauG2"),
            ElementType::AlphaG1 => write!(f, "AlphaG1"),
            ElementType::BetaG1 => write!(f, "BetaG1"),
            ElementType::BetaG2 => write!(f, "BetaG2"),
        }
    }
}

/// Determines which batch exponentiation algorithm to use
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BatchExpMode {
    Auto,
    Direct,
    BatchInversion,
}

impl fmt::Display for BatchExpMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BatchExpMode::Auto => write!(f, "Auto"),
            BatchExpMode::Direct => write!(f, "Direct"),
            BatchExpMode::BatchInversion => write!(f, "Batch inversion"),
        }
    }
}

/// Determines which batch exponentiation algorithm to use
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SubgroupCheckMode {
    Auto,
    Direct,
    Batched,
    No,
}

impl fmt::Display for SubgroupCheckMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SubgroupCheckMode::Auto => write!(f, "Auto"),
            SubgroupCheckMode::Direct => write!(f, "Direct"),
            SubgroupCheckMode::Batched => write!(f, "Batched"),
            SubgroupCheckMode::No => write!(f, "No"),
        }
    }
}

pub fn deserialize<T: CanonicalDeserialize, R: Read>(
    reader: R,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
) -> core::result::Result<T, SerializationError> {
    if !matches!(check_correctness, CheckForCorrectness::Full | CheckForCorrectness::No) {
        return Err(SerializationError::InvalidData);
    }
    CanonicalDeserialize::deserialize_with_mode(reader, compressed, check_correctness.into())
}

pub fn serialize<T: CanonicalSerialize, W: Write>(
    element: &T,
    writer: W,
    compressed: UseCompression,
) -> core::result::Result<(), SerializationError> {
    CanonicalSerialize::serialize_with_mode(element, writer, compressed)
}

pub fn check_subgroup<C: AffineRepr>(
    elements: &[C],
    subgroup_check_mode: SubgroupCheckMode,
) -> core::result::Result<(), Error> {
    // const SECURITY_PARAM: usize = 128;
    const BATCH_SIZE: usize = 1 << 12;
    let prime_order_subgroup_check_pass = match (elements.len() > BATCH_SIZE, subgroup_check_mode) {
        (_, SubgroupCheckMode::No) => true,
        (true, SubgroupCheckMode::Auto) | (_, SubgroupCheckMode::Batched) => {
            // match batch_verify_in_subgroup(elements, SECURITY_PARAM, &mut rand::thread_rng()) {
            //     Ok(()) => true,
            //     _ => false,
            // }
            // PITODO
            error!("Batched mode is currently disabled");
            cfg_iter!(elements).all(|p| p.mul_bigint(<C::ScalarField as PrimeField>::MODULUS).is_zero())
        }
        (false, SubgroupCheckMode::Auto) | (_, SubgroupCheckMode::Direct) => {
            // PITODO: double-check
            cfg_iter!(elements).all(|p| p.mul_bigint(<C::ScalarField as PrimeField>::MODULUS).is_zero())
        }
    };
    if !prime_order_subgroup_check_pass {
        return Err(Error::IncorrectSubgroup);
    }

    Ok(())
}

pub fn read_vec<G: AffineRepr, R: Read>(
    mut reader: R,
    compressed: UseCompression,
    check_for_correctness: CheckForCorrectness,
) -> Result<Vec<G>, Error> {
    let size = G::default().serialized_size(compressed);
    let length = u64::deserialize_uncompressed(&mut reader)? as usize;
    let mut bytes = vec![0u8; length * size];
    reader.read_exact(&mut bytes)?;
    bytes.read_batch(compressed, check_for_correctness)
}
