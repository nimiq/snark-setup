//! # setup-utils
//!
//! Utilities for building MPC Ceremonies for large SNARKs.
//! Provides traits for batched writing and reading group elements to buffers.
pub mod errors;
pub use errors::{Error, InvariantKind, Phase2Error, VerificationError};

/// A convenience result type for returning errors
pub type Result<T> = std::result::Result<T, Error>;

mod groth16_utils;
pub use groth16_utils::{domain_size, Groth16Params};

mod elements;
pub use elements::{
    check_subgroup,
    deserialize,
    read_vec,
    serialize,
    BatchExpMode,
    CheckForCorrectness,
    ElementType,
    SubgroupCheckMode,
    UseCompression,
};

mod helpers;
pub use helpers::*;

mod io;
pub use io::{buffer_size, write_to_file, BatchDeserializer, BatchSerializer, Deserializer, Serializer};

pub mod rayon_cfg;

mod seed;
pub use seed::derive_rng_from_seed;

// Re-exports for handling hashes
pub use blake2::digest::generic_array::GenericArray;
pub use typenum::U64;

pub use ark_std::{cfg_chunks, cfg_into_iter, cfg_iter_mut};
pub mod converters;
