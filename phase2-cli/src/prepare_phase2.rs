use phase1::{parameters::*, Phase1};
use setup_utils::{CheckForCorrectness, Groth16Params, Result, UseCompression};
use std::ops::Neg;

use ark_ec::pairing::Pairing as Engine;

use memmap::*;
use std::fs::OpenOptions;

const INPUT_IS_COMPRESSED: UseCompression = UseCompression::No;
const OUTPUT_IS_COMPRESSED: UseCompression = UseCompression::No;

/// `phase2_size` should equal to the number of constraints + instance variables of the original circuit.
/// Since our matrices have additional constraints for each instance variables,
/// this usually corresponds to the number of constraints in these.
pub fn prepare_phase2<T: Engine + Sync>(
    phase2_filename: &str,
    response_filename: &str,
    phase2_size: usize,
    parameters: &Phase1Parameters<T>,
    check_correctness: CheckForCorrectness,
) -> Result<()>
where
    T::G1Affine: Neg<Output = T::G1Affine>,
{
    // Try to load response file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(response_filename)
        .expect("unable open response file in this directory");
    let response_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    // Create the parameter file
    let mut writer = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(phase2_filename)
        .expect("unable to create parameter file in this directory");

    // Deserialize the accumulator
    let current_accumulator = Phase1::deserialize(
        &response_readable_map,
        INPUT_IS_COMPRESSED,
        check_correctness,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator");

    // Load the elements to the Groth16 utility
    let groth16_params = Groth16Params::<T>::new(
        phase2_size,
        current_accumulator.tau_powers_g1,
        current_accumulator.tau_powers_g2,
        current_accumulator.alpha_tau_powers_g1,
        current_accumulator.beta_tau_powers_g1,
        current_accumulator.beta_g2,
    )
    .expect("could not create Groth16 Lagrange coefficients");

    // Write the parameters
    groth16_params.write(&mut writer, OUTPUT_IS_COMPRESSED)?;

    Ok(())
}
