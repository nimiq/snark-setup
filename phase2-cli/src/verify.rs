use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, write_to_file, CheckForCorrectness, SubgroupCheckMode};

use ark_ec::pairing::Pairing;

use crate::{COMBINED_IS_COMPRESSED, COMPRESS_CONTRIBUTE_INPUT, COMPRESS_CONTRIBUTE_OUTPUT};
use memmap::MmapOptions;
use std::{fs::OpenOptions, io::Write, ops::Neg};
use tracing::info;

pub fn verify<P: Pairing + Sync>(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    check_input_correctness: CheckForCorrectness,
    response_filename: &str,
    response_hash_filename: &str,
    check_output_correctness: CheckForCorrectness,
    new_challenge_filename: &str,
    new_challenge_hash_filename: &str,
    subgroup_check_mode: SubgroupCheckMode,
    verifying_full_contribution: bool,
) where
    P::G1Affine: Neg<Output = P::G1Affine>,
{
    info!("Verifying phase 2");

    let challenge_contents = std::fs::read(challenge_filename).expect("should have read challenge");
    let challenge_hash = calculate_hash(&challenge_contents);
    write_to_file(challenge_hash_filename, &challenge_hash);

    info!("`challenge` file contains decompressed points and has a hash:");
    print_hash(&challenge_hash);

    let parameters_before = MPCParameters::<P>::read_fast(
        challenge_contents.as_slice(),
        COMPRESS_CONTRIBUTE_INPUT,
        check_input_correctness,
        true,
        subgroup_check_mode,
    )
    .expect("should have read parameters");

    let response_contents = std::fs::read(response_filename).expect("should have read response");
    let response_hash = calculate_hash(&response_contents);
    write_to_file(response_hash_filename, &response_hash);

    info!("`response` file contains decompressed points and has a hash:");
    print_hash(&response_hash);

    let after_compressed = if verifying_full_contribution {
        COMBINED_IS_COMPRESSED
    } else {
        COMPRESS_CONTRIBUTE_OUTPUT
    };
    let parameters_after = MPCParameters::<P>::read_fast(
        response_contents.as_slice(),
        after_compressed,
        check_output_correctness,
        true,
        subgroup_check_mode,
    )
    .expect("should have read parameters");

    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(new_challenge_filename)
        .expect("unable to create new challenge file in this directory");
    parameters_after
        .write(writer, COMPRESS_CONTRIBUTE_INPUT)
        .expect("unable to write new challenge file");

    // Read new challenge to create hash
    let new_challenge_reader = OpenOptions::new()
        .read(true)
        .open(new_challenge_filename)
        .expect("unable open challenge file in this directory");
    let new_challenge_readable_map = unsafe {
        MmapOptions::new()
            .map(&new_challenge_reader)
            .expect("unable to create a memory map for input")
    };

    let new_challenge_hash = calculate_hash(&new_challenge_readable_map);
    write_to_file(new_challenge_hash_filename, new_challenge_hash.as_slice());

    parameters_before
        .verify(&parameters_after)
        .expect("should have successfully verified");
    info!(
        "Done!\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    print_hash(&response_hash);
}
