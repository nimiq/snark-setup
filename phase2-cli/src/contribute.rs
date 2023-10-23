use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, write_to_file, BatchExpMode, CheckForCorrectness, SubgroupCheckMode};

use ark_ec::pairing::Pairing;

use crate::{COMPRESS_CONTRIBUTE_INPUT, COMPRESS_CONTRIBUTE_OUTPUT};
use rand::Rng;
use std::{io::Write, ops::Neg};
use tracing::info;

pub fn contribute<P: Pairing + Sync>(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    response_filename: &str,
    response_hash_filename: &str,
    check_input_correctness: CheckForCorrectness,
    batch_exp_mode: BatchExpMode,
    mut rng: impl Rng,
) where
    P::G1Affine: Neg<Output = P::G1Affine>,
{
    info!("Contributing to phase 2");

    let challenge_contents = std::fs::read(challenge_filename).expect("should have read challenge");
    let challenge_hash = calculate_hash(&challenge_contents);
    write_to_file(challenge_hash_filename, &challenge_hash);

    info!("`challenge` file contains decompressed points and has a hash:");
    print_hash(&challenge_hash);

    let mut parameters = MPCParameters::<P>::read_fast(
        challenge_contents.as_slice(),
        COMPRESS_CONTRIBUTE_INPUT,
        check_input_correctness,
        false,
        SubgroupCheckMode::Auto,
    )
    .expect("should have read parameters");
    parameters
        .contribute(batch_exp_mode, &mut rng)
        .expect("should have successfully contributed");
    let mut serialized_response = vec![];
    parameters
        .write(&mut serialized_response, COMPRESS_CONTRIBUTE_OUTPUT)
        .expect("should have written input");
    write_to_file(response_filename, &serialized_response);
    let response_hash = calculate_hash(&serialized_response);
    write_to_file(response_hash_filename, &response_hash);
    info!(
        "Done!\n\n\
              Your contribution has been written to response file\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    print_hash(&response_hash);
}
