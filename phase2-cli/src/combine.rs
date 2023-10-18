use phase2::parameters::{verify_transcript, MPCParameters};
use setup_utils::{print_hash, CheckForCorrectness, SubgroupCheckMode, UseCompression};

use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;

use std::{
    fs::File,
    io::{BufRead, BufReader},
    ops::Neg,
};
use tracing::info;

use crate::{COMBINED_IS_COMPRESSED, COMPRESS_CONTRIBUTE_INPUT, COMPRESS_CONTRIBUTE_OUTPUT};

pub fn combine<P: Pairing + Sync>(
    initial_query_filename: &str,
    initial_full_filename: &str,
    response_list_filename: &str,
    combined_filename: &str,
    combine_initial: bool,
) where
    P::G1Affine: Neg<Output = P::G1Affine>,
{
    info!("Combining phase 2");

    let response_list_reader =
        BufReader::new(File::open(response_list_filename).expect("should have opened the response list"));

    let full_contents = std::fs::read(initial_full_filename).expect("should have initial full parameters");
    let full_parameters = MPCParameters::<P>::read_fast(
        full_contents.as_slice(),
        UseCompression::No,
        CheckForCorrectness::No,
        false,
        SubgroupCheckMode::Auto,
    )
    .expect("should have read full parameters");

    let mut query_contents =
        std::io::Cursor::new(std::fs::read(initial_query_filename).expect("should have read initial query"));
    let query_parameters = MPCParameters::<P>::read_groth16_fast(
        &mut query_contents,
        UseCompression::No,
        CheckForCorrectness::No,
        false,
        SubgroupCheckMode::Auto,
    )
    .expect("should have deserialized initial query params");

    let parameters_compressed = if combine_initial {
        COMPRESS_CONTRIBUTE_INPUT
    } else {
        COMPRESS_CONTRIBUTE_OUTPUT
    };
    let mut all_parameters = vec![];
    for line in response_list_reader.lines() {
        let line = line.expect("should have read line");
        let contents = std::fs::read(line).expect("should have read response");
        let parameters = MPCParameters::<P>::read_fast(
            contents.as_slice(),
            parameters_compressed,
            CheckForCorrectness::No,
            false,
            SubgroupCheckMode::Auto,
        )
        .expect("should have read parameters");
        all_parameters.push(parameters);
    }

    let combined =
        MPCParameters::<P>::combine(&query_parameters, &all_parameters).expect("should have combined parameters");

    let contributions_hash = if combine_initial {
        verify_transcript(full_parameters.cs_hash, &combined.contributions).expect("should have verified successfully")
    } else {
        full_parameters
            .verify(&combined)
            .expect("should have verified successfully")
    };

    info!("Contributions hashes:");
    for contribution_hash in contributions_hash {
        print_hash(&contribution_hash[..]);
    }

    let mut combined_contents = vec![];
    combined
        .write(&mut combined_contents, COMBINED_IS_COMPRESSED)
        .expect("should have written combined");
    std::fs::write(combined_filename, &combined_contents).expect("should have written combined file");

    let mut combined_parameters_contents = vec![];
    combined
        .params
        .serialize_uncompressed(&mut combined_parameters_contents)
        .expect("should have serialized combined parameters");
    std::fs::write(format!("{}.params", combined_filename), &combined_parameters_contents)
        .expect("should have written combined parameters file");
}
