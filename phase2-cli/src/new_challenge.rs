use phase2::{load_circuit::Matrices, parameters::MPCParameters};
use setup_utils::{calculate_hash, print_hash, write_to_file, CheckForCorrectness, UseCompression};

use crate::COMPRESS_CONTRIBUTE_INPUT;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use memmap::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    ops::Neg,
};
use tracing::info;

pub fn new_challenge<P: Pairing + Sync>(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    challenge_list_filename: &str,
    chunk_size: usize,
    phase1_filename: &str,
    phase1_powers: usize,
    circuit_filename: &str,
) -> usize
where
    P::G1Affine: Neg<Output = P::G1Affine>,
{
    info!("Generating phase 2");

    let mut file = File::open(circuit_filename).unwrap();
    let mut buffer = Vec::<u8>::new();
    file.read_to_end(&mut buffer).unwrap();
    let m = Matrices::<P>::deserialize_compressed(&*buffer).unwrap();

    info!("Loaded circuit with {} constraints", m.num_constraints);

    let phase2_size =
        std::cmp::max(m.num_constraints, m.num_witness_variables + m.num_instance_variables).next_power_of_two();
    let chunk_size = std::cmp::min(chunk_size, phase2_size);

    let reader = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&phase1_filename)
        .expect("unable open phase 1 file in this directory");
    let mut phase1_readable_map = unsafe {
        MmapOptions::new()
            .map_mut(&reader)
            .expect("unable to create a memory map for input")
    };

    let (full_mpc_parameters, query_parameters, all_mpc_parameters) = MPCParameters::<P>::new_from_buffer_chunked(
        m,
        &mut phase1_readable_map,
        UseCompression::No,
        CheckForCorrectness::No,
        1 << phase1_powers,
        phase2_size,
        chunk_size,
    )
    .unwrap();

    let mut serialized_mpc_parameters = vec![];
    full_mpc_parameters
        .write(&mut serialized_mpc_parameters, COMPRESS_CONTRIBUTE_INPUT)
        .unwrap();

    let mut serialized_query_parameters = vec![];
    query_parameters
        .serialize_with_mode(&mut serialized_query_parameters, COMPRESS_CONTRIBUTE_INPUT)
        .unwrap();

    let contribution_hash = {
        write_to_file(format!("{}.full", challenge_filename), &serialized_mpc_parameters);
        // Get the hash of the contribution, so the user can compare later
        calculate_hash(&serialized_mpc_parameters)
    };

    write_to_file(format!("{}.query", challenge_filename), &serialized_query_parameters);

    let mut challenge_list_file =
        std::fs::File::create(challenge_list_filename).expect("unable to open new challenge list file");

    for (i, chunk) in all_mpc_parameters.iter().enumerate() {
        let mut serialized_chunk = vec![];
        chunk
            .write(&mut serialized_chunk, COMPRESS_CONTRIBUTE_INPUT)
            .expect("unable to write chunk");
        write_to_file(format!("{}.{}", challenge_filename, i), &serialized_chunk);
        challenge_list_file
            .write(format!("{}.{}\n", challenge_filename, i).as_bytes())
            .expect("unable to write challenge list");
    }

    write_to_file(challenge_hash_filename, contribution_hash.as_slice());

    info!("Empty contribution is formed with a hash:");
    print_hash(&contribution_hash);
    info!("Wrote a fresh accumulator to challenge file");
    all_mpc_parameters.len()
}
