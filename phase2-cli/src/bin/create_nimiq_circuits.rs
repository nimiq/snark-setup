use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use nimiq_zkp_circuits::circuits::{
    mnt4::{MacroBlockWrapperCircuit, MergerWrapperCircuit, PKTreeNodeCircuit as MNT4PKTreeNodeCircuit},
    mnt6::{MacroBlockCircuit, MergerCircuit, PKTreeLeafCircuit, PKTreeNodeCircuit as MNT6PKTreeNodeCircuit},
};
use phase2::{load_circuit::Matrices, parameters::circuit_to_qap};
use rand::thread_rng;
use setup_utils::write_to_file;
use tracing::{info, Level};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

fn create_circuit<E: Pairing, C: ConstraintSynthesizer<E::ScalarField> + Clone>(circuit: C, filename: &str) {
    // Test circuit first
    let cs = ConstraintSystem::new_ref();
    // Synthesize the circuit.
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .expect("constraint generation should not fail");
    assert!(cs.is_satisfied().unwrap());

    let cs = circuit_to_qap::<E, _>(circuit).expect("Could not prepare circuit for QAP");

    let matrices = cs.to_matrices().expect("Could not generate matrices");
    let matrices = Matrices::<E>::from(matrices);

    let mut serialized_matrices = Vec::with_capacity(matrices.uncompressed_size());
    matrices
        .serialize_uncompressed(&mut serialized_matrices)
        .expect("Could not serialize matrices");
    write_to_file(&filename, &serialized_matrices);
    info!("Successfully created circuit at `{}`", filename);
}

fn create_circuits() {
    let rng = &mut thread_rng();
    // create_circuit::<MNT6_753, _>(MergerWrapperCircuit::rand(rng), "merger_wrapper");
    // create_circuit::<MNT4_753, _>(MergerCircuit::rand(rng), "merger");
    // create_circuit::<MNT6_753, _>(MacroBlockWrapperCircuit::rand(rng), "macro_block_wrapper");
    // create_circuit::<MNT4_753, _>(MacroBlockCircuit::rand(rng), "macro_block");
    // for tree_level in 0..5 {
    //     let filename = format!("pk_tree_{}", tree_level);
    //     if tree_level % 2 == 0 {
    //         create_circuit::<MNT6_753, _>(MNT4PKTreeNodeCircuit::rand(tree_level, rng), &filename);
    //     } else {
    //         create_circuit::<MNT4_753, _>(MNT6PKTreeNodeCircuit::rand(tree_level, rng), &filename);
    //     }
    // }
    create_circuit::<MNT4_753, _>(PKTreeLeafCircuit::rand(rng), "pk_tree_5");
}

fn main() {
    Subscriber::builder()
        .with_target(false)
        .with_timer(ChronoUtc::rfc3339())
        .with_max_level(Level::INFO)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("Creating circuits");
    create_circuits();
}
