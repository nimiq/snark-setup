use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use gumdrop::Options;
use phase2::{helpers::testing::TestCircuit, load_circuit::Matrices, parameters::circuit_to_qap};
use rand::thread_rng;
use setup_utils::{
    converters::{curve_from_str, CurveKind},
    write_to_file,
};
use tracing::{info, Level};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

#[derive(Debug, Options, Clone)]
struct CircuitOpts {
    #[options(
        help = "the elliptic curve to use",
        default = "bls12_377",
        parse(try_from_str = "curve_from_str")
    )]
    pub curve_kind: CurveKind,
}

fn create_circuit<E: Pairing>(opts: CircuitOpts) {
    let circuit = TestCircuit::<E>(Some(E::ScalarField::rand(&mut thread_rng())));

    let cs = circuit_to_qap::<E, _>(circuit).expect("Could not prepare circuit for QAP");

    let matrices = cs.to_matrices().expect("Could not generate matrices");
    let matrices = Matrices::<E>::from(matrices);

    let mut serialized_matrices = Vec::with_capacity(matrices.uncompressed_size());
    matrices
        .serialize_uncompressed(&mut serialized_matrices)
        .expect("Could not serialize matrices");
    let filename = format!("testcircuit_{}", opts.curve_kind);
    write_to_file(&filename, &serialized_matrices);
    info!("Successfully created circuit at `{}`", filename);
}

fn main() {
    Subscriber::builder()
        .with_target(false)
        .with_timer(ChronoUtc::rfc3339())
        .with_max_level(Level::INFO)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: CircuitOpts = CircuitOpts::parse_args_default_or_exit();

    info!("Creating circuit for {} curve", opts.curve_kind);
    match opts.curve_kind {
        CurveKind::Bls12_377 => create_circuit::<Bls12_377>(opts),
        CurveKind::BW6 => create_circuit::<BW6_761>(opts),
        CurveKind::MNT4_753 => create_circuit::<MNT4_753>(opts),
        CurveKind::MNT6_753 => create_circuit::<MNT6_753>(opts),
    };
}
