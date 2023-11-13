use std::{fs::File, marker::PhantomData};

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, ProvingKey};
use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use ark_relations::r1cs::{ConstraintSynthesizer, Field};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::UniformRand;
use gumdrop::Options;
use phase2::helpers::testing::{TestCircuit, TestHashCircuit};
use rand::{rngs::OsRng, thread_rng, RngCore};
use setup_utils::converters::{curve_from_str, CurveKind};
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
    #[options(help = "use more complex circuit")]
    pub complex: bool,
    #[options(help = "proving key file")]
    pub proving_key_path: String,
}

fn create_circuit<E: Pairing>(opts: CircuitOpts) {
    if opts.complex {
        let mut x = vec![0u8; 32];
        let mut rng = thread_rng();
        rng.fill_bytes(&mut x);
        let circuit = TestHashCircuit::<E>(x, PhantomData);
        let inputs = circuit.public_inputs();
        test_circuit::<E, _>(opts, circuit, &inputs);
    } else {
        let circuit = TestCircuit::<E>(Some(E::ScalarField::rand(&mut thread_rng())));
        let input = circuit.0.unwrap().square();
        test_circuit::<E, _>(opts, circuit, &[input]);
    }
}

fn test_circuit<E: Pairing, C: ConstraintSynthesizer<E::ScalarField> + Clone>(
    opts: CircuitOpts,
    circuit: C,
    public_inputs: &[E::ScalarField],
) {
    let mut rng = OsRng::default();

    let f = File::open(&opts.proving_key_path).expect("Could not read proving key file");
    let pk = ProvingKey::<E>::deserialize_compressed(&f).expect("Could not deserialize proving key");

    info!("Proving circuit");
    let proof = Groth16::<E>::prove(&pk, circuit.clone(), &mut rng).unwrap();

    info!("Verifying circuit");
    assert!(
        Groth16::<E>::verify_proof(&pk.vk.into(), &proof, public_inputs).unwrap(),
        "Could not verify proof"
    );

    info!("Successfully verified proof");
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
