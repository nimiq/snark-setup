use ark_mnt4_753::MNT4_753;
use ark_mnt6_753::MNT6_753;
use setup_utils::converters::CurveKind;

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing as Engine;

use gumdrop::Options;
use phase2_cli::{combine, contribute, new_challenge, verify, Command, Phase2Opts};
use setup_utils::{
    derive_rng_from_seed,
    upgrade_correctness_check_config,
    CheckForCorrectness,
    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
};
use std::{fs::read_to_string, ops::Neg, process, time::Instant};
use tracing::{error, info};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

fn execute_cmd<E: Engine>(opts: Phase2Opts)
where
    E::G1Affine: Neg<Output = E::G1Affine>,
{
    let command = opts.clone().command.unwrap_or_else(|| {
        error!("No command was provided.");
        error!("{}", Phase2Opts::usage());
        process::exit(2)
    });

    let now = Instant::now();

    match command {
        Command::New(opt) => {
            new_challenge::<E>(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                &opt.challenge_list_fname,
                opts.chunk_size,
                &opt.phase1_fname,
                opt.phase1_powers,
                &opt.circuit_fname,
            );
        }
        Command::Contribute(opt) => {
            let seed = hex::decode(&read_to_string(&opts.seed).expect("should have read seed").trim())
                .expect("seed should be a hex string");
            let rng = derive_rng_from_seed(&seed);
            contribute::<E>(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                &opt.response_fname,
                &opt.response_hash_fname,
                upgrade_correctness_check_config(
                    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
                    opts.force_correctness_checks,
                ),
                opts.batch_exp_mode,
                rng,
            );
        }
        Command::Verify(opt) => {
            verify::<E>(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                &opt.response_fname,
                &opt.response_hash_fname,
                CheckForCorrectness::OnlyNonZero,
                &opt.new_challenge_fname,
                &opt.new_challenge_hash_fname,
                opts.subgroup_check_mode,
                false,
            );
        }
        Command::Combine(opt) => {
            combine::<E>(
                &opt.initial_query_fname,
                &opt.initial_full_fname,
                &opt.response_list_fname,
                &opt.combined_fname,
                false,
            );
        }
    };

    let new_now = Instant::now();
    info!("Executing {:?} took: {:?}", opts, new_now.duration_since(now));
}

fn main() {
    Subscriber::builder()
        .with_target(false)
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: Phase2Opts = Phase2Opts::parse_args_default_or_exit();

    match opts.curve_kind {
        CurveKind::Bls12_377 => execute_cmd::<Bls12_377>(opts),
        CurveKind::BW6 => execute_cmd::<BW6_761>(opts),
        CurveKind::MNT4_753 => execute_cmd::<MNT4_753>(opts),
        CurveKind::MNT6_753 => execute_cmd::<MNT6_753>(opts),
    };
}
