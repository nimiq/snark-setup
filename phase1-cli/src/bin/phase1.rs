use phase1::{CurveParameters, Phase1Parameters};
use phase1_cli::{
    combine,
    contribute,
    new_challenge,
    split,
    transform_pok_and_correctness,
    transform_ratios,
    Command,
    Phase1Opts,
};
use setup_utils::{
    converters::CurveKind,
    derive_rng_from_seed,
    from_slice,
    upgrade_correctness_check_config,
    BatchGroupArithmetic,
    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
};

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing as Engine;

use gumdrop::Options;
use std::{fs::read_to_string, process, time::Instant};
use tracing::{error, info};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

fn execute_cmd<E: Engine>(opts: Phase1Opts)
where
    E::G1Affine: BatchGroupArithmetic,
    E::G2Affine: BatchGroupArithmetic,
{
    let curve = CurveParameters::<E>::new();
    let parameters = Phase1Parameters::<E>::new(
        opts.contribution_mode,
        opts.chunk_index,
        opts.chunk_size,
        curve,
        opts.proving_system,
        opts.power,
        opts.batch_size,
    );

    let command = opts.clone().command.unwrap_or_else(|| {
        error!("No command was provided.");
        error!("{}", Phase1Opts::usage());
        process::exit(2)
    });

    let now = Instant::now();

    match command {
        Command::New(opt) => {
            new_challenge(&opt.challenge_fname, &opt.challenge_hash_fname, &parameters);
        }
        Command::Contribute(opt) => {
            // contribute to the randomness
            let seed = hex::decode(&read_to_string(&opts.seed).expect("should have read seed").trim())
                .expect("seed should be a hex string");
            let rng = derive_rng_from_seed(&seed);
            contribute(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                &opt.response_fname,
                &opt.response_hash_fname,
                upgrade_correctness_check_config(
                    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
                    opts.force_correctness_checks,
                ),
                opts.batch_exp_mode,
                &parameters,
                rng,
            );
        }
        Command::Beacon(opt) => {
            // use the beacon's randomness
            // Place block hash here (block number #564321)
            let beacon_hash = hex::decode(&opt.beacon_hash).expect("could not hex decode beacon hash");
            let rng = derive_rng_from_seed(&from_slice(&beacon_hash));
            contribute(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                &opt.response_fname,
                &opt.response_hash_fname,
                upgrade_correctness_check_config(
                    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
                    opts.force_correctness_checks,
                ),
                opts.batch_exp_mode,
                &parameters,
                rng,
            );
        }
        Command::VerifyAndTransformPokAndCorrectness(opt) => {
            // we receive a previous participation, verify it, and generate a new challenge from it
            transform_pok_and_correctness(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                upgrade_correctness_check_config(DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS, opts.force_correctness_checks),
                &opt.response_fname,
                &opt.response_hash_fname,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                    opts.force_correctness_checks,
                ),
                &opt.new_challenge_fname,
                &opt.new_challenge_hash_fname,
                opts.subgroup_check_mode,
                !opts.skip_ratio_check,
                &parameters,
            );
        }
        Command::VerifyAndTransformRatios(opt) => {
            // we receive a previous participation, verify it, and generate a new challenge from it
            transform_ratios(
                &opt.response_fname,
                upgrade_correctness_check_config(DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS, opts.force_correctness_checks),
                &parameters,
            );
        }
        Command::Combine(opt) => {
            combine(&opt.response_list_fname, &opt.combined_fname, &parameters);
        }
        Command::Split(opt) => {
            split(&opt.chunk_fname_prefix, &opt.full_fname, &parameters);
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

    let opts: Phase1Opts = Phase1Opts::parse_args_default_or_exit();

    match opts.curve_kind {
        CurveKind::Bls12_377 => execute_cmd::<Bls12_377>(opts),
        CurveKind::BW6 => execute_cmd::<BW6_761>(opts),
    };
}
