use tracing::error;

use super::*;

impl<'a, E: Pairing + Sync> Phase1<'a, E> {
    /// Verifies that the accumulator was transformed correctly
    /// given the `PublicKey` and the so-far hash of the accumulator.
    /// This verifies a single chunk and checks only that the points
    /// are not zero, that they're in the prime order subgroup.
    /// In the first chunk, it also checks the proofs of knowledge
    /// and that the elements were correctly multiplied.

    ///
    /// Phase 1 - Verification
    ///
    /// Verifies a transformation of the `Accumulator` with the `PublicKey`,
    /// given a 64-byte transcript `digest`.
    ///
    /// Verifies that the accumulator was transformed correctly
    /// given the `PublicKey` and the so-far hash of the accumulator.
    /// This verifies a single chunk and checks only that the points are not zero,
    /// that they're in the prime order subgroup. In the first chunk, it also checks
    /// the proofs of knowledge and that the elements were correctly multiplied.
    ///
    #[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
    pub fn verification(
        input: &[u8],
        output: &[u8],
        new_challenge: &mut [u8],
        key: &PublicKey<E>,
        digest: &[u8],
        compressed_input: UseCompression,
        compressed_output: UseCompression,
        compressed_new_challenge: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        check_output_for_correctness: CheckForCorrectness,
        subgroup_check_mode: SubgroupCheckMode,
        ratio_check: bool,
        parameters: &'a Phase1Parameters<E>,
    ) -> Result<()> {
        let span = info_span!("phase1-verification");
        let _ = span.enter();

        info!("starting...");

        // Split the output buffer into its components.
        let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split(output, parameters, compressed_output);
        let (
            new_challenge_tau_g1,
            new_challenge_tau_g2,
            new_challenge_alpha_g1,
            new_challenge_beta_g1,
            new_challenge_beta_g2,
        ) = split_mut(new_challenge, parameters, compressed_new_challenge);

        let (g1_check, g2_check, ratio_check) = {
            // Ensure that the initial conditions are correctly formed (first 2 elements)
            // We allocate a G1 vector of length 2 and re-use it for our G1 elements.
            // We keep the values of the tau_g1 / tau_g2 elements for later use.

            let after_g1 =
                read_initial_elements::<E::G1Affine>(tau_g1, compressed_output, check_output_for_correctness);

            // Current iteration of tau_g2[0].
            let after_g2 =
                read_initial_elements::<E::G2Affine>(tau_g2, compressed_output, check_output_for_correctness);

            match (after_g1, after_g2) {
                (Ok(after_g1), Ok(after_g2)) => {
                    let g1_check = (after_g1[0], after_g1[1]);
                    let g2_check = (after_g2[0], after_g2[1]);

                    (g1_check, g2_check, ratio_check)
                }
                _ => (
                    (E::G1Affine::zero(), E::G1Affine::zero()),
                    (E::G2Affine::zero(), E::G2Affine::zero()),
                    false,
                ),
            }
        };

        if parameters.contribution_mode == ContributionMode::Full || parameters.chunk_index == 0 {
            // Run proof of knowledge checks if contribution mode is on full, or this is the first chunk index.
            // Split the input buffer into its components.
            let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
                split(input, parameters, compressed_input);

            let [tau_g2_s, alpha_g2_s, beta_g2_s] = compute_g2_s_key(&key, &digest)?;

            // Compose into tuple form for convenience.
            let tau_single_g1_check = &(key.tau_g1.0, key.tau_g1.1);
            let tau_single_g2_check = &(tau_g2_s, key.tau_g2);
            // let alpha_single_g1_check = &(key.alpha_g1.0, key.alpha_g1.1);
            let alpha_single_g2_check = &(alpha_g2_s, key.alpha_g2);
            let beta_single_g1_check = &(key.beta_g1.0, key.beta_g1.1);
            let beta_single_g2_check = &(beta_g2_s, key.beta_g2);

            // Ensure the key ratios are correctly produced.
            {
                // Check the proofs of knowledge for tau, alpha, and beta.
                let check_ratios = &[
                    (&(key.tau_g1.0, key.tau_g1.1), &(tau_g2_s, key.tau_g2), "Tau G1<>G2"),
                    (
                        &(key.alpha_g1.0, key.alpha_g1.1),
                        &(alpha_g2_s, key.alpha_g2),
                        "Alpha G1<>G2",
                    ),
                    (
                        &(key.beta_g1.0, key.beta_g1.1),
                        &(beta_g2_s, key.beta_g2),
                        "Beta G1<>G2",
                    ),
                ];

                for (a, b, err) in check_ratios {
                    check_same_ratio::<E>(a, b, err.to_string())?;
                }
                debug!("key ratios were correctly produced");
            }

            // Ensure that the initial conditions are correctly formed (first 2 elements).
            // We allocate a G1 vector of length 2 and re-use it for our G1 elements.
            // We keep the values of the tau_g1 / tau_g2 elements for later use.

            // Check that tau^i was computed correctly in G1.
            let (mut before_g1, mut after_g1) = {
                // Previous iteration of tau_g1[0].
                let before_g1 =
                    read_initial_elements::<E::G1Affine>(in_tau_g1, compressed_input, check_input_for_correctness)?;
                // Current iteration of tau_g1[0].
                let after_g1 =
                    read_initial_elements::<E::G1Affine>(tau_g1, compressed_output, check_output_for_correctness)?;

                // Check tau_g1[0] is the prime subgroup generator.
                if after_g1[0] != E::G1Affine::generator() {
                    return Err(VerificationError::InvalidGenerator(ElementType::TauG1).into());
                }

                // Check that tau^1 was multiplied correctly.
                check_same_ratio::<E>(
                    &(before_g1[1], after_g1[1]),
                    tau_single_g2_check,
                    "Before-After: tau_g1".to_string(),
                )?;

                (before_g1, after_g1)
            };

            // Check that tau^i was computed correctly in G2.
            {
                // Previous iteration of tau_g2[0].
                let before_g2 =
                    read_initial_elements::<E::G2Affine>(in_tau_g2, compressed_input, check_input_for_correctness)?;
                // Current iteration of tau_g2[0].
                let after_g2 =
                    read_initial_elements::<E::G2Affine>(tau_g2, compressed_output, check_output_for_correctness)?;

                // Check tau_g2[0] is the prime subgroup generator.
                if after_g2[0] != E::G2Affine::generator() {
                    return Err(VerificationError::InvalidGenerator(ElementType::TauG2).into());
                }

                // Check that tau^1 was multiplied correctly.
                check_same_ratio::<E>(
                    tau_single_g1_check,
                    &(before_g2[1], after_g2[1]),
                    "Before-After: tau_g2".to_string(),
                )?;
            }

            // Check that alpha_g1[0] and beta_g1[0] were computed correctly.
            {
                // Determine the check based on the proof system's requirements.
                let checks = match parameters.proving_system {
                    ProvingSystem::Groth16 => vec![
                        (in_alpha_g1, alpha_g1, alpha_single_g2_check),
                        (in_beta_g1, beta_g1, beta_single_g2_check),
                    ],
                    ProvingSystem::Marlin => vec![(in_alpha_g1, alpha_g1, alpha_single_g2_check)],
                };

                // Check that alpha_g1[0] and beta_g1[0] was multiplied correctly.
                for (before, after, check) in &checks {
                    before.read_batch_preallocated(&mut before_g1, compressed_input, check_input_for_correctness)?;
                    after.read_batch_preallocated(&mut after_g1, compressed_output, check_output_for_correctness)?;
                    check_same_ratio::<E>(
                        &(before_g1[0], after_g1[0]),
                        check,
                        "Before-After: alpha_g1[0] / beta_g1[0]".to_string(),
                    )?;
                }
            }

            // Check that beta_g2[0] was computed correctly.
            {
                if parameters.proving_system == ProvingSystem::Groth16 {
                    // Read in the first beta_g2 element from the previous iteration and current iteration.
                    let before_beta_g2 =
                        (&*in_beta_g2).read_element::<E::G2Affine>(compressed_input, check_input_for_correctness)?;
                    let after_beta_g2 =
                        (&*beta_g2).read_element::<E::G2Affine>(compressed_output, check_output_for_correctness)?;
                    new_challenge_beta_g2.write_element(&after_beta_g2, compressed_new_challenge)?;

                    // Check that beta_g2[0] was multiplied correctly.
                    check_same_ratio::<E>(
                        beta_single_g1_check,
                        &(before_beta_g2, after_beta_g2),
                        "Before-After: beta_g2[0]".to_string(),
                    )?;
                }
            }
        };

        debug!("initial elements were computed correctly");

        iter_chunk(&parameters, |start, end| {
            // Preallocate 2 vectors per batch.
            // Ensure that the pairs are created correctly (we do this in chunks!).
            // Load `batch_size` chunks on each iteration and perform the transformation.

            debug!("verifying chunk from {} to {}", start, end);

            let span = info_span!("batch", start, end);
            let _enter = span.enter();

            // Determine the chunk start and end indices based on the contribution mode.
            let (start_chunk, end_chunk) = match parameters.contribution_mode {
                ContributionMode::Chunked => (
                    start - parameters.chunk_index * parameters.chunk_size, // start index
                    end - parameters.chunk_index * parameters.chunk_size,   // end index
                ),
                ContributionMode::Full => (start, end),
            };

            // If there's only one element, ratio check will fail, so return an error
            if ratio_check && end <= start + 1 {
                return Err(Error::BatchTooSmall);
            }

            match parameters.proving_system {
                ProvingSystem::Groth16 => {
                    rayon::scope(|t| {
                        let _enter = span.enter();

                        // Process tau_g1 elements.
                        t.spawn(|_| {
                            let _enter = span.enter();

                            let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                            check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G1Affine>(
                                (tau_g1, compressed_output),
                                (start_chunk, end_chunk),
                                &mut g1,
                                subgroup_check_mode,
                            )
                            .expect("could not check element are non zero and in prime order subgroup (tau g1)");

                            if ratio_check {
                                check_power_ratios::<E>(
                                    (tau_g1, compressed_output, CheckForCorrectness::No),
                                    (start_chunk, end_chunk),
                                    &mut g1,
                                    &g2_check,
                                    "tau g1",
                                )
                                .expect("could not check element ratios (tau g1)");
                            }

                            let size = buffer_size::<E::G1Affine>(compressed_new_challenge);
                            new_challenge_tau_g1[start_chunk * size..end_chunk * size]
                                .write_batch(&mut g1[0..end_chunk - start_chunk], compressed_new_challenge)
                                .expect("Should have written tau_g1 to new challenge");

                            trace!("tau_g1 verification was successful");
                        });

                        if start < parameters.powers_length {
                            // If the `end` would be out of bounds, then just process until
                            // the end (this is necessary in case the last batch would try to
                            // process more elements than available).
                            let max = match parameters.contribution_mode {
                                ContributionMode::Chunked => std::cmp::min(
                                    (parameters.chunk_index + 1) * parameters.chunk_size,
                                    parameters.powers_length,
                                ),
                                ContributionMode::Full => parameters.powers_length,
                            };
                            let end = if start + parameters.batch_size > max { max } else { end };

                            // Determine the chunk start and end indices based on the contribution mode.
                            let (start_chunk, end_chunk) = match parameters.contribution_mode {
                                ContributionMode::Chunked => (
                                    start - parameters.chunk_index * parameters.chunk_size, // start index
                                    end - parameters.chunk_index * parameters.chunk_size,   // end index
                                ),
                                ContributionMode::Full => (start, end),
                            };

                            if end > start + 1 {
                                rayon::scope(|t| {
                                    let _enter = span.enter();

                                    // Process tau_g2 elements.
                                    t.spawn(|_| {
                                        let _enter = span.enter();

                                        let mut g2 = vec![E::G2Affine::zero(); parameters.batch_size];

                                        check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G2Affine>(
                                        (tau_g2, compressed_output),
                                        (start_chunk, end_chunk),
                                        &mut g2,
                                        subgroup_check_mode,
                                    )
                                    .expect(
                                        "could not check elements are non zero and in prime order subgroup (tau g2)",
                                    );

                                        if ratio_check {
                                            check_power_ratios_g2::<E>(
                                                (tau_g2, compressed_output, CheckForCorrectness::No),
                                                (start_chunk, end_chunk),
                                                &mut g2[..],
                                                &g1_check,
                                                "tau g2",
                                            )
                                            .expect("could not check ratios (tau g2)");
                                        }

                                        let size = buffer_size::<E::G2Affine>(compressed_new_challenge);
                                        new_challenge_tau_g2[start_chunk * size..end_chunk * size]
                                            .write_batch(&mut g2[0..end_chunk - start_chunk], compressed_new_challenge)
                                            .expect("Should have written tau_g2 to new challenge");

                                        trace!("tau_g2 verification was successful");
                                    });

                                    // Process alpha_g1 elements.
                                    t.spawn(|_| {
                                        let _enter = span.enter();

                                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                                        check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G1Affine>(
                                        (alpha_g1, compressed_output),
                                        (start_chunk, end_chunk),
                                        &mut g1,
                                        subgroup_check_mode,
                                    )
                                    .expect(
                                        "could not check elements are non zero and in prime order subgroup (alpha g1)",
                                    );

                                        if ratio_check {
                                            check_power_ratios::<E>(
                                                (alpha_g1, compressed_output, CheckForCorrectness::No),
                                                (start_chunk, end_chunk),
                                                &mut g1,
                                                &g2_check,
                                                "alpha g1",
                                            )
                                            .expect("could not check ratios (alpha g1)");
                                        }

                                        let size = buffer_size::<E::G1Affine>(compressed_new_challenge);
                                        new_challenge_alpha_g1[start_chunk * size..end_chunk * size]
                                            .write_batch(&mut g1[0..end_chunk - start_chunk], compressed_new_challenge)
                                            .expect("Should have written alpha_g1 to new challenge");

                                        trace!("alpha_g1 verification was successful");
                                    });

                                    // Process beta_g1 elements.
                                    t.spawn(|_| {
                                        let _enter = span.enter();

                                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                                        check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G1Affine>(
                                        (beta_g1, compressed_output),
                                        (start_chunk, end_chunk),
                                        &mut g1,
                                        subgroup_check_mode,
                                    )
                                    .expect(
                                        "could not check element are non zero and in prime order subgroup (beta g1)",
                                    );

                                        if ratio_check {
                                            check_power_ratios::<E>(
                                                (beta_g1, compressed_output, CheckForCorrectness::No),
                                                (start_chunk, end_chunk),
                                                &mut g1,
                                                &g2_check,
                                                "beta g1",
                                            )
                                            .expect("could not check element ratios (beta g1)");
                                        }
                                        let size = buffer_size::<E::G1Affine>(compressed_new_challenge);
                                        new_challenge_beta_g1[start_chunk * size..end_chunk * size]
                                            .write_batch(&mut g1[0..end_chunk - start_chunk], compressed_new_challenge)
                                            .expect("Should have written beta_g1 to new challenge");

                                        trace!("beta_g1 verification was successful");
                                    });
                                });
                            }
                        }
                    });
                }
                ProvingSystem::Marlin => {
                    rayon::scope(|t| {
                        let _ = span.enter();

                        // Process tau_g1 elements.
                        t.spawn(|_| {
                            let _ = span.enter();

                            let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                            check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G1Affine>(
                                (tau_g1, compressed_output),
                                (start_chunk, end_chunk),
                                &mut g1,
                                subgroup_check_mode,
                            )
                            .expect("could not check ratios for tau_g1 elements");

                            let size = buffer_size::<E::G1Affine>(compressed_new_challenge);
                            new_challenge_tau_g1[start_chunk * size..end_chunk * size]
                                .write_batch(&mut g1[0..end_chunk - start_chunk], compressed_new_challenge)
                                .expect("Should have written tau_g1 to new challenge");

                            trace!("tau_g1 verification was successful");
                        });

                        if start == 0 {
                            t.spawn(|_| {
                                let _ = span.enter();

                                let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                                let num_alpha_powers = 3;

                                let start_chunk = 0;
                                let end_chunk = num_alpha_powers + 3 * parameters.total_size_in_log2;

                                check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G1Affine>(
                                    (alpha_g1, compressed_output),
                                    (start_chunk, end_chunk),
                                    &mut g1,
                                    subgroup_check_mode,
                                )
                                .expect("could not check ratios for tau_g1 elements");

                                let size = buffer_size::<E::G1Affine>(compressed_new_challenge);
                                new_challenge_alpha_g1[start_chunk * size..end_chunk * size]
                                    .write_batch(&mut g1[0..end_chunk - start_chunk], compressed_new_challenge)
                                    .expect("Should have written alpha_g1 to new challenge");

                                trace!("alpha_g1 verification was successful");

                                let start_chunk = 0;
                                let end_chunk = parameters.total_size_in_log2 + 2;

                                let mut g2 = vec![E::G2Affine::zero(); parameters.batch_size];

                                check_elements_are_nonzero_and_in_prime_order_subgroup::<E::G2Affine>(
                                    (tau_g2, compressed_output),
                                    (start_chunk, end_chunk),
                                    &mut g2,
                                    subgroup_check_mode,
                                )
                                .expect("could not check element are non zero and in prime order subgroup");

                                let size = buffer_size::<E::G2Affine>(compressed_new_challenge);
                                new_challenge_tau_g2[start_chunk * size..end_chunk * size]
                                    .write_batch(&mut g2[0..end_chunk - start_chunk], compressed_new_challenge)
                                    .expect("Should have written tau_g2 to new challenge");

                                trace!("tau_g2 verification was successful");
                            });
                        } else {
                            debug!("Ignoring the last element, because the last was extended anyway.");
                        }
                    });
                }
            }

            debug!("batch verification successful");

            Ok(())
        })?;

        info!("phase1-verification complete");

        Ok(())
    }

    /// Verifies that the accumulator was transformed correctly
    /// given the `PublicKey` and the so-far hash of the accumulator.
    /// This verifies the ratios in a given accumulator.
    pub fn aggregate_verification(
        (output, compressed_output, check_output_for_correctness): (&[u8], UseCompression, CheckForCorrectness),
        parameters: &Phase1Parameters<E>,
    ) -> Result<()> {
        let span = info_span!("phase1-aggregate-verification");
        let _enter = span.enter();

        info!("starting...");

        let (tau_g1, tau_g2, alpha_g1, beta_g1, _) = split(output, parameters, compressed_output);

        let (g1_check, g2_check, g1_alpha_check) = {
            // Ensure that the initial conditions are correctly formed (first 2 elements)
            // We allocate a G1 vector of length 2 and re-use it for our G1 elements.
            // We keep the values of the tau_g1 / tau_g2 elements for later use.

            // Current iteration of tau_g1[0].
            let after_g1 =
                read_initial_elements::<E::G1Affine>(tau_g1, compressed_output, check_output_for_correctness)?;

            // Current iteration of tau_g2[0].
            let after_g2 =
                read_initial_elements::<E::G2Affine>(tau_g2, compressed_output, check_output_for_correctness)?;

            // Fetch the iteration of alpha_g1[0].
            let after_alpha_g1 =
                read_initial_elements::<E::G1Affine>(alpha_g1, compressed_output, check_output_for_correctness)?;

            let g1_check = (after_g1[0], after_g1[1]);
            let g2_check = (after_g2[0], after_g2[1]);
            let g1_alpha_check = (after_alpha_g1[0], after_alpha_g1[1]);

            (g1_check, g2_check, g1_alpha_check)
        };

        debug!("initial elements were computed correctly");

        match parameters.proving_system {
            // preallocate 2 vectors per batch
            // Ensure that the pairs are created correctly (we do this in chunks!)
            // load `batch_size` chunks on each iteration and perform the transformation
            ProvingSystem::Groth16 => {
                iter_chunk(&parameters, |start, end| {
                    debug!("verifying batch from {} to {}", start, end);

                    let span = info_span!("batch", start, end);
                    let _enter = span.enter();

                    rayon::scope(|t| {
                        let _enter = span.enter();

                        t.spawn(|_| {
                            let _enter = span.enter();

                            let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                            check_power_ratios::<E>(
                                (tau_g1, compressed_output, check_output_for_correctness),
                                (start, end),
                                &mut g1,
                                &g2_check,
                                "tau g1",
                            )
                            .expect("could not check ratios for tau_g1 elements");

                            trace!("tau_g1 verification successful");
                        });

                        if start < parameters.powers_length {
                            // if the `end` would be out of bounds, then just process until
                            // the end (this is necessary in case the last batch would try to
                            // process more elements than available)
                            let end = if start + parameters.batch_size > parameters.powers_length {
                                parameters.powers_length
                            } else {
                                end
                            };

                            if end > start + 1 {
                                rayon::scope(|t| {
                                    let _enter = span.enter();

                                    t.spawn(|_| {
                                        let _enter = span.enter();

                                        let mut g2 = vec![E::G2Affine::zero(); parameters.batch_size];

                                        check_power_ratios_g2::<E>(
                                            (tau_g2, compressed_output, check_output_for_correctness),
                                            (start, end),
                                            &mut g2,
                                            &g1_check,
                                            "tau_g2",
                                        )
                                        .expect("could not check ratios for tau_g2 elements");

                                        trace!("tau_g2 verification successful");
                                    });

                                    t.spawn(|_| {
                                        let _enter = span.enter();

                                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                                        check_power_ratios::<E>(
                                            (alpha_g1, compressed_output, check_output_for_correctness),
                                            (start, end),
                                            &mut g1,
                                            &g2_check,
                                            "alpha_g1",
                                        )
                                        .expect("could not check ratios for alpha_g1 elements");

                                        trace!("alpha_g1 verification successful");
                                    });

                                    t.spawn(|_| {
                                        let _enter = span.enter();

                                        let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                                        check_power_ratios::<E>(
                                            (beta_g1, compressed_output, check_output_for_correctness),
                                            (start, end),
                                            &mut g1,
                                            &g2_check,
                                            "beta_g1",
                                        )
                                        .expect("could not check ratios for beta_g1 elements");

                                        trace!("beta_g1 verification successful");
                                    });
                                });
                            } else {
                                error!("Ignoring the last element, because the last was extended anyway.");
                            }
                        }
                    });

                    debug!("chunk verification successful");

                    Ok(())
                })?;
            }
            ProvingSystem::Marlin => {
                iter_chunk(&parameters, |start, end| {
                    debug!("verifying batch from {} to {}", start, end);

                    let span = info_span!("batch", start, end);
                    let _enter = span.enter();

                    rayon::scope(|t| {
                        let _enter = span.enter();

                        t.spawn(|_| {
                            let _enter = span.enter();

                            let mut g1 = vec![E::G1Affine::zero(); parameters.batch_size];

                            check_power_ratios::<E>(
                                (tau_g1, compressed_output, check_output_for_correctness),
                                (start, end),
                                &mut g1,
                                &g2_check,
                                "tau g1",
                            )
                            .expect("could not check ratios for tau_g1 elements");

                            trace!("tau_g1 verification successful");
                        });

                        {
                            let powers_of_two_in_range = (0..parameters.total_size_in_log2)
                                .map(|i| (i, parameters.powers_length as u64 - 1 - (1 << i) + 2))
                                .map(|(i, p)| (i, p as usize))
                                .filter(|(_, p)| start <= *p && *p < end)
                                .collect::<Vec<_>>();

                            for (i, p) in powers_of_two_in_range.into_iter() {
                                let g1_size = buffer_size::<E::G1Affine>(compressed_output);
                                let g2_size = buffer_size::<E::G2Affine>(compressed_output);

                                let g1 = (&tau_g1[p * g1_size..(p + 1) * g1_size])
                                    .read_element(compressed_output, check_output_for_correctness)
                                    .expect("should have read g1 element");
                                let g2 = (&tau_g2[(2 + i) * g2_size..(2 + i + 1) * g2_size])
                                    .read_element(compressed_output, check_output_for_correctness)
                                    .expect("should have read g2 element");
                                check_same_ratio::<E>(
                                    &(g1, E::G1Affine::generator()),
                                    &(E::G2Affine::generator(), g2),
                                    "G1<>G2".to_string(),
                                )
                                .expect("should have checked same ratio");

                                let mut alpha_g1_elements = vec![E::G1Affine::zero(); 3];
                                (&alpha_g1[(3 + 3 * i) * g1_size..(3 + 3 * i + 3) * g1_size])
                                    .read_batch_preallocated(
                                        &mut alpha_g1_elements,
                                        compressed_output,
                                        check_output_for_correctness,
                                    )
                                    .expect("should have read alpha g1 elements");
                                check_same_ratio::<E>(
                                    &(alpha_g1_elements[0], alpha_g1_elements[1]),
                                    &g2_check,
                                    "alpha_g1 ratio 1".to_string(),
                                )
                                .expect("should have checked same ratio");
                                check_same_ratio::<E>(
                                    &(alpha_g1_elements[1], alpha_g1_elements[2]),
                                    &g2_check,
                                    "alpha_g1 ratio 2".to_string(),
                                )
                                .expect("should have checked same ratio");
                                check_same_ratio::<E>(
                                    &(alpha_g1_elements[0], g1_alpha_check.0),
                                    &(E::G2Affine::generator(), g2),
                                    "alpha consistent".to_string(),
                                )
                                .expect("should have checked same ratio");
                            }
                        }
                    });

                    // This is the first batch, check alpha_g1. batch size is guaranteed to be of size >= 3
                    if start == 0 {
                        let num_alpha_powers = 3;
                        let mut g1 = vec![E::G1Affine::zero(); num_alpha_powers];

                        check_power_ratios::<E>(
                            (alpha_g1, compressed_output, check_output_for_correctness),
                            (0, num_alpha_powers),
                            &mut g1,
                            &g2_check,
                            "alpha g1",
                        )
                        .expect("could not check ratios for alpha_g1");

                        trace!("alpha_g1 verification was successful");

                        let mut g2 = vec![E::G2Affine::zero(); 3];

                        check_power_ratios_g2::<E>(
                            (tau_g2, compressed_output, check_output_for_correctness),
                            (0, 2),
                            &mut g2,
                            &g1_check,
                            "tau g2",
                        )
                        .expect("could not check ratios for tau_g2");

                        trace!("tau_g2 verification was successful");
                    }

                    debug!("chunk verification successful");

                    Ok(())
                })?;
            }
        }

        info!("aggregate verification complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::testing::{generate_input, generate_new_challenge, generate_output};
    use setup_utils::calculate_hash;

    use ark_bls12_377::Bls12_377;
    use ark_bw6_761::BW6_761;
    use ark_mnt4_753::MNT4_753;
    use ark_mnt6_753::MNT6_753;

    fn full_verification_test<E: Pairing>(
        total_size_in_log2: usize,
        batch: usize,
        compressed_input: UseCompression,
        compressed_output: UseCompression,
    ) {
        for proving_system in &[ProvingSystem::Groth16, ProvingSystem::Marlin] {
            for batch_exp_mode in
                vec![BatchExpMode::Auto, BatchExpMode::Direct, BatchExpMode::BatchInversion].into_iter()
            {
                let parameters = Phase1Parameters::<E>::new_full(*proving_system, total_size_in_log2, batch);

                // allocate the input/output vectors
                let (input, _) = generate_input(&parameters, compressed_input, CheckForCorrectness::No);
                let mut output = generate_output(&parameters, compressed_output);
                let mut new_challenge = generate_new_challenge(&parameters, UseCompression::No);

                // Construct our keypair
                let current_accumulator_hash = blank_hash();
                let mut rng = derive_rng_from_seed(b"test_verify_transformation 1");
                let (pub_key, priv_key) = Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref())
                    .expect("could not generate keypair");

                // transform the accumulator
                Phase1::computation(
                    &input,
                    &mut output,
                    compressed_input,
                    compressed_output,
                    CheckForCorrectness::No,
                    batch_exp_mode,
                    &priv_key,
                    &parameters,
                )
                .unwrap();
                // ensure that the key is not available to the verifier
                drop(priv_key);

                let res = Phase1::verification(
                    &input,
                    &output,
                    &mut new_challenge,
                    &pub_key,
                    &current_accumulator_hash,
                    compressed_input,
                    compressed_output,
                    UseCompression::No,
                    CheckForCorrectness::No,
                    CheckForCorrectness::Full,
                    SubgroupCheckMode::Auto,
                    false,
                    &parameters,
                );
                assert!(res.is_ok());

                // subsequent participants must use the hash of the accumulator they received
                let current_accumulator_hash = calculate_hash(&output);
                let (pub_key, priv_key) = Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref())
                    .expect("could not generate keypair");

                // generate a new output vector for the 2nd participant's contribution
                let mut output_2 = generate_output(&parameters, compressed_output);
                let mut new_challenge_2 = generate_new_challenge(&parameters, UseCompression::No);
                // we use the first output as input
                Phase1::computation(
                    &output,
                    &mut output_2,
                    compressed_output,
                    compressed_output,
                    CheckForCorrectness::No,
                    batch_exp_mode,
                    &priv_key,
                    &parameters,
                )
                .unwrap();
                // ensure that the key is not available to the verifier
                drop(priv_key);

                let res = Phase1::verification(
                    &output,
                    &output_2,
                    &mut new_challenge_2,
                    &pub_key,
                    &current_accumulator_hash,
                    compressed_output,
                    compressed_output,
                    UseCompression::No,
                    CheckForCorrectness::No,
                    CheckForCorrectness::Full,
                    SubgroupCheckMode::Auto,
                    false,
                    &parameters,
                );
                assert!(res.is_ok());

                // verification will fail if the old hash is used
                let res = Phase1::aggregate_verification(
                    (&output_2, compressed_output, CheckForCorrectness::Full),
                    &parameters,
                );
                assert!(res.is_ok());

                // verification will fail if the old hash is used
                let res = Phase1::verification(
                    &output,
                    &output_2,
                    &mut new_challenge_2,
                    &pub_key,
                    &blank_hash(),
                    compressed_output,
                    compressed_output,
                    UseCompression::No,
                    CheckForCorrectness::No,
                    CheckForCorrectness::Full,
                    SubgroupCheckMode::Auto,
                    false,
                    &parameters,
                );
                assert!(res.is_err());

                /* Test is disabled for now as it doesn't always work and when it does, it panics.
                // verification will fail if even 1 byte is modified
                output_2[100] = 0;
                let res = Phase1::verification(
                    &output,
                    &output_2,
                    &pub_key,
                    &current_accumulator_hash,
                    compressed_output,
                    compressed_output,
                    CheckForCorrectness::No,
                    CheckForCorrectness::Full,
                    &parameters,
                );
                assert!(res.is_err());
                */
            }
        }
    }

    fn chunk_verification_test<E: Pairing>(
        total_size_in_log2: usize,
        batch: usize,
        compressed_input: UseCompression,
        compressed_output: UseCompression,
    ) {
        let correctness = CheckForCorrectness::Full;

        for proving_system in &[ProvingSystem::Groth16, ProvingSystem::Marlin] {
            for batch_exp_mode in
                vec![BatchExpMode::Auto, BatchExpMode::Direct, BatchExpMode::BatchInversion].into_iter()
            {
                let powers_length = 1 << total_size_in_log2;
                let powers_g1_length = (powers_length << 1) - 1;
                let powers_length_for_proving_system = match *proving_system {
                    ProvingSystem::Groth16 => powers_g1_length,
                    ProvingSystem::Marlin => powers_length,
                };
                let num_chunks = (powers_length_for_proving_system + batch - 1) / batch;

                for chunk_index in 0..num_chunks {
                    // Generate a new parameter for this chunk.
                    let parameters = Phase1Parameters::<E>::new_chunk(
                        ContributionMode::Chunked,
                        chunk_index,
                        batch,
                        *proving_system,
                        total_size_in_log2,
                        batch,
                    );

                    //
                    // First contributor computes a chunk.
                    //

                    let output_1 = {
                        // Start with an empty hash as this is the first time.
                        let digest = blank_hash();

                        // Construct the first contributor's keypair.
                        let (public_key_1, private_key_1) = {
                            let mut rng = derive_rng_from_seed(b"test_verify_transformation 1");
                            Phase1::<E>::key_generation(&mut rng, digest.as_ref()).expect("could not generate keypair")
                        };

                        // Allocate the input/output vectors
                        let (input, _) = generate_input(&parameters, compressed_input, correctness);
                        let mut output_1 = generate_output(&parameters, compressed_output);
                        let mut new_challenge_1 = generate_new_challenge(&parameters, UseCompression::No);

                        // Compute a chunked contribution.
                        Phase1::computation(
                            &input,
                            &mut output_1,
                            compressed_input,
                            compressed_output,
                            correctness,
                            batch_exp_mode,
                            &private_key_1,
                            &parameters,
                        )
                        .unwrap();
                        // Ensure that the key is not available to the verifier.
                        drop(private_key_1);

                        // Verify that the chunked contribution is correct.
                        assert!(
                            Phase1::verification(
                                &input,
                                &output_1,
                                &mut new_challenge_1,
                                &public_key_1,
                                &digest,
                                compressed_input,
                                compressed_output,
                                UseCompression::No,
                                correctness,
                                correctness,
                                SubgroupCheckMode::Auto,
                                false,
                                &parameters,
                            )
                            .is_ok()
                        );

                        output_1
                    };

                    //
                    // Second contributor computes a chunk.
                    //

                    // Note subsequent participants must use the hash of the accumulator they received.
                    let digest = calculate_hash(&output_1);

                    // Construct the second contributor's keypair, based on the first contributor's output.
                    let (public_key_2, private_key_2) = {
                        let mut rng = derive_rng_from_seed(b"test_verify_transformation 2");
                        Phase1::key_generation(&mut rng, digest.as_ref()).expect("could not generate keypair")
                    };

                    // Generate a new output vector for the second contributor.
                    let mut output_2 = generate_output(&parameters, compressed_output);
                    let mut new_challenge_2 = generate_new_challenge(&parameters, UseCompression::No);

                    // Compute a chunked contribution, based on the first contributor's output.
                    Phase1::computation(
                        &output_1,
                        &mut output_2,
                        compressed_output,
                        compressed_output,
                        correctness,
                        batch_exp_mode,
                        &private_key_2,
                        &parameters,
                    )
                    .unwrap();
                    // Ensure that the key is not available to the verifier.
                    drop(private_key_2);

                    // Verify that the chunked contribution is correct.
                    assert!(
                        Phase1::verification(
                            &output_1,
                            &output_2,
                            &mut new_challenge_2,
                            &public_key_2,
                            &digest,
                            compressed_output,
                            compressed_output,
                            UseCompression::No,
                            correctness,
                            correctness,
                            SubgroupCheckMode::Auto,
                            false,
                            &parameters,
                        )
                        .is_ok()
                    );

                    // Verification will fail if the old hash is used.
                    if parameters.chunk_index == 0 {
                        assert!(
                            Phase1::verification(
                                &output_1,
                                &output_2,
                                &mut new_challenge_2,
                                &public_key_2,
                                &blank_hash(),
                                compressed_output,
                                compressed_output,
                                UseCompression::No,
                                correctness,
                                correctness,
                                SubgroupCheckMode::Auto,
                                false,
                                &parameters,
                            )
                            .is_err()
                        );
                    }

                    /* Test is disabled for now as it doesn't always work and when it does, it panics.
                    // Verification will fail if even 1 byte is modified.
                    {
                        output_2[100] = 0;
                        assert!(Phase1::verification(
                            &output_1,
                            &output_2,
                            &public_key_2,
                            &digest,
                            compressed_output,
                            compressed_output,
                            correctness,
                            correctness,
                            &parameters,
                        )
                        .is_err());
                    }
                    */
                }
            }
        }
    }

    #[test]
    fn test_verification_bls12_377() {
        full_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        full_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        full_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
        full_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::No, UseCompression::Yes);
    }

    #[test]
    fn test_verification_bw6_761() {
        full_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        full_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        full_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
        full_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::No, UseCompression::Yes);
    }

    #[test]
    fn test_chunk_verification_bw6_761() {
        chunk_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        chunk_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        chunk_verification_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
    }

    #[test]
    fn test_chunk_verification_bls12_377() {
        chunk_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        chunk_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        chunk_verification_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
    }

    #[test]
    fn test_verification_mnt4_753() {
        full_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        full_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        full_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
        full_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::No, UseCompression::Yes);
    }

    #[test]
    fn test_verification_mnt6_753() {
        full_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        full_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        full_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
        full_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::No, UseCompression::Yes);
    }

    #[test]
    fn test_chunk_verification_mnt4_753() {
        chunk_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        chunk_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        chunk_verification_test::<MNT4_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
    }

    #[test]
    fn test_chunk_verification_mnt6_753() {
        chunk_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes);
        chunk_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No);
        chunk_verification_test::<MNT6_753>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No);
    }
}
