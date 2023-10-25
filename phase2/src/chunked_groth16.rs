//! Chunked Phase 2
//!
//! Large MPCs can require >50GB of elements to be loaded in memory. This module provides
//! utilities for operating directly on raw items which implement `Read`, `Write` and `Seek`
//! such that contributing and verifying the MPC can be done in chunks which fit in memory.
use crate::{
    keypair::{Keypair, PublicKey},
    parameters::*,
};
use setup_utils::{
    batch_mul,
    check_same_ratio,
    deserialize,
    merge_pairs,
    serialize,
    BatchExpMode,
    CheckForCorrectness,
    InvariantKind,
    Phase2Error,
    Result,
    UseCompression,
};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use byteorder::{BigEndian, WriteBytesExt};
use rand::Rng;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::{Mul, Neg},
};
use tracing::{debug, info, info_span, trace};

/// Given two serialized contributions to the ceremony, this will check that `after`
/// has been correctly calculated from `before`. Large vectors will be read in
/// `batch_size` batches
#[allow(clippy::cognitive_complexity)]
pub fn verify<E: Pairing>(
    before: &mut [u8],
    after: &mut [u8],
    batch_size: usize,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
) -> Result<Vec<[u8; 64]>> {
    let span = info_span!("phase2-verify");
    let _enter = span.enter();
    info!("starting...");

    let mut before = std::io::Cursor::new(before);
    let mut after = std::io::Cursor::new(after);

    let vk_before = deserialize::<VerifyingKey<E>, _>(&mut before, compressed, check_correctness)?;
    let beta_g1_before = deserialize::<E::G1Affine, _>(&mut before, compressed, check_correctness)?;
    // we don't need the previous delta_g1 so we can skip it
    // it has the same length as beta_g1_before
    before.seek(SeekFrom::Current(beta_g1_before.compressed_size() as i64))?;

    let vk_after = deserialize::<VerifyingKey<E>, _>(&mut after, compressed, check_correctness)?;
    let beta_g1_after = deserialize::<E::G1Affine, _>(&mut after, compressed, check_correctness)?;
    let delta_g1_after = deserialize::<E::G1Affine, _>(&mut after, compressed, check_correctness)?;

    // VK parameters remain unchanged, except for Delta G2
    // which we check at the end of the function against the new contribution's
    // pub_key
    ensure_unchanged(vk_before.alpha_g1, vk_after.alpha_g1, InvariantKind::AlphaG1)?;
    ensure_unchanged(beta_g1_before, beta_g1_after, InvariantKind::BetaG1)?;
    ensure_unchanged(vk_before.beta_g2, vk_after.beta_g2, InvariantKind::BetaG2)?;
    ensure_unchanged(vk_before.gamma_g2, vk_after.gamma_g2, InvariantKind::GammaG2)?;
    ensure_unchanged_vec(
        &vk_before.gamma_abc_g1,
        &vk_after.gamma_abc_g1,
        &InvariantKind::GammaAbcG1,
    )?;

    debug!("initial elements unchanged");

    // Split the before-after buffers in non-overlapping slices and spawn a thread for each group
    // of variables
    let position = before.position() as usize;
    let remaining_before = &mut before.get_mut()[position..];
    let position = after.position() as usize;
    let remaining_after = &mut after.get_mut()[position..];
    let (before_alpha_g1, before_beta_g1, before_beta_g2, before_h, before_l) =
        split_transcript::<E>(remaining_before)?;
    let (after_alpha_g1, after_beta_g1, after_beta_g2, after_h, after_l) = split_transcript::<E>(remaining_after)?;
    // Save the position where the cursor should be after the threads execute
    let pos = position
        + 5 * 8 // u64 = 8 bytes
        + before_alpha_g1.len()
        + before_beta_g1.len()
        + before_beta_g2.len()
        + before_h.len()
        + before_l.len();

    crossbeam::scope(|s| -> Result<_> {
        let _enter = span.enter();
        // Alpha G1, Beta G1/G2 queries are same
        // (do this in chunks since the vectors may be large)
        let mut threads = Vec::with_capacity(5);
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("alpha_g1_query");
            let _enter = span.enter();
            chunked_ensure_unchanged_vec::<E::G1Affine>(
                before_alpha_g1,
                after_alpha_g1,
                batch_size,
                &InvariantKind::AlphaG1Query,
                compressed,
                check_correctness,
            )
        }));
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("beta_g1_query");
            let _enter = span.enter();
            chunked_ensure_unchanged_vec::<E::G1Affine>(
                before_beta_g1,
                after_beta_g1,
                batch_size,
                &InvariantKind::BetaG1Query,
                compressed,
                check_correctness,
            )
        }));
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("beta_g2_query");
            let _enter = span.enter();
            chunked_ensure_unchanged_vec::<E::G2Affine>(
                before_beta_g2,
                after_beta_g2,
                batch_size,
                &InvariantKind::BetaG2Query,
                compressed,
                check_correctness,
            )
        }));

        // H and L queries should be updated with delta^-1
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("h_g1_query");
            let _enter = span.enter();
            chunked_check_ratio::<E>(
                before_h,
                vk_before.delta_g2,
                after_h,
                vk_after.delta_g2,
                batch_size,
                compressed,
                check_correctness,
                "H_query ratio check failed",
            )
        }));
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("l_g1_query");
            let _enter = span.enter();
            chunked_check_ratio::<E>(
                before_l,
                vk_before.delta_g2,
                after_l,
                vk_after.delta_g2,
                batch_size,
                compressed,
                check_correctness,
                "L_query ratio check failed",
            )
        }));

        // join the threads at the end to ensure
        // the computation is done
        for t in threads {
            t.join()??;
        }

        Ok(())
    })??;

    before.seek(SeekFrom::Start(pos as u64))?;
    after.seek(SeekFrom::Start(pos as u64))?;

    // cs_hash should be the same
    let mut cs_hash_before = [0u8; 64];
    before.read_exact(&mut cs_hash_before)?;
    let mut cs_hash_after = [0u8; 64];
    after.read_exact(&mut cs_hash_after)?;
    ensure_unchanged(&cs_hash_before[..], &cs_hash_after[..], InvariantKind::CsHash)?;

    debug!("cs hash was unchanged");

    // None of the previous transformations should change
    let contributions_before = PublicKey::<E>::read_batch(&mut before)?;
    let contributions_after = PublicKey::<E>::read_batch(&mut after)?;
    ensure_unchanged(
        &contributions_before[..],
        &contributions_after[0..contributions_before.len()],
        InvariantKind::Contributions,
    )?;

    debug!("previous contributions were unchanged");

    // Ensure that the new pub_key has been properly calculated
    let pub_key = if let Some(pub_key) = contributions_after.last() {
        pub_key
    } else {
        // if there were no new contributions then we should error
        return Err(Phase2Error::NoContributions.into());
    };
    ensure_unchanged(pub_key.delta_after, delta_g1_after, InvariantKind::DeltaG1)?;
    debug!("public key was updated correctly");

    check_same_ratio::<E>(
        &(E::G1Affine::generator(), pub_key.delta_after),
        &(E::G2Affine::generator(), vk_after.delta_g2),
        "Inconsistent G2 Delta".to_string(),
    )?;

    debug!("verifying key was updated correctly");

    let res = verify_transcript(cs_hash_before, &contributions_after)?;

    debug!("verified transcript");

    info!("done.");
    Ok(res)
}

/// Given a buffer which corresponds to the format of `MPCParameters` (Groth16 Parameters
/// followed by the contributions array and the contributions hash), this will modify the
/// Delta_g1, the VK's Delta_g2 and will update the H and L queries in place while leaving
/// everything else unchanged
pub fn contribute<E: Pairing, R: Rng>(
    buffer: &mut [u8],
    rng: &mut R,
    batch_size: usize,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
    batch_exp_mode: BatchExpMode,
) -> Result<[u8; 64]> {
    let span = info_span!("phase2-contribute");
    let _enter = span.enter();

    info!("starting...");

    let mut buffer = std::io::Cursor::new(buffer);
    // The VK is small so we read it directly from the start
    let mut vk = deserialize::<VerifyingKey<E>, _>(&mut buffer, compressed, check_correctness)?;
    // leave beta_g1 unchanged
    let g1_compressed_size = E::G1Affine::default().compressed_size();
    buffer.seek(SeekFrom::Current(g1_compressed_size as i64))?;
    // read delta_g1
    let mut delta_g1 = deserialize::<E::G1Affine, _>(&mut buffer, compressed, check_correctness)?;

    // Skip the vector elements for now so that we can read the contributions
    skip_vec::<E::G1Affine, _>(&mut buffer)?; // Alpha G1
    skip_vec::<E::G1Affine, _>(&mut buffer)?; // Beta G1
    skip_vec::<E::G2Affine, _>(&mut buffer)?; // Beta G2
    skip_vec::<E::G1Affine, _>(&mut buffer)?; // H
    skip_vec::<E::G1Affine, _>(&mut buffer)?; // L

    // Read the transcript hash and the contributions
    let mut cs_hash = [0u8; 64];
    buffer.read_exact(&mut cs_hash)?;
    let contributions = PublicKey::<E>::read_batch(&mut buffer)?;

    // Create the keypair
    let Keypair {
        public_key,
        private_key,
    } = Keypair::new(delta_g1, cs_hash, &contributions, rng);
    let hash = public_key.hash();
    // THIS MUST BE DESTROYED
    let delta = private_key.delta;
    let delta_inv = private_key.delta.inverse().expect("nonzero");

    // update the values
    delta_g1 = delta_g1.mul(delta).into_affine();
    vk.delta_g2 = vk.delta_g2.mul(delta).into_affine();

    // go back to the start of the buffer to write the updated vk and delta_g1
    buffer.seek(SeekFrom::Start(0))?;
    // write the vk
    vk.serialize_compressed(&mut buffer)?;
    // leave beta_g1 unchanged
    buffer.seek(SeekFrom::Current(g1_compressed_size as i64))?;
    // write delta_g1
    delta_g1.serialize_compressed(&mut buffer)?;

    debug!("updated delta g1 and vk delta g2");

    skip_vec::<E::G1Affine, _>(&mut buffer)?; // Alpha G1
    skip_vec::<E::G1Affine, _>(&mut buffer)?; // Beta G1
    skip_vec::<E::G2Affine, _>(&mut buffer)?; // Beta G2

    debug!("skipped unused elements...");

    // The previous operations are all on small size elements so do them serially
    // the `h` and `l` queries are relatively large, so we can get a nice speedup
    // by performing the reads and writes in parallel
    let h_query_len = u64::deserialize_compressed(&mut buffer)? as usize;
    let position = buffer.position() as usize;
    let remaining = &mut buffer.get_mut()[position..];
    let (h, l) = remaining.split_at_mut(h_query_len * g1_compressed_size);
    let l_query_len = u64::deserialize_compressed(&mut &*l)? as usize;

    // spawn 2 scoped threads to perform the contribution
    crossbeam::scope(|s| -> Result<_> {
        let mut threads = Vec::with_capacity(2);
        let _enter = span.enter();
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("h_query");
            let _enter = span.enter();
            chunked_mul_queries::<E::G1Affine>(
                h,
                h_query_len,
                &delta_inv,
                batch_size,
                compressed,
                check_correctness,
                batch_exp_mode,
            )
        }));

        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("l_query");
            let _enter = span.enter();
            chunked_mul_queries::<E::G1Affine>(
                // since we read the l_query length we will pass the buffer
                // after it
                &mut l[8..], // u64 = 8 bytes
                l_query_len,
                &delta_inv,
                batch_size,
                compressed,
                check_correctness,
                batch_exp_mode,
            )
        }));

        for t in threads {
            t.join()??;
        }

        Ok(())
    })??;

    debug!("appending contribution...");

    // we processed the 2 elements via the raw buffer, so we have to modify the cursor accordingly
    let pos = position + (l_query_len + h_query_len) * g1_compressed_size + 8; // u64 = 8 bytes
    buffer.seek(SeekFrom::Start(pos as u64))?;

    // leave the cs_hash unchanged (64 bytes size)
    buffer.seek(SeekFrom::Current(64))?;

    // update the pub_keys length
    buffer.write_u32::<BigEndian>((contributions.len() + 1) as u32)?;

    // advance to where the next pub_key would be in the buffer and append it
    buffer.seek(SeekFrom::Current((PublicKey::<E>::size() * contributions.len()) as i64))?;
    public_key.write(&mut buffer)?;

    info!("done.");

    Ok(hash)
}

/// Skips the vector ahead of the cursor.
fn skip_vec<C: AffineRepr, B: Read + Seek>(mut buffer: B) -> Result<()> {
    let len = u64::deserialize_compressed(&mut buffer)? as usize;
    let skip_len = len * C::default().compressed_size();
    buffer.seek(SeekFrom::Current(skip_len as i64))?;
    Ok(())
}

/// Multiplies a vector of affine elements by `element` in `batch_size` batches
/// The first 8 bytes read from the buffer are the vector's length. The result
/// is written back to the buffer in place
#[allow(clippy::cognitive_complexity)]
fn chunked_mul_queries<C: AffineRepr>(
    buffer: &mut [u8],
    query_len: usize,
    element: &C::ScalarField,
    batch_size: usize,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
    batch_exp_mode: BatchExpMode,
) -> Result<()> {
    let span = info_span!("multiply_query");
    let _enter = span.enter();
    debug!("starting...");
    let mut buffer = std::io::Cursor::new(buffer);

    let iters = query_len / batch_size;
    let leftovers = query_len % batch_size;
    // naive chunking, probably room for parallelization
    for i in 0..iters {
        let span = info_span!("iter", i);
        let _enter = span.enter();

        mul_query::<C, _>(
            &mut buffer,
            element,
            batch_size,
            compressed,
            check_correctness,
            batch_exp_mode,
        )?;

        trace!("ok");
    }
    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        let span = info_span!("iter", i = iters);
        let _enter = span.enter();

        mul_query::<C, _>(
            &mut buffer,
            element,
            leftovers,
            compressed,
            check_correctness,
            batch_exp_mode,
        )?;

        trace!("ok");
    }

    debug!("done");
    Ok(())
}

/// Deserializes `num_els` elements, multiplies them by `element`
/// and writes them back in place
fn mul_query<C: AffineRepr, B: Read + Write + Seek>(
    mut buffer: B,
    element: &C::ScalarField,
    num_els: usize,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
    batch_exp_mode: BatchExpMode,
) -> Result<()> {
    let mut query = (0..num_els)
        .map(|_| deserialize::<C, _>(&mut buffer, compressed, check_correctness))
        .collect::<std::result::Result<Vec<_>, _>>()?; // why can't we use the aliased error type here?

    batch_mul(&mut query, element, batch_exp_mode)?;

    // seek back to update the elements
    buffer.seek(SeekFrom::Current(
        ((num_els * C::default().compressed_size()) as i64).neg(),
    ))?;
    query
        .iter()
        .map(|el| serialize(el, &mut buffer, compressed))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(())
}

/// Checks that 2 vectors read from the 2 buffers are the same in chunks
#[allow(clippy::cognitive_complexity)]
fn chunked_ensure_unchanged_vec<C: AffineRepr>(
    before: &mut [u8],
    after: &mut [u8],
    batch_size: usize,
    kind: &InvariantKind,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
) -> Result<()> {
    let span = info_span!("unchanged_vec");
    let _enter = span.enter();
    debug!("starting...");

    let c_compressed_size = C::default().compressed_size();
    let len_before = before.len() / c_compressed_size;
    let len_after = after.len() / c_compressed_size;
    ensure_unchanged(len_before, len_after, kind.clone())?;

    let mut before = std::io::Cursor::new(before);
    let mut after = std::io::Cursor::new(after);

    let iters = len_before / batch_size;
    let leftovers = len_before % batch_size;
    for i in 0..iters {
        let span1 = info_span!("iter", i);
        let _enter = span1.enter();

        let (els_before, els_after) =
            read_batch::<C, _>(&mut before, &mut after, batch_size, compressed, check_correctness)?;
        ensure_unchanged_vec(&els_before, &els_after, kind)?;

        trace!("ok");
    }

    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        let span1 = info_span!("iter", i = iters);
        let _enter = span1.enter();

        let (els_before, els_after) =
            read_batch::<C, _>(&mut before, &mut after, leftovers, compressed, check_correctness)?;
        ensure_unchanged_vec(&els_before, &els_after, kind)?;

        trace!("ok");
    }

    debug!("done.");

    Ok(())
}

/// Checks that 2 vectors read from the 2 buffers are the same in chunks
fn chunked_check_ratio<E: Pairing>(
    before: &mut [u8],
    before_delta_g2: E::G2Affine,
    after: &mut [u8],
    after_delta_g2: E::G2Affine,
    batch_size: usize,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
    err: &'static str,
) -> Result<()> {
    let span = info_span!("check_ratio");
    let _enter = span.enter();
    debug!("starting...");

    // read total length
    // PITODO: check if we should use compressed argument
    let g1_compressed_size = E::G1Affine::default().compressed_size();
    let len_before = before.len() / g1_compressed_size;
    let len_after = after.len() / g1_compressed_size;
    if len_before != len_after {
        return Err(Phase2Error::InvalidLength.into());
    }

    let mut before = std::io::Cursor::new(before);
    let mut after = std::io::Cursor::new(after);

    let iters = len_before / batch_size;
    let leftovers = len_before % batch_size;
    for _ in 0..iters {
        let (els_before, els_after) =
            read_batch::<E::G1Affine, _>(&mut before, &mut after, batch_size, compressed, check_correctness)?;
        let pairs = merge_pairs(&els_before, &els_after);
        check_same_ratio::<E>(&pairs, &(after_delta_g2, before_delta_g2), err.to_string())?;
    }
    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        let (els_before, els_after) =
            read_batch::<E::G1Affine, _>(&mut before, &mut after, leftovers, compressed, check_correctness)?;
        let pairs = merge_pairs(&els_before, &els_after);
        check_same_ratio::<E>(&pairs, &(after_delta_g2, before_delta_g2), err.to_string())?;
    }

    debug!("done.");

    Ok(())
}

fn read_batch<C: AffineRepr, B: Read + Write + Seek>(
    mut before: B,
    mut after: B,
    batch_size: usize,
    compressed: UseCompression,
    check_correctness: CheckForCorrectness,
) -> Result<(Vec<C>, Vec<C>)> {
    let els_before = (0..batch_size)
        .map(|_| deserialize::<C, _>(&mut before, compressed, check_correctness))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let els_after = (0..batch_size)
        .map(|_| deserialize::<C, _>(&mut after, compressed, check_correctness))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok((els_before, els_after))
}

type SplitBuf<'a> = (&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8]);

/// splits the transcript from phase 1 after it's been prepared and converted to coefficient form
fn split_transcript<E: Pairing>(input: &mut [u8]) -> Result<SplitBuf> {
    // A, bg1, bg2, h, l
    let len_size = 8; // u64 = 8 bytes
    let g1_compressed_size = E::G1Affine::default().compressed_size();
    let g2_compressed_size = E::G2Affine::default().compressed_size();
    let a_g1_length = u64::deserialize_compressed(&mut &*input)? as usize;
    let (a_g1, others) = input[len_size..].split_at_mut(a_g1_length * g1_compressed_size);

    let b_g1_length = u64::deserialize_compressed(&mut &*others)? as usize;
    let (b_g1, others) = others[len_size..].split_at_mut(b_g1_length * g1_compressed_size);

    let b_g2_length = u64::deserialize_compressed(&mut &*others)? as usize;
    let (b_g2, others) = others[len_size..].split_at_mut(b_g2_length * g2_compressed_size);

    let h_g1_length = u64::deserialize_compressed(&mut &*others)? as usize;
    let (h_g1, others) = others[len_size..].split_at_mut(h_g1_length * g1_compressed_size);

    let l_g1_length = u64::deserialize_compressed(&mut &*others)? as usize;
    let (l_g1, _) = others[len_size..].split_at_mut(l_g1_length * g1_compressed_size);

    Ok((a_g1, b_g1, b_g2, h_g1, l_g1))
}
