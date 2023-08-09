use ark_ec::AffineRepr;
use ark_ff::biginteger::BigInteger;
use ark_std::vec::Vec;

pub use self::internal::BatchGroupArithmetic;

/// We use a batch size that is big enough to amortise the cost of the actual
/// inversion close to zero while not straining the CPU cache by generating and
/// fetching from large w-NAF tables and slices [G]
pub const BATCH_AFFINE_BATCH_SIZE: usize = 4096;

/// We code this in the second operand for the `batch_add_in_place_read_only`
/// method utilised in the `batch_scalar_mul_in_place` method.
/// 0 == Identity; 1 == Neg; 2 == GLV; 3 == GLV + Neg
pub(crate) const ENDO_CODING_BITS: usize = 2;

#[inline(always)]
pub(crate) fn decode_endo_from_u32(index_code: u32) -> (usize, u8) {
    (index_code as usize >> ENDO_CODING_BITS, index_code as u8 % 4)
}

/// We make use of the Montgomery trick to amortise finite field inversions
/// in order to utilise the affine formulas for elliptic curve adds and doubles
/// which are significantly cheaper for SW curves than the projective formulas

/// More detailed description in ../spec/algorithmic-optimisations.pdf
pub(crate) mod internal {
    use ark_ec::AffineRepr;
    use ark_ff::{biginteger::BigInteger, Field};
    use ark_std::{ops::Neg, vec::Vec};
    use either::Either;

    pub trait BatchGroupArithmetic
    where
        Self: Sized + Clone + Copy + AffineRepr + Neg<Output = Self>,
    {
        type BaseFieldForBatch: Field;

        // We use the w-NAF method, achieving point density of approximately 1/(w + 1)
        // and requiring storage of only 2^(w - 1).
        // Refer to e.g. Improved Techniques for Fast Exponentiation, Section 4
        // Bodo M¨oller 2002. https://www.bmoeller.de/pdf/fastexp-icisc2002.pdf

        /// Computes [[p_1, 3 * p_1, ..., (2^w - 1) * p_1], ..., [p_n, 3*p_n,  ...,
        /// (2^w - 1) p_n]] We need to manipulate the offsets when using the
        /// table
        fn batch_wnaf_tables(bases: &[Self], w: usize) -> Vec<Self> {
            let half_size = 1 << (w - 1);
            let batch_size = bases.len();

            let mut two_a = bases.to_vec();
            let instr = (0..batch_size).map(|x| x as u32).collect::<Vec<_>>();
            Self::batch_double_in_place(&mut two_a, &instr[..], None);

            let mut tables = Vec::<Self>::with_capacity(half_size * batch_size);
            tables.extend_from_slice(bases);
            let mut scratch_space = Vec::<Option<Self>>::with_capacity((batch_size - 1) / 2 + 1);

            for i in 1..half_size {
                let instr = (0..batch_size)
                    .map(|x| (((i - 1) * batch_size + x) as u32, x as u32))
                    .collect::<Vec<_>>();
                Self::batch_add_write_read_self(&two_a[..], &instr[..], &mut tables, &mut scratch_space);
            }
            tables
        }

        /// Computes the vectorised version of the wnaf integer recoding
        /// Optionally takes a slice of booleans which indicate whether that
        /// scalar is negative. If so, it negates the recoding.
        /// Mutates scalars in place
        fn batch_wnaf_opcode_recoding<BigInt: BigInteger>(
            scalars: &mut [BigInt],
            w: usize,
            negate: Option<&[bool]>,
        ) -> Vec<Vec<Option<i16>>> {
            let batch_size = scalars.len();
            let window_size: i16 = 1 << (w + 1);
            let half_window_size: i16 = 1 << w;

            let mut op_code_vectorised = Vec::<Vec<Option<i16>>>::with_capacity(BigInt::NUM_LIMBS * 64);

            let mut all_none = false;

            if negate.is_some() {
                debug_assert_eq!(scalars.len(), negate.unwrap().len());
            }

            let f = false;
            while !all_none {
                let iter = match negate {
                    None => Either::Left(core::iter::repeat(&f).take(batch_size)),
                    Some(bools) => Either::Right(bools.iter()),
                };
                let mut opcode_row = Vec::with_capacity(batch_size);
                for (s, &neg) in scalars.iter_mut().zip(iter) {
                    if s.is_zero() {
                        opcode_row.push(None);
                    } else {
                        let op = if s.is_odd() {
                            // BigIntegers are always of len > 0;
                            let mut z: i16 = (s.as_ref()[0] % (1 << (w + 1))) as i16;
                            if z < half_window_size {
                                s.sub_with_borrow(&BigInt::from(z as u64));
                            } else {
                                z = z - window_size;
                                s.add_with_carry(&BigInt::from((-z) as u64));
                            }
                            if neg { -z } else { z }
                        } else {
                            0
                        };
                        opcode_row.push(Some(op));
                        s.div2();
                    }
                }
                all_none = opcode_row.iter().all(|x| x.is_none());
                if !all_none {
                    op_code_vectorised.push(opcode_row);
                }
            }
            op_code_vectorised
        }

        // We define a series of batched primitive EC ops, each of which is most
        // suitable to a given scenario.
        //
        // We encode the indexes as u32s to save on fetch latency via better cacheing.
        // The principle we are applying is that the len of the batch ops should
        // never exceed about 2^20, and the table size would never exceed 2^10, so
        // 32 bits will always be enough

        /// Mutates bases to be doubled in place
        /// Accepts optional scratch space which might help by reducing the
        /// number of heap allocations for the Vector-based scratch_space
        /// Indices should never be repeated.
        fn batch_double_in_place(
            bases: &mut [Self],
            index: &[u32],
            scratch_space: Option<&mut Vec<Self::BaseFieldForBatch>>,
        );

        /// Mutates bases in place and stores result in the first operand.
        /// The element corresponding to the second operand becomes junk data.
        /// Indices should never be repeated.
        fn batch_add_in_place_same_slice(bases: &mut [Self], index: &[(u32, u32)]);

        /// Mutates bases in place and stores result in bases.
        /// The elements in other become junk data. Indices should never be repeated.
        fn batch_add_in_place(bases: &mut [Self], other: &mut [Self], index: &[(u32, u32)]);

        /// Adds elements in bases with elements in other (for instance, a table),
        /// utilising a scratch space to store intermediate results.

        /// The first index of the tuple should never be repeated.
        fn batch_add_in_place_read_only(
            bases: &mut [Self],
            other: &[Self],
            index: &[(u32, u32)],
            scratch_space: &mut Vec<Self>,
        );

        /// Lookups up group elements according to index, and either adds and writes
        /// or simply writes them to new_elems, using scratch space to store
        /// intermediate values. Scratch space is always cleared after use.

        /// No-ops, or copies of the elem in the slice `lookup` in the position of
        /// the index of the first operand to the new_elems vector, are encoded
        /// as !0u32 in the index for the second operand
        fn batch_add_write(
            lookup: &[Self],
            index: &[(u32, u32)],
            new_elems: &mut Vec<Self>,
            scratch_space: &mut Vec<Option<Self>>,
        );

        /// Similar to batch_add_write, only that the lookup for the first operand
        /// is performed in new_elems rather than lookup

        /// No-ops, or copies of the elem in the slice `lookup` in the position of
        /// the index of the first operand to the new_elems vector, are encoded
        /// as !0u32 in the index for the second operand

        /// Indices corresponding to the first operand should never be repeated.
        fn batch_add_write_read_self(
            lookup: &[Self],
            index: &[(u32, u32)],
            new_elems: &mut Vec<Self>,
            scratch_space: &mut Vec<Option<Self>>,
        );

        /// Performs a batch scalar multiplication using the w-NAF encoding
        /// utilising the primitive batched ops
        fn batch_scalar_mul_in_place<BigInt: BigInteger>(mut bases: &mut [Self], scalars: &mut [BigInt], w: usize) {
            let batch_size = bases.len();
            let opcode_vectorised = Self::batch_wnaf_opcode_recoding::<BigInt>(scalars, w, None);
            let tables = Self::batch_wnaf_tables(bases, w);

            // Set all points to 0;
            let zero = Self::zero();
            for p in bases.iter_mut() {
                *p = zero;
            }

            for opcode_row in opcode_vectorised.iter().rev() {
                let index_double: Vec<_> = opcode_row
                    .iter()
                    .enumerate()
                    .filter(|x| x.1.is_some())
                    .map(|x| x.0 as u32)
                    .collect();

                Self::batch_double_in_place(&mut bases, &index_double[..], None);

                let mut add_ops: Vec<Self> = opcode_row
                    .iter()
                    .enumerate()
                    .filter(|(_, op)| op.is_some() && op.unwrap() != 0)
                    .map(|(i, op)| {
                        let idx = op.unwrap();
                        if idx > 0 {
                            tables[(idx as usize) / 2 * batch_size + i].clone()
                        } else {
                            tables[(-idx as usize) / 2 * batch_size + i].clone().neg()
                        }
                    })
                    .collect();

                let index_add: Vec<_> = opcode_row
                    .iter()
                    .enumerate()
                    .filter(|(_, op)| op.is_some() && op.unwrap() != 0)
                    .map(|x| x.0)
                    .enumerate()
                    .map(|(x, y)| (y as u32, x as u32))
                    .collect();

                Self::batch_add_in_place(&mut bases, &mut add_ops[..], &index_add[..]);
            }
        }

        /// Chunks vectorised instructions into a size that does not require
        /// storing a lot of intermediate state
        fn get_chunked_instr<T: Clone>(instr: &[T], batch_size: usize) -> Vec<Vec<T>> {
            let mut res = Vec::new();

            let rem = instr.chunks_exact(batch_size).remainder();
            let mut chunks = instr.chunks_exact(batch_size).peekable();

            if chunks.len() == 0 {
                res.push(rem.to_vec());
            }

            while let Some(chunk) = chunks.next() {
                let chunk = if chunks.peek().is_none() {
                    [chunk, rem].concat()
                } else {
                    chunk.to_vec()
                };
                res.push(chunk);
            }
            res
        }
    }
}

/// We make the syntax for performing batch ops on slices cleaner
/// by defining a corresponding trait and impl for [G] rather than on G
pub trait BatchGroupArithmeticSlice<G: AffineRepr> {
    fn batch_double_in_place(&mut self, index: &[u32]);

    fn batch_add_in_place_same_slice(&mut self, index: &[(u32, u32)]);

    fn batch_add_in_place(&mut self, other: &mut Self, index: &[(u32, u32)]);

    fn batch_add_write(&self, index: &[(u32, u32)], new_elems: &mut Vec<G>, scratch_space: &mut Vec<Option<G>>);

    fn batch_scalar_mul_in_place<BigInt: BigInteger>(&mut self, scalars: &mut [BigInt], w: usize);
}

impl<G: AffineRepr + BatchGroupArithmetic> BatchGroupArithmeticSlice<G> for [G] {
    fn batch_double_in_place(&mut self, index: &[u32]) {
        #[cfg(all(debug_assertions, feature = "std"))]
        {
            let mut set = std::collections::HashSet::new();
            if !index.into_iter().all(|x| set.insert(*x)) {
                panic!("Indices cannot be repeated");
            }
        }
        G::batch_double_in_place(self, index, None);
    }

    fn batch_add_in_place_same_slice(&mut self, index: &[(u32, u32)]) {
        #[cfg(all(debug_assertions, feature = "std"))]
        {
            let mut set = std::collections::HashSet::new();
            if !index.into_iter().all(|(x, y)| set.insert(*x) && set.insert(*y)) {
                panic!("Indices cannot be repeated");
            }
        }
        G::batch_add_in_place_same_slice(self, index);
    }

    fn batch_add_in_place(&mut self, other: &mut Self, index: &[(u32, u32)]) {
        #[cfg(all(debug_assertions, feature = "std"))]
        {
            let mut set1 = std::collections::HashSet::new();
            let mut set2 = std::collections::HashSet::new();
            if !index.into_iter().all(|(x, y)| set1.insert(*x) && set2.insert(*y)) {
                panic!("Indices cannot be repeated");
            }
        }
        G::batch_add_in_place(self, other, index);
    }

    fn batch_add_write(&self, index: &[(u32, u32)], new_elems: &mut Vec<G>, scratch_space: &mut Vec<Option<G>>) {
        G::batch_add_write(self, index, new_elems, scratch_space);
    }

    fn batch_scalar_mul_in_place<BigInt: BigInteger>(&mut self, scalars: &mut [BigInt], w: usize) {
        G::batch_scalar_mul_in_place(self, scalars, w);
    }
}

#[cfg(test)]
mod tests {
    use std::ops::AddAssign;

    use crate::batch::{bucketed_add::batch_bucketed_add, glv::GLVParameters};
    use ark_ec::{short_weierstrass::SWCurveConfig, twisted_edwards::TECurveConfig, CurveGroup};
    use ark_ff::{BigInteger64, PrimeField};
    use ark_std::{cfg_chunks_mut, UniformRand, Zero};
    use rand::{
        distributions::{Distribution, Uniform},
        Rng,
        SeedableRng,
    };
    use rand_xorshift::XorShiftRng;
    use rayon::{
        iter::{IndexedParallelIterator, ParallelIterator},
        prelude::ParallelSliceMut,
    };

    use super::*;
    use crate::{batch::bucketed_add::BucketPosition, batch_verify_in_subgroup};

    pub const ITERATIONS: usize = 10;
    pub const AFFINE_BATCH_SIZE: usize = 4096;

    fn create_pseudo_uniform_random_elems<C: AffineRepr + BatchGroupArithmetic, R: Rng>(
        rng: &mut R,
        max_logn: usize,
    ) -> Vec<C> {
        const AFFINE_BATCH_SIZE: usize = 4096;
        println!("Starting");
        let now = std::time::Instant::now();
        // Generate pseudorandom group elements
        let step = Uniform::new(0, 1 << (max_logn + 5));
        let elem = C::Group::rand(rng).into_affine();
        let mut random_elems = vec![elem; 1 << max_logn];
        let mut scalars: Vec<BigInteger64> = (0..1 << max_logn).map(|_| (step.sample(rng) as u64).into()).collect();
        cfg_chunks_mut!(random_elems, AFFINE_BATCH_SIZE)
            .zip(cfg_chunks_mut!(scalars, AFFINE_BATCH_SIZE))
            .for_each(|(e, s)| {
                e[..].batch_scalar_mul_in_place::<BigInteger64>(&mut s[..], 1);
            });

        println!("Initial generation: {:?}", now.elapsed().as_micros());
        random_elems
    }

    pub fn random_batch_doubling_test<G: CurveGroup>()
    where
        G::Affine: BatchGroupArithmetic,
    {
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        for j in 0..ITERATIONS {
            let size = std::cmp::min(1 << 7, 1 << (j + 5));
            let mut a = Vec::with_capacity(size);
            let mut b = Vec::with_capacity(size);

            for i in 0..size {
                a.push(G::rand(&mut rng));
                b.push(G::rand(&mut rng));
            }

            let mut c = a.clone();

            let mut a: Vec<G::Affine> = a.iter().map(|p| p.into_affine()).collect();

            a[..].batch_double_in_place(&(0..size).map(|x| x as u32).collect::<Vec<_>>()[..]);

            for p_c in c.iter_mut() {
                *p_c.double_in_place();
            }

            let c: Vec<G::Affine> = c.iter().map(|p| p.into_affine()).collect();

            assert_eq!(a, c);
        }
    }

    pub fn random_batch_addition_test<G: CurveGroup>()
    where
        G::Affine: BatchGroupArithmetic,
    {
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        for j in 0..ITERATIONS {
            let size = std::cmp::min(1 << 7, 1 << (j + 5));
            let mut a = Vec::with_capacity(size);
            let mut b = Vec::with_capacity(size);

            for i in 0..size {
                a.push(G::rand(&mut rng));
                b.push(G::rand(&mut rng));
            }

            let mut c = a.clone();
            let mut d = b.clone();

            let mut a: Vec<G::Affine> = a.iter().map(|p| p.into_affine()).collect();
            let mut b: Vec<G::Affine> = b.iter().map(|p| p.into_affine()).collect();

            a[..].batch_add_in_place(
                &mut b[..],
                &(0..size).map(|x| (x as u32, x as u32)).collect::<Vec<_>>()[..],
            );

            for (p_c, p_d) in c.iter_mut().zip(d.iter()) {
                *p_c += *p_d;
            }

            let c: Vec<G::Affine> = c.iter().map(|p| p.into_affine()).collect();

            assert_eq!(a, c);
        }
    }

    pub fn random_batch_add_doubling_test<G: CurveGroup>()
    where
        G::Affine: BatchGroupArithmetic,
    {
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        for j in 0..ITERATIONS {
            let size = std::cmp::min(1 << 7, 1 << (j + 5));
            let mut a = Vec::<G>::with_capacity(size);
            let mut b = Vec::<G>::with_capacity(size);

            for i in 0..size {
                a.push(G::rand(&mut rng));
            }

            let mut b = a.clone();
            let mut c = a.clone();
            let mut d = b.clone();

            let mut a: Vec<G::Affine> = a.iter().map(|p| p.into_affine()).collect();
            let mut b: Vec<G::Affine> = b.iter().map(|p| p.into_affine()).collect();

            a[..].batch_add_in_place(
                &mut b[..],
                &(0..size).map(|x| (x as u32, x as u32)).collect::<Vec<_>>()[..],
            );

            for (p_c, p_d) in c.iter_mut().zip(d.iter()) {
                *p_c += *p_d;
            }

            let c: Vec<G::Affine> = c.iter().map(|p| p.into_affine()).collect();

            assert_eq!(a, c);
        }
    }

    pub fn random_batch_scalar_mul_test<G: CurveGroup>()
    where
        G::Affine: BatchGroupArithmetic,
    {
        use std::ops::MulAssign;
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        for j in 0..ITERATIONS {
            let size = std::cmp::min(1 << 7, 1 << (j + 4));
            let mut a = Vec::with_capacity(size);
            let mut s = Vec::with_capacity(size);

            for i in 0..size {
                a.push(G::rand(&mut rng));
                s.push(G::ScalarField::rand(&mut rng));
            }

            let mut c = a.clone();
            let mut t = s.clone();

            let mut a: Vec<G::Affine> = a.iter().map(|p| p.into_affine()).collect();

            let mut s: Vec<<G::ScalarField as PrimeField>::BigInt> = s.iter().map(|p| p.into_bigint()).collect();

            let now = std::time::Instant::now();
            a[..].batch_scalar_mul_in_place::<<G::ScalarField as PrimeField>::BigInt>(&mut s[..], 4);
            println!("Batch affine mul for {} elems: {}us", size, now.elapsed().as_micros());

            let now = std::time::Instant::now();
            for (p_c, s_t) in c.iter_mut().zip(t.iter()) {
                p_c.mul_assign(*s_t);
            }
            println!("Proj mul for {} elems: {}us", size, now.elapsed().as_micros());

            let c: Vec<G::Affine> = c.iter().map(|p| p.into_affine()).collect();

            for (p1, p2) in a.iter().zip(c) {
                assert_eq!(*p1, p2);
            }
        }
    }

    fn batch_bucketed_add_test<C: AffineRepr>()
    where
        C: BatchGroupArithmetic,
    {
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        #[cfg(not(feature = "big_n"))]
        const MAX_LOGN: usize = 12;
        #[cfg(feature = "big_n")]
        const MAX_LOGN: usize = 22;

        let random_elems = create_pseudo_uniform_random_elems(&mut rng, MAX_LOGN);

        for i in (MAX_LOGN - 4)..(ITERATIONS / 2 + MAX_LOGN - 4) {
            let n_elems = 1 << i;
            let n_buckets = 1 << (i - 3);

            let mut bucket_assign = Vec::<_>::with_capacity(n_elems);
            let step = Uniform::new(0, n_buckets);

            for i in 0..n_elems {
                bucket_assign.push(BucketPosition {
                    bucket: step.sample(&mut rng) as u32,
                    position: i as u32,
                });
            }

            let mut res1 = vec![];
            let mut elems_mut = random_elems[0..n_elems].to_vec();
            let now = std::time::Instant::now();
            res1 = batch_bucketed_add::<C>(n_buckets, &mut elems_mut[..], &mut bucket_assign.to_vec()[..]);
            println!(
                "batch bucketed add for {} elems: {:?}",
                n_elems,
                now.elapsed().as_micros()
            );

            let mut res2 = vec![C::Group::zero(); n_buckets];
            let mut elems = random_elems[0..n_elems].to_vec();

            let now = std::time::Instant::now();
            for (&bucket_idx, elem) in bucket_assign.iter().zip(elems) {
                res2[bucket_idx.bucket as usize].add_assign(&elem);
            }
            println!("bucketed add for {} elems: {:?}", n_elems, now.elapsed().as_micros());

            let res1: Vec<C::Group> = res1.iter().map(|&p| p.into()).collect();

            for (i, (p1, p2)) in res1.iter().zip(res2).enumerate() {
                assert_eq!(*p1, p2);
            }
        }
    }

    macro_rules! batch_verify_test {
        ($P: ident, $GroupAffine: ident, $GroupProjective: ident, $name: ident) => {
            let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

            #[cfg(not(feature = "big_n"))]
            const MAX_LOGN: usize = 14;
            #[cfg(feature = "big_n")]
            const MAX_LOGN: usize = 22;

            const SECURITY_PARAM: usize = 128;
            // Generate pseudorandom group elements
            let random_elems: Vec<$GroupAffine<P>> = create_pseudo_uniform_random_elems(&mut rng, MAX_LOGN);

            let now = std::time::Instant::now();
            let mut non_subgroup_points = Vec::with_capacity(1 << 10);
            while non_subgroup_points.len() < 1 << 10 {
                if let Some(elem) = $GroupAffine::<P>::$name($P::BaseField::rand(&mut rng), false)
                {
                    // If the cofactor is small, with non-negligible probability the sampled point
                    // is in the group, so we should check it isn't. Else we don't waste compute.
                    if $P::COFACTOR[1..].iter().all(|&x| x == 0u64) {
                        if !elem.is_in_correct_subgroup_assuming_on_curve() {
                            non_subgroup_points.push(elem);
                        }
                    } else {
                        non_subgroup_points.push(elem);
                    }
                }
            }
            println!(
                "Generate non-subgroup points: {:?}",
                now.elapsed().as_micros()
            );

            println!("Security Param: {}", SECURITY_PARAM);
            let mut estimated_timing = 0;
            for i in (MAX_LOGN - 4)..(ITERATIONS / 2 + MAX_LOGN - 4) {
                let n_elems = 1 << i;
                println!("n: {}", n_elems);

                if i == MAX_LOGN - 4 {
                    let mut tmp_elems_for_naive = random_elems[0..n_elems].to_vec();
                    let now = std::time::Instant::now();
                    cfg_chunks_mut!(tmp_elems_for_naive, AFFINE_BATCH_SIZE).map(|e| {
                        // Probably could optimise this further: single scalar
                        // We also need to make GLV work with the characteristic
                        let size = e.len();
                        e[..].batch_scalar_mul_in_place::<<<$GroupAffine<P> as AffineRepr>::ScalarField as PrimeField>::BigInt>(
                            &mut vec![<<$GroupAffine<P> as AffineRepr>::ScalarField as PrimeField>::MODULUS; size][..],
                            4,
                        );
                        e.iter().all(|p| p.is_zero())
                    })
                    .all(|b| b);

                    estimated_timing = now.elapsed().as_micros();
                    println!(
                        "Success: In Subgroup. n: {}, time: {} (naive)",
                        n_elems,
                        estimated_timing
                    );
                } else {
                    estimated_timing *= 2;
                    println!(
                        "Estimated timing for n: {}, time: {} (naive)",
                        n_elems,
                        estimated_timing
                    );
                }

                let random_location = Uniform::new(0, n_elems);
                let mut tmp_elems = random_elems[0..n_elems].to_vec();

                let now = std::time::Instant::now();
                batch_verify_in_subgroup::<$GroupAffine<P>, XorShiftRng>(&tmp_elems[..], SECURITY_PARAM, &mut rng)
                    .expect("Should have verified as correct");
                println!(
                    "Success: In Subgroup. n: {}, time: {}",
                    n_elems,
                    now.elapsed().as_micros()
                );

                for j in 0..10 {
                    // Randomly insert random non-subgroup elems
                    for k in 0..(1 << j) {
                        tmp_elems[random_location.sample(&mut rng)] = non_subgroup_points[k];
                    }
                    let now = std::time::Instant::now();
                    match batch_verify_in_subgroup::<$GroupAffine<P>, XorShiftRng>(&tmp_elems[..], SECURITY_PARAM, &mut rng) {
                        Ok(_) => assert!(false, "did not detect non-subgroup elems"),
                        _ => assert!(true),
                    };
                    println!(
                        "Success: Not in subgroup. n: {}, non-subgroup elems: {}, time: {}",
                        n_elems,
                        (1 << (j + 1)) - 1,
                        now.elapsed().as_micros()
                    );
                }
            }

            // // We can induce a collision and thus failure to identify non-subgroup elements with the following
            // // for small security parameters. This is a non-deterministic "anti-test" that should fail and cause
            // // panic. It is meant for sanity checking.
            // for j in 0..10000 {
            //     // Randomly insert random non-subgroup elems
            //     if j == 0 {
            //         for _ in 0..(1 << j) {
            //             loop {
            //                 if let Some(non_subgroup_elem) =
            //                     GroupAffine::<P>::get_point_from_x(P::BaseField::rand(&mut rng), false)
            //                 {
            //                     tmp_elems[random_location.sample(&mut rng)] = non_subgroup_elem;
            //                     tmp_elems[random_location.sample(&mut rng) + 1] = non_subgroup_elem.neg();
            //                     break;
            //                 }
            //             }
            //         }
            //     }
            //     let now = std::time::Instant::now();
            //     match batch_verify_in_subgroup::<GroupAffine<P>>(&tmp_elems[..], SECURITY_PARAM) {
            //         Ok(_) => assert!(false, "did not detect non-subgroup elems"),
            //         _ => assert!(true),
            //     };
            //     println!(
            //         "Success: Not in subgroup. n: {}, non-subgroup elems: {}, time: {}",
            //         n_elems,
            //         (1 << (j + 1)) - 1,
            //         now.elapsed().as_micros()
            //     );
            // }
        }
    }

    fn sw_batch_verify_test<P: SWCurveConfig + GLVParameters>() {
        use ark_ec::short_weierstrass::{Affine, Projective};
        batch_verify_test!(P, Affine, Projective, get_point_from_x_unchecked);
    }

    fn te_batch_verify_test<P: TECurveConfig + GLVParameters>() {
        use ark_ec::twisted_edwards::{Affine, Projective};
        batch_verify_test!(P, Affine, Projective, get_point_from_y_unchecked);
    }

    #[test]
    fn test_batch_bls12_377() {
        use ark_bls12_377::{
            g1::Config as G1Config,
            g2::Config as G2Config,
            G1Affine,
            G1Projective,
            G2Affine,
            G2Projective,
        };

        random_batch_doubling_test::<G1Projective>();
        random_batch_addition_test::<G1Projective>();
        random_batch_add_doubling_test::<G1Projective>();
        random_batch_scalar_mul_test::<G1Projective>();
        batch_bucketed_add_test::<G1Affine>();
        sw_batch_verify_test::<G1Config>();

        random_batch_doubling_test::<G2Projective>();
        random_batch_addition_test::<G2Projective>();
        random_batch_add_doubling_test::<G2Projective>();
        random_batch_scalar_mul_test::<G2Projective>();
        batch_bucketed_add_test::<G2Affine>();
        sw_batch_verify_test::<G2Config>();
    }

    #[test]
    fn test_batch_bls12_381() {
        use ark_bls12_381::{
            g1::Config as G1Config,
            g2::Config as G2Config,
            G1Affine,
            G1Projective,
            G2Affine,
            G2Projective,
        };

        random_batch_doubling_test::<G1Projective>();
        random_batch_addition_test::<G1Projective>();
        random_batch_add_doubling_test::<G1Projective>();
        random_batch_scalar_mul_test::<G1Projective>();
        batch_bucketed_add_test::<G1Affine>();
        sw_batch_verify_test::<G1Config>();

        random_batch_doubling_test::<G2Projective>();
        random_batch_addition_test::<G2Projective>();
        random_batch_add_doubling_test::<G2Projective>();
        random_batch_scalar_mul_test::<G2Projective>();
        batch_bucketed_add_test::<G2Affine>();
        sw_batch_verify_test::<G2Config>();
    }

    #[test]
    fn test_batch_bw6_761() {
        use ark_bw6_761::{
            g1::Config as G1Config,
            g2::Config as G2Config,
            G1Affine,
            G1Projective,
            G2Affine,
            G2Projective,
        };

        random_batch_doubling_test::<G1Projective>();
        random_batch_addition_test::<G1Projective>();
        random_batch_add_doubling_test::<G1Projective>();
        random_batch_scalar_mul_test::<G1Projective>();
        batch_bucketed_add_test::<G1Affine>();
        sw_batch_verify_test::<G1Config>();

        random_batch_doubling_test::<G2Projective>();
        random_batch_addition_test::<G2Projective>();
        random_batch_add_doubling_test::<G2Projective>();
        random_batch_scalar_mul_test::<G2Projective>();
        batch_bucketed_add_test::<G2Affine>();
        sw_batch_verify_test::<G2Config>();
    }
}
