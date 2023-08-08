use std::ops::Neg;

use crate::batch::arith::decode_endo_from_u32;

use super::arith::internal::BatchGroupArithmetic;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ff::Field;
use ark_std::{One, Zero as OtherZero};

macro_rules! batch_add_loop_1 {
    ($a: ident, $b: ident, $inversion_tmp: ident) => {
        if $a.is_zero() || $b.is_zero() {
            continue;
        } else {
            let y1y2 = $a.y * &$b.y;
            let x1x2 = $a.x * &$b.x;

            $a.x = ($a.x + &$a.y) * &($b.x + &$b.y) - &y1y2 - &x1x2;
            $a.y = y1y2;
            if !P::COEFF_A.is_zero() {
                $a.y -= &P::mul_by_a(x1x2);
            }

            let dx1x2y1y2 = P::COEFF_D * &y1y2 * &x1x2;

            let inversion_mul_d = $inversion_tmp * &dx1x2y1y2;

            $a.x *= &($inversion_tmp - &inversion_mul_d);
            $a.y *= &($inversion_tmp + &inversion_mul_d);

            $b.x = P::BaseField::one() - &dx1x2y1y2.square();

            $inversion_tmp *= &$b.x;
        }
    };
}

macro_rules! batch_add_loop_2 {
    ($a: ident, $b: ident, $inversion_tmp: ident) => {
        if $a.is_zero() {
            *$a = $b;
        } else if !$b.is_zero() {
            $a.x *= &$inversion_tmp;
            $a.y *= &$inversion_tmp;

            $inversion_tmp *= &$b.x;
        }
    };
}

impl<P: TECurveConfig> BatchGroupArithmetic for Affine<P> {
    type BaseFieldForBatch = P::BaseField;

    fn batch_double_in_place(
        bases: &mut [Self],
        index: &[u32],
        _scratch_space: Option<&mut Vec<Self::BaseFieldForBatch>>,
    ) {
        Self::batch_add_in_place(
            bases,
            &mut bases.to_vec()[..],
            &index.iter().map(|&x| (x, x)).collect::<Vec<_>>()[..],
        );
    }

    // Total cost: 12 mul. Projective formulas: 11 mul.
    fn batch_add_in_place_same_slice(bases: &mut [Self], index: &[(u32, u32)]) {
        let mut inversion_tmp = P::BaseField::one();
        // We run two loops over the data separated by an inversion
        for (idx, idy) in index.iter() {
            let (mut a, mut b) = if idx < idy {
                let (x, y) = bases.split_at_mut(*idy as usize);
                (&mut x[*idx as usize], &mut y[0])
            } else {
                let (x, y) = bases.split_at_mut(*idx as usize);
                (&mut y[0], &mut x[*idy as usize])
            };
            batch_add_loop_1!(a, b, inversion_tmp);
        }

        inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

        for (idx, idy) in index.iter().rev() {
            let (a, b) = if idx < idy {
                let (x, y) = bases.split_at_mut(*idy as usize);
                (&mut x[*idx as usize], y[0])
            } else {
                let (x, y) = bases.split_at_mut(*idx as usize);
                (&mut y[0], x[*idy as usize])
            };
            batch_add_loop_2!(a, b, inversion_tmp);
        }
    }

    // Total cost: 12 mul. Projective formulas: 11 mul.
    fn batch_add_in_place(bases: &mut [Self], other: &mut [Self], index: &[(u32, u32)]) {
        let mut inversion_tmp = P::BaseField::one();
        // We run two loops over the data separated by an inversion
        for (idx, idy) in index.iter() {
            let (mut a, mut b) = (&mut bases[*idx as usize], &mut other[*idy as usize]);
            batch_add_loop_1!(a, b, inversion_tmp);
        }

        inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

        for (idx, idy) in index.iter().rev() {
            let (a, b) = (&mut bases[*idx as usize], other[*idy as usize]);
            batch_add_loop_2!(a, b, inversion_tmp);
        }
    }

    #[inline]
    fn batch_add_in_place_read_only(
        bases: &mut [Self],
        other: &[Self],
        index: &[(u32, u32)],
        scratch_space: &mut Vec<Self>,
    ) {
        let mut inversion_tmp = P::BaseField::one();
        // We run two loops over the data separated by an inversion
        for (idx, idy) in index.iter() {
            let (idy, endomorphism) = decode_endo_from_u32(*idy);
            let mut a = &mut bases[*idx as usize];
            // Apply endomorphisms according to encoding
            let mut b = if endomorphism % 2 == 1 {
                other[idy].neg()
            } else {
                other[idy]
            };

            batch_add_loop_1!(a, b, inversion_tmp);
            scratch_space.push(b);
        }

        inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

        for (idx, _) in index.iter().rev() {
            let (a, b) = (&mut bases[*idx as usize], scratch_space.pop().unwrap());
            batch_add_loop_2!(a, b, inversion_tmp);
        }
    }

    fn batch_add_write(
        lookup: &[Self],
        index: &[(u32, u32)],
        new_elems: &mut Vec<Self>,
        scratch_space: &mut Vec<Option<Self>>,
    ) {
        let mut inversion_tmp = P::BaseField::one();

        for (idx, idy) in index.iter() {
            if *idy == !0u32 {
                new_elems.push(lookup[*idx as usize]);
                scratch_space.push(None);
            } else {
                let (mut a, mut b) = (lookup[*idx as usize], lookup[*idy as usize]);
                batch_add_loop_1!(a, b, inversion_tmp);
                new_elems.push(a);
                scratch_space.push(Some(b));
            }
        }

        inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

        for (a, op_b) in new_elems.iter_mut().rev().zip(scratch_space.iter().rev()) {
            match op_b {
                Some(b) => {
                    let b_ = *b;
                    batch_add_loop_2!(a, b_, inversion_tmp);
                }
                None => (),
            };
        }
        scratch_space.clear();
    }

    fn batch_add_write_read_self(
        lookup: &[Self],
        index: &[(u32, u32)],
        new_elems: &mut Vec<Self>,
        scratch_space: &mut Vec<Option<Self>>,
    ) {
        let mut inversion_tmp = P::BaseField::one();

        for (idx, idy) in index.iter() {
            if *idy == !0u32 {
                new_elems.push(lookup[*idx as usize]);
                scratch_space.push(None);
            } else {
                let (mut a, mut b) = (new_elems[*idx as usize], lookup[*idy as usize]);
                batch_add_loop_1!(a, b, inversion_tmp);
                new_elems.push(a);
                scratch_space.push(Some(b));
            }
        }

        inversion_tmp = inversion_tmp.inverse().unwrap(); // this is always in Fp*

        for (a, op_b) in new_elems.iter_mut().rev().zip(scratch_space.iter().rev()) {
            match op_b {
                Some(b) => {
                    let b_ = *b;
                    batch_add_loop_2!(a, b_, inversion_tmp);
                }
                None => (),
            };
        }
        scratch_space.clear();
    }
}
