use ark_ff::{biginteger::arithmetic::mac_with_carry, BigInteger};

/// Takes two slices of u64 representing big integers and returns a bigger
/// BigInteger of type Self representing their product. Preferably used
/// only for even NUM_LIMBS. We require the invariant that this.len() ==
/// other.len() == NUM_LIMBS / 2
#[inline]
pub(crate) fn mul_no_reduce<T: BigInteger>(this: &[u64], other: &[u64]) -> T {
    assert!(this.len() == T::NUM_LIMBS / 2);
    assert!(other.len() == T::NUM_LIMBS / 2);

    let mut result = T::default();
    let mut r = result.as_mut();

    for i in 0..T::NUM_LIMBS / 2 {
        let mut carry = 0u64;
        for j in 0..T::NUM_LIMBS / 2 {
            r[j + i] = mac_with_carry(r[j + i], this[i], other[j], &mut carry);
        }
        r[T::NUM_LIMBS / 2 + i] = carry;
    }

    result
}

/// Similar to `mul_no_reduce` but accepts slices of len == NUM_LIMBS and
/// only returns lower half of the result
#[inline]
pub(crate) fn mul_no_reduce_lo<T: BigInteger>(this: &[u64], other: &[u64]) -> T {
    assert!(this.len() == T::NUM_LIMBS);
    assert!(other.len() == T::NUM_LIMBS);

    let mut result = T::default();
    let mut r = result.as_mut();

    for i in 0..T::NUM_LIMBS {
        let mut carry = 0u64;
        for j in 0..(T::NUM_LIMBS - i) {
            r[j + i] = mac_with_carry(r[j + i], this[i], other[j], &mut carry);
        }
    }

    result
}
