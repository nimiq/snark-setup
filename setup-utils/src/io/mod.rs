//! Utilities for writing and reading group elements to buffers compressed and uncompressed
mod read;
pub use read::{BatchDeserializer, Deserializer};

mod write;
pub use write::{BatchSerializer, Serializer};

use crate::UseCompression;
use ark_ec::AffineRepr;

pub fn buffer_size<C: AffineRepr>(compression: UseCompression) -> usize {
    C::default().serialized_size(compression)
}

#[cfg(test)]
mod tests {
    use super::*;
    use phase1::helpers::testing::random_point_vec;

    use ark_ec::models::bls12::{G1Affine, G2Affine};

    use crate::CheckForCorrectness;
    use rand::thread_rng;

    #[test]
    fn read_write_single() {
        read_write_single_element::<G1Affine>(UseCompression::No);
        read_write_single_element::<G1Affine>(UseCompression::Yes);
        read_write_single_element::<G2Affine>(UseCompression::No);
        read_write_single_element::<G2Affine>(UseCompression::Yes);
    }

    #[test]
    fn read_write_single_preallocated() {
        read_write_single_element_preallocated::<G1Affine>(UseCompression::No);
        read_write_single_element_preallocated::<G1Affine>(UseCompression::Yes);
        read_write_single_element_preallocated::<G2Affine>(UseCompression::No);
        read_write_single_element_preallocated::<G2Affine>(UseCompression::Yes);
    }

    #[test]
    fn read_write_batch() {
        read_write_batch_element::<G1Affine>(UseCompression::No);
        read_write_batch_element::<G1Affine>(UseCompression::Yes);
        read_write_batch_element::<G2Affine>(UseCompression::No);
        read_write_batch_element::<G2Affine>(UseCompression::Yes);
    }

    #[test]
    fn read_write_batch_preallocated() {
        read_write_batch_element_preallocated::<G1Affine>(UseCompression::No);
        read_write_batch_element_preallocated::<G1Affine>(UseCompression::Yes);
        read_write_batch_element_preallocated::<G2Affine>(UseCompression::No);
        read_write_batch_element_preallocated::<G2Affine>(UseCompression::Yes);
    }

    fn read_write_single_element<E: AffineRepr>(compression: UseCompression) {
        // uncompressed buffers are twice the size
        let el = E::prime_subgroup_generator();
        let mut buf = vec![];
        // assert that the deserialized version is the same as the serialized
        buf.write_element(&el, compression).unwrap();
        let deserialized: E = buf.read_element(compression, CheckForCorrectness::No).unwrap();
        assert_eq!(el, deserialized);
    }

    fn read_write_single_element_preallocated<E: AffineRepr>(compression: UseCompression) {
        // uncompressed buffers are twice the size
        let mut prealloc = E::zero();
        let el = E::prime_subgroup_generator();
        let mut buf = vec![];
        // assert that the deserialized version is the same as the serialized
        buf.write_element(&el, compression).unwrap();
        buf.read_element_preallocated(&mut prealloc, compression, CheckForCorrectness::No)
            .unwrap();
        assert_eq!(el, prealloc);
    }

    fn read_write_batch_element<E: AffineRepr>(compression: UseCompression) {
        // generate a vector of 10 elements
        let num_els = 10;
        let mut rng = thread_rng();
        let elements: Vec<E> = random_point_vec(num_els, &mut rng);
        let len = buffer_size::<E>(compression);
        let len = len * num_els;
        let mut buf = vec![0; len];
        buf.write_batch(&elements, compression).unwrap();
        let deserialized1: Vec<E> = buf.read_batch(compression, CheckForCorrectness::No).unwrap();
        let deserialized2: Vec<E> = buf.read_batch(compression, CheckForCorrectness::No).unwrap();
        assert_eq!(elements, deserialized1);
        assert_eq!(elements, deserialized2);
    }

    fn read_write_batch_element_preallocated<E: AffineRepr>(compression: UseCompression) {
        // generate a vector of 10 elements
        let num_els = 10;
        let mut rng = thread_rng();
        let elements: Vec<E> = random_point_vec(num_els, &mut rng);
        // generate another preallocated vector
        let len = buffer_size::<E>(compression);
        let len = len * num_els;
        let mut buf = vec![0; len];
        buf.write_batch(&elements, compression).unwrap();
        let mut prealloc: Vec<E> = random_point_vec(num_els, &mut rng);
        let mut prealloc2: Vec<E> = random_point_vec(num_els, &mut rng);
        buf.read_batch_preallocated(&mut prealloc, compression, CheckForCorrectness::No)
            .unwrap();
        buf.read_batch_preallocated(&mut prealloc2, compression, CheckForCorrectness::No)
            .unwrap();
        assert_eq!(elements, prealloc);
        assert_eq!(elements, prealloc2);
    }
}
