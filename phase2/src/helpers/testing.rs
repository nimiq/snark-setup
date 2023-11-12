use std::marker::PhantomData;

use ark_crypto_primitives::crh::sha256::{constraints::*, digest::Digest, Sha256};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_r1cs_std::{bits::uint8::UInt8, prelude::EqGadget};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

// circuit proving knowledge of a square root
// when generating the Setup, the element inside is None
#[derive(Clone, Debug)]
pub struct TestHashCircuit<E: Pairing>(pub Vec<u8>, pub PhantomData<E>);
impl<E: Pairing> ConstraintSynthesizer<E::ScalarField> for TestHashCircuit<E> {
    fn generate_constraints(self, cs: ConstraintSystemRef<E::ScalarField>) -> std::result::Result<(), SynthesisError> {
        // allocate a private input `x`
        let x = UInt8::new_witness_vec(cs.clone(), &self.0)?;

        // input
        let out = UInt8::new_input_vec(cs.clone(), &Sha256::digest(&self.0))?;

        let h = Sha256Gadget::digest(&x)?;
        h.0.enforce_equal(&out)?;

        Ok(())
    }
}

// circuit proving knowledge of a hash pre-image
#[derive(Clone, Debug)]
pub struct TestCircuit<E: Pairing>(pub Option<E::ScalarField>);
impl<E: Pairing> ConstraintSynthesizer<E::ScalarField> for TestCircuit<E> {
    fn generate_constraints(self, cs: ConstraintSystemRef<E::ScalarField>) -> std::result::Result<(), SynthesisError> {
        // allocate a private input `x`
        // this can be made public with `alloc_input`, which would then require
        // that the verifier provides it
        let x = cs
            .new_witness_variable(|| self.0.ok_or(SynthesisError::AssignmentMissing))
            .unwrap();
        // 1 input!
        let out = cs
            .new_input_variable(|| self.0.map(|x| x.square()).ok_or(SynthesisError::AssignmentMissing))
            .unwrap();
        // x * x = x^2
        for _ in 0..4 {
            cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + out)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_groth16::{prepare_verifying_key, Groth16};

    // no need to run these tests, they're just added as a guideline for how to
    // consume the circuit
    #[test]
    fn test_square_root() {
        test_square_root_curve::<Bls12_377>()
    }

    fn test_square_root_curve<E: Pairing>() {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut rand::thread_rng();
        // Create parameters for our circuit
        let params = {
            let c = TestCircuit::<E>(None);
            Groth16::<E>::generate_random_parameters_with_reduction(c, rng).unwrap()
        };
        let pvk = prepare_verifying_key(&params.vk);

        // we know the square root of 25 -> 5
        let out = <E::ScalarField as From<u64>>::from(25);
        let input = <E::ScalarField as From<u64>>::from(5);

        // Prover instantiates the circuit and creates a proof
        // with his RNG
        let c = TestCircuit::<E>(Some(input));
        let proof = Groth16::<E>::create_random_proof_with_reduction(c, &params, rng).unwrap();

        // Verifier only needs to know 25 (the output, aka public input),
        // the vk and the proof!
        assert!(Groth16::<E>::verify_proof(&pvk, &proof, &[out]).unwrap());
    }
}
