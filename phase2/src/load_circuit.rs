use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintMatrices, Matrix};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use setup_utils::Error;

// For serialization of the constraint system
#[derive(Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct Matrices<E: Pairing> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,
    /// The number of non_zero entries in the A matrix.
    pub a_num_non_zero: usize,
    /// The number of non_zero entries in the B matrix.
    pub b_num_non_zero: usize,
    /// The number of non_zero entries in the C matrix.
    pub c_num_non_zero: usize,
    /// The A constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub a: Matrix<E::ScalarField>,
    /// The B constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub b: Matrix<E::ScalarField>,
    /// The C constraint matrix. This is empty when
    /// `self.mode == SynthesisMode::Prove { construct_matrices = false }`.
    pub c: Matrix<E::ScalarField>,
}

impl<E: Pairing> Matrices<E> {
    pub fn read(input_map: &[u8]) -> Result<Self, Error> {
        Ok(Matrices::deserialize_compressed(&mut &input_map[..])?)
    }
}

impl<E: Pairing> From<ConstraintMatrices<E::ScalarField>> for Matrices<E> {
    fn from(value: ConstraintMatrices<E::ScalarField>) -> Self {
        Self {
            num_instance_variables: value.num_instance_variables,
            num_witness_variables: value.num_witness_variables,
            num_constraints: value.num_constraints,
            a_num_non_zero: value.a_num_non_zero,
            b_num_non_zero: value.b_num_non_zero,
            c_num_non_zero: value.c_num_non_zero,
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}
