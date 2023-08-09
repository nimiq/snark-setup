use crate::Phase1Parameters;
use setup_utils::{BatchGroupArithmetic, Error, UseCompression};

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<E: Pairing>
where
    E::G1Affine: BatchGroupArithmetic,
    E::G2Affine: BatchGroupArithmetic,
{
    pub tau_g1: (E::G1Affine, E::G1Affine),
    pub alpha_g1: (E::G1Affine, E::G1Affine),
    pub beta_g1: (E::G1Affine, E::G1Affine),
    pub tau_g2: E::G2Affine,
    pub alpha_g2: E::G2Affine,
    pub beta_g2: E::G2Affine,
}

impl<E: Pairing> PartialEq for PublicKey<E>
where
    E::G1Affine: BatchGroupArithmetic,
    E::G2Affine: BatchGroupArithmetic,
{
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.tau_g1.0 == other.tau_g1.0
            && self.tau_g1.1 == other.tau_g1.1
            && self.alpha_g1.0 == other.alpha_g1.0
            && self.alpha_g1.1 == other.alpha_g1.1
            && self.beta_g1.0 == other.beta_g1.0
            && self.beta_g1.1 == other.beta_g1.1
            && self.tau_g2 == other.tau_g2
            && self.alpha_g2 == other.alpha_g2
            && self.beta_g2 == other.beta_g2
    }
}

impl<E: Pairing> PublicKey<E>
where
    E::G1Affine: BatchGroupArithmetic,
    E::G2Affine: BatchGroupArithmetic,
{
    /// Writes the key to the memory map (takes into account offsets)
    pub fn write(
        &self,
        output_map: &mut [u8],
        accumulator_was_compressed: UseCompression,
        parameters: &Phase1Parameters<E>,
    ) -> Result<(), Error> {
        let position = match accumulator_was_compressed {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
            UseCompression::No => parameters.accumulator_size,
        };
        // Write the public key after the provided position
        self.serialize_compressed(&mut output_map[position..].as_mut())?;

        Ok(())
    }

    /// Deserialize the public key from the memory map (takes into account offsets)
    pub fn read(
        input_map: &[u8],
        accumulator_was_compressed: UseCompression,
        parameters: &Phase1Parameters<E>,
    ) -> Result<Self, Error> {
        let position = match accumulator_was_compressed {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
            UseCompression::No => parameters.accumulator_size,
        };
        // The public key is written after the provided position
        Ok(PublicKey::deserialize_compressed(&mut &input_map[position..])?)
    }
}
