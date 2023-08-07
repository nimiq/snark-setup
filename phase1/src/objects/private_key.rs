use ark_ec::pairing::Pairing;

/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
#[derive(PartialEq, Debug)]
pub struct PrivateKey<E: Pairing> {
    pub tau: E::ScalarField,
    pub alpha: E::ScalarField,
    pub beta: E::ScalarField,
}
