use ark_bls12_381::{g1::Config as G1Config, g2::Config as G2Config, Fq, Fq2, Fr};
use ark_ff::{BigInt, BigInteger256, BigInteger384, PrimeField};

use crate::batch::glv::GLVParameters;

impl GLVParameters for G1Config {
    type WideBigInt = BigInt<8>;

    const B1: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([4294967295, 12413508272118670338, 0, 0]);
    const B1_IS_NEG: bool = true;
    const B2: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([1, 0, 0, 0]);
    const LAMBDA: Self::ScalarField = Fr::new(BigInteger256::new([
        7865245318337523249,
        18346590209729131401,
        15545362854776399464,
        6505881510324251116,
    ]));
    const OMEGA: Self::BaseField = Fq::new(BigInteger384::new([
        3526659474838938856,
        17562030475567847978,
        1632777218702014455,
        14009062335050482331,
        3906511377122991214,
        368068849512964448,
    ]));
    /// |round(B2 * R / n)|
    const Q1: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([2, 0, 0, 0]);
    /// |round(B1 * R / n)|
    const Q2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger256::new([7203196592358157870, 8965520006802549469, 1, 0]);
    const R_BITS: u32 = 256;
}

impl GLVParameters for G2Config {
    type WideBigInt = BigInt<8>;

    const B1: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([4294967295, 12413508272118670338, 0, 0]);
    const B1_IS_NEG: bool = true;
    const B2: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([1, 0, 0, 0]);
    const LAMBDA: Self::ScalarField = Fr::new(BigInteger256::new([
        7865245318337523249,
        18346590209729131401,
        15545362854776399464,
        6505881510324251116,
    ]));
    const OMEGA: Self::BaseField = Fq2::new(
        Fq::new(BigInteger384::new([
            14772873186050699377,
            6749526151121446354,
            6372666795664677781,
            10283423008382700446,
            286397964926079186,
            1796971870900422465,
        ])),
        Fq::new(BigInteger384::new([0, 0, 0, 0, 0, 0])),
    );
    /// |round(B2 * R / n)|
    const Q1: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([2, 0, 0, 0]);
    /// |round(B1 * R / n)|
    const Q2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger256::new([7203196592358157870, 8965520006802549469, 1, 0]);
    const R_BITS: u32 = 256;
}
