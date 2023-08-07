use ark_bls12_377::{g1::Config as G1Config, g2::Config as G2Config, Fq, Fq2, Fr};
use ark_ff::{BigInt, BigInteger256, BigInteger384, PrimeField};

use crate::batch::glv::GLVParameters;

impl GLVParameters for G1Config {
    type WideBigInt = BigInt<8>;

    const B1: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger256::new([725501752471715841, 4981570305181876225, 0, 0]);
    const B1_IS_NEG: bool = false;
    const B2: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([1, 0, 0, 0]);
    const LAMBDA: Self::ScalarField = Fr::new(BigInteger256::new([
        12574070832645531618,
        10005695704657941814,
        1564543351912391449,
        657300228442948690,
    ]));
    const OMEGA: Self::BaseField = Fq::new(BigInteger384::new([
        15766275933608376691,
        15635974902606112666,
        1934946774703877852,
        18129354943882397960,
        15437979634065614942,
        101285514078273488,
    ]));
    /// |round(B2 * R / n)|
    const Q1: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([13, 0, 0, 0]);
    /// |round(B1 * R / n)|
    const Q2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger256::new([9183663392111466540, 12968021215939883360, 3, 0]);
    const R_BITS: u32 = 256;
}

impl GLVParameters for G2Config {
    type WideBigInt = BigInt<8>;

    const B1: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger256::new([725501752471715841, 4981570305181876225, 0, 0]);
    const B1_IS_NEG: bool = false;
    const B2: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([1, 0, 0, 0]);
    const LAMBDA: Self::ScalarField = Fr::new(BigInteger256::new([
        12574070832645531618,
        10005695704657941814,
        1564543351912391449,
        657300228442948690,
    ]));
    const OMEGA: Self::BaseField = Fq2::new(
        Fq::new(BigInteger384::new([
            3203870859294639911,
            276961138506029237,
            9479726329337356593,
            13645541738420943632,
            7584832609311778094,
            101110569012358506,
        ])),
        Fq::new(BigInteger384::new([0, 0, 0, 0, 0, 0])),
    );
    /// |round(B2 * R / n)|
    const Q1: <Self::ScalarField as PrimeField>::BigInt = BigInteger256::new([13, 0, 0, 0]);
    /// |round(B1 * R / n)|
    const Q2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger256::new([9183663392111466540, 12968021215939883360, 3, 0]);
    const R_BITS: u32 = 256;
}
