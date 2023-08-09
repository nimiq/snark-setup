use ark_bw6_761::{g1::Config as G1Config, g2::Config as G2Config, Fq, Fr};
use ark_ff::{BigInteger384, BigInteger768, PrimeField};

use crate::batch::glv::GLVParameters;

/// The parameters can be obtained from
/// Optimized and secure pairing-friendly elliptic
/// curves suitable for one layer proof composition
/// Youssef El Housni and Aurore Guillevic, 2020.
/// https://eprint.iacr.org/2020/351.pdf
/// and the precomputed parameters Qi, Bi, *_IS_NEG can be obtained from
/// scripts/glv_lattice_basis
impl GLVParameters for G1Config {
    type WideBigInt = BigInteger768;

    const B1: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([6390748608727089153, 3321046870121250816, 862915519668593664, 0, 0, 0]);
    const B1_IS_NEG: bool = true;
    const B2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([15251369769346007039, 3321046870121250815, 862915519668593664, 0, 0, 0]);
    /// lambda in Z s.t. phi(P) = lambda*P for all P
    /// \lambda = 0x9b3af05dd14f6ec619aaf7d34594aabc5ed1347970dec00452217cc900000008508c00000000001
    const LAMBDA: Self::ScalarField = Fr::new(BigInteger384::new([
        15766275933608376691,
        15635974902606112666,
        1934946774703877852,
        18129354943882397960,
        15437979634065614942,
        101285514078273488,
    ]));
    /// phi((x, y)) = (\omega x, y)
    /// \omega = 0x531dc16c6ecd27aa846c61024e4cca6c1f31e53bd9603c2d17be416c5e44
    /// 26ee4a737f73b6f952ab5e57926fa701848e0a235a0a398300c65759fc4518315
    /// 1f2f082d4dcb5e37cb6290012d96f8819c547ba8a4000002f962140000000002a
    const OMEGA: Fq = Fq::new(BigInteger768::new([
        7467050525960156664,
        11327349735975181567,
        4886471689715601876,
        825788856423438757,
        532349992164519008,
        5190235139112556877,
        10134108925459365126,
        2188880696701890397,
        14832254987849135908,
        2933451070611009188,
        11385631952165834796,
        64130670718986244,
    ]));
    /// |round(B2 * R / n)|
    const Q1: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([8993470605275773807, 4826578625773784734, 2319558931065627696, 7, 0, 0]);
    /// |round(B1 * R / n)|
    const Q2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([11941976086484053770, 4826578625773784813, 2319558931065627696, 7, 0, 0]);
    const R_BITS: u32 = 384;
}

impl GLVParameters for G2Config {
    type WideBigInt = BigInteger768;

    const B1: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([6390748608727089153, 3321046870121250816, 862915519668593664, 0, 0, 0]);
    const B1_IS_NEG: bool = true;
    const B2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([15251369769346007039, 3321046870121250815, 862915519668593664, 0, 0, 0]);
    /// lambda in Z s.t. phi(P) = lambda*P for all P
    /// \lambda = 0x9b3af05dd14f6ec619aaf7d34594aabc5ed1347970dec00452217cc900000008508c00000000001
    const LAMBDA: Self::ScalarField = Fr::new(BigInteger384::new([
        15766275933608376691,
        15635974902606112666,
        1934946774703877852,
        18129354943882397960,
        15437979634065614942,
        101285514078273488,
    ]));
    /// phi((x, y)) = (\omega x, y)
    /// \omega = 0x531dc16c6ecd27aa846c61024e4cca6c1f31e53bd9603c2d17be416c5e44
    /// 26ee4a737f73b6f952ab5e57926fa701848e0a235a0a398300c65759fc4518315
    /// 1f2f082d4dcb5e37cb6290012d96f8819c547ba8a4000002f962140000000002a
    const OMEGA: Fq = Fq::new(BigInteger768::new([
        9193734820520314185,
        15390913228415833887,
        5309822015742495676,
        5431732283202763350,
        17252325881282386417,
        298854800984767943,
        15252629665615712253,
        11476276919959978448,
        6617989123466214626,
        293279592164056124,
        3271178847573361778,
        76563709148138387,
    ]));
    /// |round(B2 * R / n)|
    const Q1: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([8993470605275773807, 4826578625773784734, 2319558931065627696, 7, 0, 0]);
    /// |round(B1 * R / n)|
    const Q2: <Self::ScalarField as PrimeField>::BigInt =
        BigInteger384::new([11941976086484053770, 4826578625773784813, 2319558931065627696, 7, 0, 0]);
    const R_BITS: u32 = 384;
}
