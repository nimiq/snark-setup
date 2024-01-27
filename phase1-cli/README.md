# Phase 1 CLI

You can see an E2E demo with 3 participants and the beacon at the end by running `test.sh`.

## CLI Guide

### Phase 1

Coordinators run:
1. `new` to create a new accumulator
1. `verify-and-transform` after receiving a contribution to the previous challenge, to produce a new challenge for the next contribution
1. `beacon` at the end of the ceremony (optional, as the security proof [does not require it](https://electriccoin.co/blog/reinforcing-the-security-of-the-sapling-mpc/))

Users should only care about the `contribute` option.

```ignore
$ ./phase1 --help
Usage: ./phase1 [OPTIONS]

Optional arguments:
  -h, --help
  -c, --curve-kind CURVE-KIND
                     the elliptic curve to use (default: bls12_381)
  -p, --proving-system PROVING-SYSTEM
                     the proving system to use (default: groth16)
  -b, --batch-size BATCH-SIZE
                     the size of batches to process (default: 256)
  -P, --power POWER  the circuit power (circuit size will be 2^{power}) (default: 21)

Available commands:

  new                   creates a new challenge for the ceremony
  contribute            contribute to ceremony by producing a response to a challenge (or create a new challenge if this is the first contribution)
  beacon                contribute randomness via a random beacon (e.g. a bitcoin block header hash)
  verify-and-transform  verify the contributions so far and generate a new challenge
```

## License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
