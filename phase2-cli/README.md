### Prepare Phase 2

This binary will only be run by the coordinator after Phase 1 has been executed.
Note that the parameters produced are **only for the Groth16 SNARK**.

```ignore
./prepare_phase2 --help
Usage: ./prepare_phase2 [OPTIONS]

Optional arguments:
  -h, --help
  -p, --phase2-fname PHASE2-FNAME
                             the file which will contain the FFT coefficients processed for Phase 2 of the setup
  -r, --response-fname RESPONSE-FNAME
                             the response file which will be processed for the specialization (phase 2) of the setup
  -c, --curve-kind CURVE-KIND
                             the elliptic curve to use (default: bls12_377)
  -P, --proving-system PROVING-SYSTEM
                             the proving system to use (default: groth16)
  -b, --batch-size BATCH-SIZE
                             the size of batches to process (default: 256)
  --power POWER              the number of powers used for phase 1 (default: 21)
  --phase2-size PHASE2-SIZE  the size of the phase 2 circuit (default: 2^{power})
```