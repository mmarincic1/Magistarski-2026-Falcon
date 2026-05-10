# Selective disclosure: BLS-MT-ZKP
Proof of concept for selective disclosure of digital credentials using Merkle trees and BLS signatures, with Pedersen Commitment and Bulletproofs for range proofs. Main focus is on selective disclosure of claims in multiple credentials and their verification.


## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/seilabecirovic/Selective-disclosure-BLS-Merkle-Trees.git

cd Selective-disclosure-BLS-Merkle-Trees
```

2. Install required packages
```
npm install
```


## Usage

This section describes the command-line interface functionality of the library; corresponding functions can also be accessed through the API.

### Generate issuer keys

To generate an issuer signing key pair, run

```
npm run generate-keys -- --issuerName <issuerName>
```

where `issuerName` is the name of the issue. This function generates private and public keys and stores them in separate files.

### Sign a set of claims and record the root hash and signature

To create a Merkle tree from a set of claims and generate a signature on the root, run 

```
npm run create-credential -- --claims <claims> --key <key>
```

where ` claims` is the path to the JSON file containing claims, while `key` is the path to the public key. This function generates a file which contains issuer, root hash and signature, and a file that contains credential.

### Define required claims

To define required claims, run

```
 npm run require-claims -- --name <name> --disclose <disclose...> --numerical <numerical...> --min <min...> --max <max...>
```

where `name` is the name of the verifier that requires the claims, `disclose` is the list of string claims that need to be disclosed, `numerical` is the list of numerical values that need to be proved, `min` is the list of minimum values for the numerical proofs, `max` is the the list of maximum values for the numerical proofs. Function creates a file containing required claims.


### Selectively-disclosure of claims

To selectively disclose some claims, run

```
 npm run disclose-claims -- --claims <claims> --disclosed <disclosed...>
```

where `claims` is the path to the JSON claims file, `disclosed...` is a path to the JSON required claims file. Function creates a file containing generated claims and Merkle tree proofs. 

### Verification of disclosed claims

To verify disclosed claims, run

```
npm run verify-single -- --proof <proof> --signature <signature> --key <key> --required <required>
```

where  `proof` is the path to the disclosed claims and proofs, `signature` is the path to the record file containing root hash and signature of credential, `key` is the path to the public key of issuer, and `required` is the path to the required claims. Function verifies disclosed claims through root and bulletproofs for ranges and through signature. 

### Selective disclosure of claims in multiple credentials

To selectively disclose claims from multiple credentials and generate a presentation, run

```
npm run create-presentation -- --claims <claims...> --roots <roots...> 
```

where `claims` are paths to selectively disclosed claims and their proofs seperated by space, `roots...` are a series of space-separated paths to files containing hashes of roots and signatures of disclosed credentials. Function creates a file containing aggregated generated claims and Merkle tree proofs, alongside aggregated signature. 

### Verification of disclosed claims from multiple credentials

To verify disclosed claims, run

```
npm run verify-multiple -- --claims <claims> --key <key...> --root <root...> --required <required>
```

where 
`proof` is the path to the aggregated disclosed claims and proofs, `key` is the path to the public keys of issuers separated by space, `root` are the space-separated filepaths of root hashes and signature for each credential and `required` are the space-seperated filepaths of required claims. Function verifies disclosed claims of multiple credentials. 


## Example

The following steps give an end-to-end example on how to use the library, using test data.

1. Issuers A and B create their signing key pair (of default ES256 algorithm type)

```
npm run generate-keys --  --issuerName IssuerA

npm run generate-keys --  --issuerName IssuerB
```

2. Issuer A issues a credential, as well as issuer B

```
npm run create-credential -- --claims ./examples/claimsA.json --key IssuerA_privateKey.json

npm run create-credential -- --claims ./examples/claimsB.json --key IssuerB_privateKey.json 
```

3. Verifier C requries different claims from credentials, including range proof where possible:

```
npm run require-claims -- --name VerifierCIssuerA --disclose given_name family_name --numerical age --min 18 --max 80
npm run require-claims -- --name VerifierCIssuerB --disclose university --numerical GPA --min 3 --max 5
```

4. Holder selectively disclose claims from credential of issuer A and some claims from issuer B

```
npm run disclose-claims -- --claims IssuerA_claimsA_issued_credential.json --disclosed VerifierCIssuerARequiredDisclosures.json
npm run disclose-claims -- --claims IssuerB_claimsB_issued_credential.json --disclosed VerifierCIssuerBRequiredDisclosures.json
```

5. Verifier verifies the disclosed claims of both issuers seperately 

```
npm run verify-single -- --proof revealedClaims_IssuerA_claimsA_issued_credential.json --signature IssuerA_claimsA_signature.json --key IssuerA_publicKey.json --required  VerifierCIssuerARequiredDisclosures.json
npm run verify-single -- --proof revealedClaims_IssuerB_claimsB_issued_credential.json --signature IssuerB_claimsB_signature.json --key IssuerB_publicKey.json --required VerifierCIssuerBRequiredDisclosures.json
```

6. Holder combines disclosed claims from issuer A and issuer B

```
npm run create-presentation -- --claims revealedClaims_IssuerA_claimsA_issued_credential.json revealedClaims_IssuerB_claimsB_issued_credential.json  --roots IssuerA_claimsA_signature.json IssuerB_claimsB_signature.json 
```

6. Verifier verifies aggregated presentation

```
 npm run verify-multiple -- --claims aggregatedClaimsAndSignatures.json --key IssuerA_publicKey.json IssuerB_publicKey.json --root IssuerA_claimsA_signature.json IssuerB_claimsB_signature.json  --required VerifierCIssuerARequiredDisclosures.json VerifierCIssuerBRequiredDisclosures.json
```

# Selective Disclosure: BLS-MT-ZKP with Falcon Post-Quantum Signatures

Extended proof-of-concept implementation for selective disclosure of digital credentials using:

- Merkle Trees
- Post-Quantum Falcon Signatures
- SHA3-256 hashing
- Pedersen Commitments
- Bulletproofs range proofs

The project extends the original BLS-MT-ZKP implementation by introducing a post-quantum signature layer based on Falcon and replacing the Merkle tree hashing algorithm with SHA3-256.

Main focus of the project:
- selective disclosure of claims,
- range proofs for numerical values,
- multiple credential presentations,
- post-quantum signature support,
- comparison between original BLS and Falcon-based approaches.

---

# Implemented Extensions

Compared to the original implementation, the following changes were introduced.

## Falcon Post-Quantum Signature Integration

The original BLS signature layer was extended with Falcon-512 signatures.

Implemented functionality:
- Falcon key generation
- Falcon signing of Merkle roots
- Falcon signature verification
- Batch verification fallback strategy for multiple credentials
- Dual-mode support (BLS / Falcon)

## SHA3-256 Merkle Hashing

Original SHA-256 hashing used inside Merkle trees was replaced with SHA3-256.

The Pedersen commitment layer was intentionally preserved because:
- Bulletproof range proofs depend on the current commitment model
- Full migration to post-quantum ZKP primitives is outside the scope of this implementation

## Aggregation Fallback Strategy

BLS supports native aggregate signatures.

Falcon does not provide equivalent aggregation support in the used implementation.

Because of this:
- The original BLS aggregation mechanism was preserved for BLS mode
- Falcon mode uses a fallback strategy based on:
  - lists of individual signatures
  - batch verification optimization

This preserves selective disclosure functionality while remaining compatible with Falcon signatures.

---

# Setup

Make sure the following are installed:

- [Node.js](https://nodejs.org/) (LTS recommended)
- npm
- Rust + Cargo (required for Falcon CLI)

Clone repository:

```bash
git clone -b main https://github.com/seilabecirovic/Selective-disclosure-BLS-Merkle-Trees.git

cd Selective-disclosure-BLS-Merkle-Trees
```

Install Node.js dependencies:

```bash
npm install
```

---

# Falcon CLI Setup

The Falcon implementation uses a Rust CLI wrapper.

Build Falcon CLI:

```bash
cd falcon-rust
cargo build --release
```

Return to project root:

```bash
cd ..
```

---

# Configuration

The project supports two modes:

- Falcon mode (default)
- Original BLS mode

Configuration is controlled through:

```js
export const USE_FALCON =
  process.env.USE_FALCON !== "false";
```

## Falcon mode

```bash
./scripts/run-falcon-flow.sh
```

## BLS mode

```bash
USE_FALCON=false ./scripts/run-bls-flow.sh
```

---

# Usage

## Generate issuer keys

```bash
npm run generate-keys -- --issuerName <issuerName>
```

Generates:
- public key
- private key

Depending on selected mode:
- BLS keys
- Falcon keys

---

## Create Credential and Sign Merkle Root

```bash
npm run create-credential -- --claims <claims> --key <key>
```

Creates:
- credential file
- Merkle root
- signature file

---

## Define Required Claims

```bash
npm run require-claims -- \
  --name <name> \
  --disclose <disclose...> \
  --numerical <numerical...> \
  --min <min...> \
  --max <max...>
```

Creates verifier disclosure requirements.

---

## Create Selective Disclosure Proof

```bash
npm run disclose-claims -- \
  --claims <claims> \
  --disclosed <requirements>
```

Creates:
- disclosed claims
- Merkle proofs
- Bulletproof range proofs

---

## Verify Disclosed Claims

```bash
npm run verify-single -- \
  --proof <proof> \
  --signature <signature> \
  --key <key> \
  --required <required>
```

Verification includes:
- Merkle proof verification
- Bulletproof range proof verification
- Signature verification

---

## Create Aggregated Presentation

```bash
npm run create-presentation -- \
  --claims <claims...> \
  --roots <roots...>
```

Creates:
- aggregated presentation
- combined disclosed claims
- signature metadata

In Falcon mode:
- aggregation uses fallback strategy
- signatures are stored individually

---

## Verify Aggregated Presentation

```bash
npm run verify-multiple -- \
  --claims <claims> \
  --key <key...> \
  --root <root...> \
  --required <required...>
```

### BLS Mode

Uses:
- native BLS aggregate signature verification

### Falcon Mode

Uses:
- batch verification of individual Falcon signatures

This is **NOT** cryptographic aggregation.

It is an optimization that:
- reduces CLI invocation overhead
- verifies multiple Falcon signatures in one Rust process execution

---

# Scripts

## Falcon Single Credential Flow

```bash
./scripts/run-single-flow.sh
```

Runs:
- Falcon key generation
- credential creation
- selective disclosure
- single verification

---

## Falcon Multi-Credential Flow

```bash
./scripts/run-falcon-flow.sh
```

Runs:
- multiple credential issuing
- aggregated presentation creation
- Falcon batch verification fallback

---

## Original BLS Single Flow

```bash
./scripts/run-bls-single-flow.sh
```

Runs original BLS implementation for a single credential.

---

## Original BLS Multi-Credential Flow

```bash
./scripts/run-bls-flow.sh
```

Runs original BLS implementation for multiple credentials.

---

# Benchmarking

The project includes detailed benchmarking scripts for comparing:
- BLS
- Falcon

implementations.

## Step Benchmark

```bash
./scripts/benchmark-steps.sh
```

Or with custom iteration count:

```bash
./scripts/benchmark-steps.sh 10
```

The benchmark measures:
- key generation
- credential creation and signing
- selective disclosure generation
- single verification
- presentation creation
- multiple verification
- file sizes
- key sizes
- signature sizes

Generated outputs:

```text
benchmark-results/
├── step-benchmark-<timestamp>.csv
├── summary-<timestamp>.txt
├── sizes-<timestamp>.txt
└── logs-<timestamp>/
```

---

# Security Notes

## BLS

Original implementation:
- supports native aggregation
- not post-quantum secure

## Falcon

Extended implementation:
- post-quantum secure signature layer
- no native aggregation
- larger keys and signatures

## SHA3-256

Merkle tree hashing was migrated from SHA-256 to SHA3-256.

## Pedersen Commitments

Pedersen commitments and Bulletproof range proofs remain unchanged from the original implementation.

---

# Experimental Results

Benchmarking showed:
- Falcon key generation is slower than BLS
- Falcon keys and signatures are significantly larger
- Overall selective disclosure performance remains comparable
- Bulletproof generation and verification dominate execution time
- Falcon batch verification performs comparably to BLS aggregate verification in tested scenarios

---

# Project Structure

```text
src/
├── createCredential.js
├── discloseClaims.js
├── verifyClaims.js
├── verifyAggregatedClaimsAndSignature.js
├── falconCli.js
├── utils.js
└── ...

scripts/
├── run-single-flow.sh
├── run-falcon-flow.sh
├── run-bls-single-flow.sh
├── run-bls-flow.sh
└── benchmark-steps.sh

falcon-rust/
└── Falcon Rust CLI implementation
```

---

# Notes

This implementation is a proof-of-concept research project.

The Falcon batch verification mechanism:
- does not implement true cryptographic aggregation
- serves as a practical fallback strategy compatible with Falcon signatures

Future work may include:
- STARK-based aggregation approaches
- LaBRADOR-style constructions
- fully post-quantum zero-knowledge proof systems