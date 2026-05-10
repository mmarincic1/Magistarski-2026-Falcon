#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Falcon single credential flow ==="
echo

echo "[0/7] Cleaning previous run files..."
rm -f \
  IssuerA_privateKey.json \
  IssuerA_publicKey.json \
  IssuerB_privateKey.json \
  IssuerB_publicKey.json \
  IssuerA_claimsA_issued_credential.json \
  IssuerB_claimsB_issued_credential.json \
  IssuerA_claimsA_signature.json \
  IssuerB_claimsB_signature.json \
  VerifierCIssuerARequiredDisclosures.json \
  VerifierCIssuerBRequiredDisclosures.json \
  revealedClaims_IssuerA_claimsA_issued_credential.json \
  revealedClaims_IssuerB_claimsB_issued_credential.json \
  aggregatedClaimsAndSignatures.json \
  IssuerA_falcon_privateKey.json \
  IssuerA_falcon_publicKey.json \
  IssuerB_falcon_privateKey.json \
  IssuerB_falcon_publicKey.json \

echo "[1/7] Generating issuer keys..."
npm run generate-keys -- --issuerName IssuerA

echo "[2/7] Creating credential..."
npm run create-credential -- \
  --claims ./examples/claimsA.json \
  --key IssuerA_falcon_privateKey.json

echo "[3/7] Creating verifier requirements..."
npm run require-claims -- \
  --name VerifierCIssuerA \
  --disclose given_name family_name \
  --numerical age \
  --min 18 \
  --max 80

echo "[4/7] Creating selective disclosure proof..."
npm run disclose-claims -- \
  --claims IssuerA_claimsA_issued_credential.json \
  --disclosed VerifierCIssuerARequiredDisclosures.json

echo "[5/7] Verifying selective disclosure..."
npm run verify-single -- \
  --proof revealedClaims_IssuerA_claimsA_issued_credential.json \
  --signature IssuerA_claimsA_signature.json \
  --key IssuerA_falcon_publicKey.json \
  --required VerifierCIssuerARequiredDisclosures.json

echo
echo "✅ Falcon single credential flow completed successfully."