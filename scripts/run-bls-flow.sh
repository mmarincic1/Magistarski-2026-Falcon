#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export USE_FALCON=false

echo "=== Original BLS flow ==="
echo

echo "[0/9] Cleaning previous BLS run files..."
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

echo "[1/9] Generating BLS issuer keys..."
npm run generate-keys -- --issuerName IssuerA
npm run generate-keys -- --issuerName IssuerB

echo "[2/9] Creating credentials..."
npm run create-credential -- \
  --claims ./examples/claimsA.json \
  --key IssuerA_privateKey.json

npm run create-credential -- \
  --claims ./examples/claimsB.json \
  --key IssuerB_privateKey.json

echo "[3/9] Creating verifier requirements..."
npm run require-claims -- \
  --name VerifierCIssuerA \
  --disclose given_name family_name \
  --numerical age \
  --min 18 \
  --max 80

npm run require-claims -- \
  --name VerifierCIssuerB \
  --disclose university \
  --numerical GPA \
  --min 3 \
  --max 5

echo "[4/9] Creating selective disclosures..."
npm run disclose-claims -- \
  --claims IssuerA_claimsA_issued_credential.json \
  --disclosed VerifierCIssuerARequiredDisclosures.json

npm run disclose-claims -- \
  --claims IssuerB_claimsB_issued_credential.json \
  --disclosed VerifierCIssuerBRequiredDisclosures.json

echo "[5/9] Verifying single credential A..."
npm run verify-single -- \
  --proof revealedClaims_IssuerA_claimsA_issued_credential.json \
  --signature IssuerA_claimsA_signature.json \
  --key IssuerA_publicKey.json \
  --required VerifierCIssuerARequiredDisclosures.json

echo "[6/9] Verifying single credential B..."
npm run verify-single -- \
  --proof revealedClaims_IssuerB_claimsB_issued_credential.json \
  --signature IssuerB_claimsB_signature.json \
  --key IssuerB_publicKey.json \
  --required VerifierCIssuerBRequiredDisclosures.json

echo "[7/9] Creating BLS aggregated presentation..."
npm run create-presentation -- \
  --claims \
    revealedClaims_IssuerA_claimsA_issued_credential.json \
    revealedClaims_IssuerB_claimsB_issued_credential.json \
  --roots \
    IssuerA_claimsA_signature.json \
    IssuerB_claimsB_signature.json

echo "[8/9] Verifying BLS aggregated presentation..."
npm run verify-multiple -- \
  --claims aggregatedClaimsAndSignatures.json \
  --key \
    IssuerA_publicKey.json \
    IssuerB_publicKey.json \
  --root \
    IssuerA_claimsA_signature.json \
    IssuerB_claimsB_signature.json \
  --required \
    VerifierCIssuerARequiredDisclosures.json \
    VerifierCIssuerBRequiredDisclosures.json

echo
echo "✅ Original BLS flow completed successfully."