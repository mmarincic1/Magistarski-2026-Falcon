#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ITERATIONS="${1:-40}"
RESULTS_DIR="benchmark-results"
STAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS_CSV="$RESULTS_DIR/step-benchmark-$STAMP.csv"
SUMMARY_TXT="$RESULTS_DIR/summary-$STAMP.txt"
SIZES_TXT="$RESULTS_DIR/sizes-$STAMP.txt"
LOG_DIR="$RESULTS_DIR/logs-$STAMP"

mkdir -p "$RESULTS_DIR" "$LOG_DIR"

echo "=== Step benchmark: BLS vs Falcon ==="
echo "Iterations: $ITERATIONS"
echo "CSV: $RESULTS_CSV"
echo

echo "mode,flow,step,iteration,time_seconds,bytes_note" > "$RESULTS_CSV"

clean_all() {
  rm -f \
    IssuerA_privateKey.json IssuerA_publicKey.json \
    IssuerB_privateKey.json IssuerB_publicKey.json \
    IssuerA_falcon_privateKey.json IssuerA_falcon_publicKey.json \
    IssuerB_falcon_privateKey.json IssuerB_falcon_publicKey.json \
    IssuerA_claimsA_issued_credential.json \
    IssuerB_claimsB_issued_credential.json \
    IssuerA_claimsA_signature.json \
    IssuerB_claimsB_signature.json \
    VerifierCIssuerARequiredDisclosures.json \
    VerifierCIssuerBRequiredDisclosures.json \
    revealedClaims_IssuerA_claimsA_issued_credential.json \
    revealedClaims_IssuerB_claimsB_issued_credential.json \
    aggregatedClaimsAndSignatures.json
}

file_size() {
  local file="$1"
  if [ -f "$file" ]; then
    wc -c < "$file" | tr -d ' '
  else
    echo 0
  fi
}

measure() {
  local mode="$1"
  local flow="$2"
  local step="$3"
  local iter="$4"
  shift 4

  local log="$LOG_DIR/${mode}_${flow}_${step}_${iter}.log"

  echo "[$mode][$flow][$step][$iter/$ITERATIONS]"

  local start
  local end
  local elapsed

  start=$(python3 - <<'PY'
import time
print(time.perf_counter())
PY
)

  "$@" > "$log" 2>&1

  end=$(python3 - <<'PY'
import time
print(time.perf_counter())
PY
)

  elapsed=$(python3 - <<PY
start = float("$start")
end = float("$end")
print(f"{end - start:.6f}")
PY
)

  echo "$mode,$flow,$step,$iter,$elapsed," >> "$RESULTS_CSV"
  echo "  -> ${elapsed}s"
}

record_size() {
  local mode="$1"
  local flow="$2"
  local step="$3"
  local iter="$4"
  local note="$5"
  local value="$6"

  echo "$mode,$flow,$step,$iter,0,$note=$value" >> "$RESULTS_CSV"
}

run_single() {
  local mode="$1"
  local iter="$2"

  clean_all

  if [ "$mode" = "BLS" ]; then
    export USE_FALCON=false
    local priv="IssuerA_privateKey.json"
    local pub="IssuerA_publicKey.json"
  else
    export USE_FALCON=true
    local priv="IssuerA_falcon_privateKey.json"
    local pub="IssuerA_falcon_publicKey.json"
  fi

  measure "$mode" "single" "keygen" "$iter" \
    npm run generate-keys -- --issuerName IssuerA

  record_size "$mode" "single" "private_key_size" "$iter" "$priv" "$(file_size "$priv")"
  record_size "$mode" "single" "public_key_size" "$iter" "$pub" "$(file_size "$pub")"

  measure "$mode" "single" "create_credential_and_sign_root" "$iter" \
    npm run create-credential -- \
      --claims ./examples/claimsA.json \
      --key "$priv"

  record_size "$mode" "single" "credential_size" "$iter" "IssuerA_claimsA_issued_credential.json" "$(file_size IssuerA_claimsA_issued_credential.json)"
  record_size "$mode" "single" "signature_file_size" "$iter" "IssuerA_claimsA_signature.json" "$(file_size IssuerA_claimsA_signature.json)"

  measure "$mode" "single" "create_required_claims" "$iter" \
    npm run require-claims -- \
      --name VerifierCIssuerA \
      --disclose given_name family_name \
      --numerical age \
      --min 18 \
      --max 80

  measure "$mode" "single" "create_selective_disclosure" "$iter" \
    npm run disclose-claims -- \
      --claims IssuerA_claimsA_issued_credential.json \
      --disclosed VerifierCIssuerARequiredDisclosures.json

  record_size "$mode" "single" "revealed_claims_size" "$iter" "revealedClaims_IssuerA_claimsA_issued_credential.json" "$(file_size revealedClaims_IssuerA_claimsA_issued_credential.json)"

  measure "$mode" "single" "verify_single" "$iter" \
    npm run verify-single -- \
      --proof revealedClaims_IssuerA_claimsA_issued_credential.json \
      --signature IssuerA_claimsA_signature.json \
      --key "$pub" \
      --required VerifierCIssuerARequiredDisclosures.json
}

run_multiple() {
  local mode="$1"
  local iter="$2"

  clean_all

  if [ "$mode" = "BLS" ]; then
    export USE_FALCON=false
    local privA="IssuerA_privateKey.json"
    local pubA="IssuerA_publicKey.json"
    local privB="IssuerB_privateKey.json"
    local pubB="IssuerB_publicKey.json"
  else
    export USE_FALCON=true
    local privA="IssuerA_falcon_privateKey.json"
    local pubA="IssuerA_falcon_publicKey.json"
    local privB="IssuerB_falcon_privateKey.json"
    local pubB="IssuerB_falcon_publicKey.json"
  fi

  measure "$mode" "multiple" "keygen_A" "$iter" \
    npm run generate-keys -- --issuerName IssuerA

  measure "$mode" "multiple" "keygen_B" "$iter" \
    npm run generate-keys -- --issuerName IssuerB

  record_size "$mode" "multiple" "private_key_A_size" "$iter" "$privA" "$(file_size "$privA")"
  record_size "$mode" "multiple" "public_key_A_size" "$iter" "$pubA" "$(file_size "$pubA")"
  record_size "$mode" "multiple" "private_key_B_size" "$iter" "$privB" "$(file_size "$privB")"
  record_size "$mode" "multiple" "public_key_B_size" "$iter" "$pubB" "$(file_size "$pubB")"

  measure "$mode" "multiple" "create_credential_A_and_sign_root" "$iter" \
    npm run create-credential -- \
      --claims ./examples/claimsA.json \
      --key "$privA"

  measure "$mode" "multiple" "create_credential_B_and_sign_root" "$iter" \
    npm run create-credential -- \
      --claims ./examples/claimsB.json \
      --key "$privB"

  record_size "$mode" "multiple" "credential_A_size" "$iter" "IssuerA_claimsA_issued_credential.json" "$(file_size IssuerA_claimsA_issued_credential.json)"
  record_size "$mode" "multiple" "credential_B_size" "$iter" "IssuerB_claimsB_issued_credential.json" "$(file_size IssuerB_claimsB_issued_credential.json)"
  record_size "$mode" "multiple" "signature_A_file_size" "$iter" "IssuerA_claimsA_signature.json" "$(file_size IssuerA_claimsA_signature.json)"
  record_size "$mode" "multiple" "signature_B_file_size" "$iter" "IssuerB_claimsB_signature.json" "$(file_size IssuerB_claimsB_signature.json)"

  measure "$mode" "multiple" "create_required_claims_A" "$iter" \
    npm run require-claims -- \
      --name VerifierCIssuerA \
      --disclose given_name family_name \
      --numerical age \
      --min 18 \
      --max 80

  measure "$mode" "multiple" "create_required_claims_B" "$iter" \
    npm run require-claims -- \
      --name VerifierCIssuerB \
      --disclose university \
      --numerical GPA \
      --min 3 \
      --max 5

  measure "$mode" "multiple" "create_selective_disclosure_A" "$iter" \
    npm run disclose-claims -- \
      --claims IssuerA_claimsA_issued_credential.json \
      --disclosed VerifierCIssuerARequiredDisclosures.json

  measure "$mode" "multiple" "create_selective_disclosure_B" "$iter" \
    npm run disclose-claims -- \
      --claims IssuerB_claimsB_issued_credential.json \
      --disclosed VerifierCIssuerBRequiredDisclosures.json

  record_size "$mode" "multiple" "revealed_claims_A_size" "$iter" "revealedClaims_IssuerA_claimsA_issued_credential.json" "$(file_size revealedClaims_IssuerA_claimsA_issued_credential.json)"
  record_size "$mode" "multiple" "revealed_claims_B_size" "$iter" "revealedClaims_IssuerB_claimsB_issued_credential.json" "$(file_size revealedClaims_IssuerB_claimsB_issued_credential.json)"

  measure "$mode" "multiple" "verify_single_A" "$iter" \
    npm run verify-single -- \
      --proof revealedClaims_IssuerA_claimsA_issued_credential.json \
      --signature IssuerA_claimsA_signature.json \
      --key "$pubA" \
      --required VerifierCIssuerARequiredDisclosures.json

  measure "$mode" "multiple" "verify_single_B" "$iter" \
    npm run verify-single -- \
      --proof revealedClaims_IssuerB_claimsB_issued_credential.json \
      --signature IssuerB_claimsB_signature.json \
      --key "$pubB" \
      --required VerifierCIssuerBRequiredDisclosures.json

  measure "$mode" "multiple" "create_presentation" "$iter" \
    npm run create-presentation -- \
      --claims \
        revealedClaims_IssuerA_claimsA_issued_credential.json \
        revealedClaims_IssuerB_claimsB_issued_credential.json \
      --roots \
        IssuerA_claimsA_signature.json \
        IssuerB_claimsB_signature.json

  record_size "$mode" "multiple" "aggregated_presentation_size" "$iter" "aggregatedClaimsAndSignatures.json" "$(file_size aggregatedClaimsAndSignatures.json)"

  measure "$mode" "multiple" "verify_multiple" "$iter" \
    npm run verify-multiple -- \
      --claims aggregatedClaimsAndSignatures.json \
      --key \
        "$pubA" \
        "$pubB" \
      --root \
        IssuerA_claimsA_signature.json \
        IssuerB_claimsB_signature.json \
      --required \
        VerifierCIssuerARequiredDisclosures.json \
        VerifierCIssuerBRequiredDisclosures.json
}

for i in $(seq 1 "$ITERATIONS"); do
  echo
  echo "=== Iteration $i/$ITERATIONS ==="

  run_single "BLS" "$i"
  run_single "Falcon" "$i"
  run_multiple "BLS" "$i"
  run_multiple "Falcon" "$i"
done

echo
echo "=== Timing summary ==="

python3 - <<PY | tee "$SUMMARY_TXT"
import csv
from collections import defaultdict

path = "$RESULTS_CSV"
groups = defaultdict(list)

with open(path, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if float(row["time_seconds"]) <= 0:
            continue
        key = (row["mode"], row["flow"], row["step"])
        groups[key].append(float(row["time_seconds"]))

print(f"{'Mode':<10} {'Flow':<10} {'Step':<38} {'Runs':<6} {'Avg(s)':<12} {'Min(s)':<12} {'Max(s)':<12}")
print("-" * 105)

for (mode, flow, step), values in sorted(groups.items()):
    avg = sum(values) / len(values)
    print(f"{mode:<10} {flow:<10} {step:<38} {len(values):<6} {avg:<12.6f} {min(values):<12.6f} {max(values):<12.6f}")

print()
print("CSV saved to:", path)
PY

echo
echo "=== Size summary ==="

python3 - <<PY | tee "$SIZES_TXT"
import csv
from collections import defaultdict

path = "$RESULTS_CSV"
sizes = defaultdict(list)

with open(path, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        note = row["bytes_note"]
        if not note or "=" not in note:
            continue
        label, value = note.rsplit("=", 1)
        try:
            value = int(value)
        except ValueError:
            continue
        key = (row["mode"], row["flow"], row["step"], label)
        sizes[key].append(value)

print(f"{'Mode':<10} {'Flow':<10} {'Metric':<35} {'File':<45} {'Avg(bytes)':<12}")
print("-" * 120)

for (mode, flow, metric, label), values in sorted(sizes.items()):
    avg = sum(values) / len(values)
    print(f"{mode:<10} {flow:<10} {metric:<35} {label:<45} {avg:<12.2f}")

print()
print("Logs saved to:", "$LOG_DIR")
PY