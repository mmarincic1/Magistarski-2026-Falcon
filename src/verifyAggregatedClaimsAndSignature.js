import { MerkleTree } from "merkletreejs";
import loadBls from "bls-signatures";
import { createHash } from "crypto";
import fs from "fs";
import bulletproofs from "@latticelabs/zkp-js/bulletproof.js";
import { stringToBigInt, USE_FALCON } from "./utils.js";
import { falconVerifyBatch, falconVerifyRoot } from "./falconCli.js";

const CommitmentUtils = bulletproofs.CommitmentUtils;
const PedGeneratorParams = bulletproofs.PedGeneratorParams;
const GeneratorParams = bulletproofs.GeneratorParams;
const library = "elliptic";
const curveName = "secp256k1";
const CompressedBulletproof = bulletproofs.CompressedProofs;
const pedGenParams = PedGeneratorParams.generateParams(library, curveName);
const PointFn = pedGenParams.PointFn;
const sha3_256 = (data) => {
  const input = Buffer.isBuffer(data)
    ? data
    : Buffer.from(String(data));

  return createHash("sha3-256").update(input).digest();
};

// ==========================
// Single credential verify
// ==========================
async function verifyClaims(
  revealedClaims,
  rootSignatureFilePath,
  publicKeyFilePath,
  requiredClaimsFilePath
) {
  const bls = await loadBls();

  const { merkleRoot, signature } = JSON.parse(
    fs.readFileSync(rootSignatureFilePath, "utf8")
  );

  const requiredClaims = JSON.parse(
    fs.readFileSync(requiredClaimsFilePath, "utf8")
  );

  const publicKeyData = JSON.parse(
    fs.readFileSync(publicKeyFilePath, "utf8")
  );

  // ---- Merkle + ZKP ----
  const tree = new MerkleTree([], sha3_256, { sortPairs: true });

  const isValidClaims = revealedClaims.every(claimGroup =>
    Object.entries(claimGroup).every(([_, data]) => {
      let { value, salt, proof } = data;

      let leaf = value;
      if (salt) {
        value =
          typeof value === "string"
            ? stringToBigInt(value)
            : BigInt(value);

        leaf = PointFn.toHexString(
          CommitmentUtils.getPedersenCommitment(
            value,
            BigInt(salt),
            pedGenParams
          )
        );
      }

      const proofObjects = proof.map(p => ({
        position: p.position,
        data: Buffer.from(p.data, "hex"),
      }));

      return tree.verify(proofObjects, leaf, merkleRoot);
    })
  );

  // ---- Signature ----
  let isValidSignature;

  if (USE_FALCON) {
    isValidSignature = falconVerifyRoot(
      merkleRoot,
      signature,
      publicKeyData.publicKey
    );
  } else {
    const blsPk = bls.G1Element.from_bytes(
      Buffer.from(publicKeyData.publicKey, "hex")
    );

    isValidSignature = bls.AugSchemeMPL.verify(
      blsPk,
      merkleRoot,
      bls.G2Element.from_bytes(Buffer.from(signature, "hex"))
    );
  }

  return isValidClaims && isValidSignature;
}

// ========================================
// Aggregated presentation verify (FALLBACK)
// ========================================
async function verifyAggregatedClaimsAndSignature(
  aggregatedFilePath,
  publicKeyFiles,
  rootSignatureFiles,
  requiredClaimsFiles
) {
  const bls = await loadBls();

  const parsed = JSON.parse(fs.readFileSync(aggregatedFilePath, "utf8"));
  const { aggregatedClaims, aggregationMode } = parsed;

  // ---- verify claims for each credential ----
  let allClaimsValid = true;

  for (let i = 0; i < rootSignatureFiles.length; i++) {
    const ok = await verifyClaims(
      aggregatedClaims[i],
      rootSignatureFiles[i],
      publicKeyFiles[i],
      requiredClaimsFiles[i]
    );

    console.log(`Verification of claims ${i + 1}: ${ok}`);

    if (!ok) {
      allClaimsValid = false;
    }
  }

  if (!allClaimsValid) {
    console.log("Aggregated presentation valid: false");
    return false;
  }

  // =====================
  // FALCON MODE
  // =====================
  if (USE_FALCON) {
    if (aggregationMode === "none") {
      console.log("Falcon fallback: batch verification of individual signatures");

      const batchItems = rootSignatureFiles.map((rootFile, i) => {
        const { merkleRoot, signature } = JSON.parse(
          fs.readFileSync(rootFile, "utf8")
        );

        const { publicKey } = JSON.parse(
          fs.readFileSync(publicKeyFiles[i], "utf8")
        );

        return {
          root: merkleRoot,
          signature,
          publicKey,
        };
      });

      const batchResult = falconVerifyBatch(batchItems);

      console.log("Falcon batch results:", batchResult.results);
      console.log("All Falcon signatures valid:", batchResult.valid);

      return batchResult.valid;
    }
}

  // =====================
  // BLS MODE
  // =====================
  const { aggregatedSignature } = parsed;

  const aggregatedSig = bls.G2Element.from_bytes(
    Buffer.from(aggregatedSignature, "hex")
  );

  const publicKeys = publicKeyFiles.map(fp => {
    const { publicKey } = JSON.parse(fs.readFileSync(fp, "utf8"));
    return bls.G1Element.from_bytes(Buffer.from(publicKey, "hex"));
  });

  const roots = rootSignatureFiles.map(fp => {
    const { merkleRoot } = JSON.parse(fs.readFileSync(fp, "utf8"));
    return merkleRoot;
  });

  const isValid = bls.AugSchemeMPL.aggregate_verify(
    publicKeys,
    roots,
    aggregatedSig
  );

  console.log(`Aggregated BLS signature valid: ${isValid}`);
  return isValid;
}

export default verifyAggregatedClaimsAndSignature;
