import fs from "fs";
import loadBls from "bls-signatures";
import { USE_FALCON } from "./utils.js";
import { falconAggregateSignatures } from "./falconCli.js";

async function aggregateClaimsAndSignatures(claimsFiles, rootSignatureFiles) {
  const bls = await loadBls();

  // -----------------------------
  // Load disclosed claims
  // -----------------------------
  const aggregatedClaims = claimsFiles.map(fp => {
    const data = JSON.parse(fs.readFileSync(fp, "utf8"));
    return data.revealedClaims;
  });

  // -----------------------------
  // Load roots & signatures
  // -----------------------------
  const roots = rootSignatureFiles.map(fp => {
    const { merkleRoot } = JSON.parse(fs.readFileSync(fp, "utf8"));
    return merkleRoot;
  });

  const signatures = rootSignatureFiles.map(fp => {
    const { signature } = JSON.parse(fs.readFileSync(fp, "utf8"));
    return signature;
  });

  // -----------------------------
  // Check if all roots are same
  // -----------------------------
  const allSameRoot = roots.every(r => r === roots[0]);

  let output;

  // =============================
  // FALCON MODE
  // =============================
  if (USE_FALCON) {
      output = {
        aggregationMode: "none",
        aggregatedClaims,
        roots,
        signatures,
      };

      console.log("Falcon fallback applied (different roots).");
    // }
  }

  // =============================
  // BLS MODE
  // =============================
  else {
    const sigObjects = signatures.map(sigHex =>
      bls.G2Element.fromBytes(Buffer.from(sigHex, "hex"))
    );

    const aggregatedSignature = bls.AugSchemeMPL.aggregate(sigObjects);

    output = {
      aggregationMode: "bls",
      aggregatedClaims,
      aggregatedSignature: Buffer.from(
        aggregatedSignature.serialize()
      ).toString("hex"),
    };

    console.log("BLS aggregation applied.");
  }

  fs.writeFileSync(
    "aggregatedClaimsAndSignatures.json",
    JSON.stringify(output, null, 2),
    "utf8"
  );

  console.log("Aggregated presentation saved.");
}

export default aggregateClaimsAndSignatures;
