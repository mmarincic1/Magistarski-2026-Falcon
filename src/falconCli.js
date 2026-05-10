import { spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import os from "os";
import { execFileSync } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FALCON_CLI = path.resolve(
  __dirname,
  "../../falcon-rust/target/release/falcon-cli"
);

export function falconKeygen() {
  const r = spawnSync(FALCON_CLI, ["keygen"], { encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(r.stderr || "falcon-cli keygen failed");
  }
  return JSON.parse(r.stdout);
}

export function falconSignRoot(rootHex, skHex) {
  const r = spawnSync(
    FALCON_CLI,
    ["sign", rootHex, skHex],
    { encoding: "utf8" }
  );
  if (r.status !== 0) {
    throw new Error(r.stderr || "falcon-cli sign failed");
  }
  return JSON.parse(r.stdout).signature;
}

export function falconVerifyRoot(rootHex, sigHex, pkHex) {
  const r = spawnSync(
    FALCON_CLI,
    ["verify", rootHex, sigHex, pkHex],
    { encoding: "utf8" }
  );
  if (r.status !== 0) {
    throw new Error(r.stderr || "falcon-cli verify failed");
  }
  return JSON.parse(r.stdout).valid;
}

// ===============================
// Falcon signature aggregation
// ===============================

export function falconAggregateSignatures(signatures, count) {
  const args = [
    "aggregate",
    "--count",
    String(count),
    "--sigs",
    ...signatures
  ];

  const r = spawnSync(FALCON_CLI, args, { encoding: "utf8" });

  if (r.status !== 0) {
    throw new Error(r.stderr || "falcon-cli aggregate failed");
  }

  return JSON.parse(r.stdout).signature;
}



export function falconVerifyAggregated(rootHex, aggSigHex, pkHex, count) {
  const r = spawnSync(
    FALCON_CLI,
    [
      "verify-agg",
      "--root-hex",
      rootHex,
      "--sig",
      aggSigHex,
      "--pk",
      pkHex,
      "--count",
      String(count)
    ],
    { encoding: "utf8" }
  );

  if (r.status !== 0) {
    throw new Error(r.stderr || "falcon-cli verify-agg failed");
  }

  return JSON.parse(r.stdout).valid === true;
}

export function falconVerifyBatch(items) {
  const tmpFile = path.join(
    os.tmpdir(),
    `falcon-verify-batch-${process.pid}-${Date.now()}.json`
  );

  const payload = items.map(item => ({
    root_hex: item.root,
    sig_hex: item.signature,
    pk_hex: item.publicKey
  }));

  fs.writeFileSync(tmpFile, JSON.stringify(payload, null, 2));

  try {
    const output = execFileSync(
      FALCON_CLI,
      ["verify-batch", "--input", tmpFile],
      { encoding: "utf8" }
    );

    return JSON.parse(output);
  } finally {
    fs.rmSync(tmpFile, { force: true });
  }
}

