import loadBls from "bls-signatures";
import fs from "fs";
import crypto from "crypto";
import { USE_FALCON } from "./utils.js";
import { falconKeygen } from "./falconCli.js";

async function generateAndSaveKeys(issuerName) {

  if (USE_FALCON) {
    // -------- FALCON KEYGEN --------
    const { public_key, secret_key } = falconKeygen();

    const base = issuerName.replace(/[^a-z0-9]/gi, "_");

    fs.writeFileSync(
      `${base}_falcon_privateKey.json`,
      JSON.stringify({ issuer: issuerName, privateKey: secret_key }, null, 2)
    );

    fs.writeFileSync(
      `${base}_falcon_publicKey.json`,
      JSON.stringify({ issuer: issuerName, publicKey: public_key }, null, 2)
    );

    console.log("Falcon keys generated for " + issuerName);
    return;
  }

  // -------- BLS KEYGEN (POSTOJEĆE) --------
  var bls = await loadBls();

  const privateKey = bls.AugSchemeMPL.key_gen(crypto.randomBytes(32));
  const publicKey = privateKey.get_g1();

  const privateKeyHex = bls.Util.hex_str(privateKey.serialize());
  const publicKeyHex = bls.Util.hex_str(publicKey.serialize());

  const privateKeyObj = { issuer: issuerName, privateKey: privateKeyHex };
  const publicKeyObj = { issuer: issuerName, publicKey: publicKeyHex };

  fs.writeFileSync(
    `${issuerName}_privateKey.json`,
    JSON.stringify(privateKeyObj, null, 2)
  );

  fs.writeFileSync(
    `${issuerName}_publicKey.json`,
    JSON.stringify(publicKeyObj, null, 2)
  );

  console.log("BLS keys generated for " + issuerName);
}

export default generateAndSaveKeys;
