import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import { createHash } from "crypto";
import fs  from 'fs';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js'
import { closestPowerOfTwo, stringToBigInt } from './utils.js';
import { USE_FALCON } from "./utils.js";
import { falconVerifyRoot } from "./falconCli.js";
const CommitmentUtils = bulletproofs.CommitmentUtils;
const PedGeneratorParams = bulletproofs.PedGeneratorParams;
const Rand = bulletproofs.Rand;
const GeneratorParams = bulletproofs.GeneratorParams;
const library = "elliptic"
const curveName = "secp256k1";
const CompressedBulletproof = bulletproofs.CompressedProofs;
const ProofFactory = bulletproofs.ProofFactory;
const pedGenParams = PedGeneratorParams.generateParams(library, curveName);
const PointFn = pedGenParams.PointFn;


const sha3_256 = (data) => {
  const input = Buffer.isBuffer(data)
    ? data
    : Buffer.from(String(data));

  return createHash("sha3-256").update(input).digest();
};

async function verifyClaims(proofsFilePath, rootSignatureFilePath, publicKeyFilePath, requiredClaimsFilePath) {
  // Initialize the BLS library
  var bls = await loadBls();

  // Read and parse the proofs file
  const { revealedClaims } = JSON.parse(fs.readFileSync(proofsFilePath, 'utf8'));
  const requiredClaims  = JSON.parse(fs.readFileSync(requiredClaimsFilePath, 'utf8'));

  // Read and parse the root and signature file
  const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));

  // Read and parse the public key file
  const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
  const publicKeyHex = publicKeyData.publicKey;

  let blsPublicKey = null;

  if (!USE_FALCON) {
    blsPublicKey = bls.G1Element.from_bytes(
      Buffer.from(publicKeyHex, 'hex')
    );
  }

 
  // Verify each claim
  const tree = new MerkleTree([], sha3_256, { sortPairs: true }); // Dummy tree for verification

  const isValidClaims =revealedClaims.every(claimGroup => {
    return Object.entries(claimGroup).every(([key, { value, salt, proof, numerical_proof_low,numerical_proof_high, numerical_value_low,numerical_value_high }]) => {
     var leaf = value;
    if (salt){
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
      value =  BigInt(Math.round(value));
    leaf=  PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, BigInt(salt),pedGenParams))
    }
    const proofObjects = proof.map(p => ({ position: p.position, data: Buffer.from(p.data, 'hex') }));
    let validTree =  tree.verify(proofObjects, leaf, merkleRoot) 
    let validNumeric= true
    let validRangeLow= true
    let validRangeHigh = true
    if (numerical_proof_low){
      const claimKey = requiredClaims.numericalClaims.find(x=>x.claim===key)
      const size = BigInt(closestPowerOfTwo(claimKey.max))
      const genParams = GeneratorParams.generateParams(size, library, curveName, pedGenParams);  
      const proof_low = CompressedBulletproof.fromJsonString(
        numerical_proof_low, 
        genParams.pedGen.CurveFn, 
        PointFn
      );
      const proof_high = CompressedBulletproof.fromJsonString(
        numerical_proof_high, 
        genParams.pedGen.CurveFn, 
        PointFn
      );


      validRangeLow = proof_low.verify(0n, size, PointFn.fromHexString(numerical_value_low,genParams.pedGen.CurveFn), genParams)

      validRangeHigh = proof_high.verify(0n, size, PointFn.fromHexString(numerical_value_high,genParams.pedGen.CurveFn), genParams)
     const mini = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.min), BigInt(requiredClaims.salt), pedGenParams);
     const maxi = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.max), BigInt(requiredClaims.salt), pedGenParams);

      var sub= CommitmentUtils.comSubCom(PointFn.fromHexString(leaf,pedGenParams.CurveFn), mini, PointFn)
      var sub2= CommitmentUtils.comSubCom(maxi, PointFn.fromHexString(leaf,pedGenParams.CurveFn), PointFn)
      validNumeric=(PointFn.toHexString(sub)===numerical_value_low)&&(PointFn.toHexString(sub2)===numerical_value_high)
    }
     return validTree && validNumeric && validRangeLow && validRangeHigh
  });
  });
  // Verify the signature
  let isValidSignature;

  if (USE_FALCON) {
    console.log("▶ Verifying signature with Falcon");
    const publicKeyHex = publicKeyData.publicKey;
    isValidSignature = falconVerifyRoot(
      merkleRoot,
      signature,
      publicKeyHex
    );
  } else {
    isValidSignature = bls.AugSchemeMPL.verify(
      blsPublicKey,
      merkleRoot,
      bls.G2Element.from_bytes(Buffer.from(signature, 'hex'))
    );
  }


  console.log(`Claims are valid: ${isValidClaims}`);
  console.log(`Signature is valid: ${isValidSignature}`);
}

export default verifyClaims;