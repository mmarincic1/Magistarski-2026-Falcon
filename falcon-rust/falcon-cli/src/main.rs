use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;

use falcon_rust::falcon512;
use rand::{rngs::OsRng, RngCore};

#[derive(Parser)]
#[command(name = "falcon-cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a Falcon512 keypair
    Keygen,

    /// Sign message (root_hex) with secret key (sk_hex)
    Sign { root_hex: String, sk_hex: String },

    /// Verify signature (sig_hex) over message (root_hex) with public key (pk_hex)
    Verify { root_hex: String, sig_hex: String, pk_hex: String },

    /// Aggregate multiple signatures into a single signature (experimental)
    ///
    /// Usage:
    /// falcon-cli aggregate --count 2 --sigs <sig1_hex> <sig2_hex> ...
    Aggregate {
        #[arg(long)]
        count: usize,

        #[arg(long, num_args = 2..)]
        sigs: Vec<String>,
    },

    /// Verify an aggregated signature (experimental)
    ///
    /// Usage:
    /// falcon-cli verify-agg --root-hex <msg_hex> --sig <agg_sig_hex> --pk <pk_hex> --count 2
    VerifyAgg {
        #[arg(long)]
        root_hex: String,

        #[arg(long)]
        sig: String,

        #[arg(long)]
        pk: String,

        #[arg(long)]
        count: usize,
    },
    /// Verify multiple Falcon signatures from a JSON file
    ///
    /// Input JSON format:
    /// [
    ///   { "root_hex": "...", "sig_hex": "...", "pk_hex": "..." }
    /// ]
    VerifyBatch {
        #[arg(long)]
        input: String,
    },
}

#[derive(Serialize)]
struct KeygenOut {
    public_key: String,
    secret_key: String,
}

#[derive(Serialize)]
struct SignOut {
    signature: String,
}

#[derive(Serialize)]
struct VerifyOut {
    valid: bool,
}

#[derive(Serialize)]
struct AggregateOut {
    signature: String,
    count: usize,
}

#[derive(Deserialize)]
struct VerifyBatchItem {
    root_hex: String,
    sig_hex: String,
    pk_hex: String,
}

#[derive(Serialize)]
struct VerifyBatchOut {
    valid: bool,
    results: Vec<bool>,
}

fn main() {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Keygen => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);

            let (sk, pk) = falcon512::keygen(seed);
            let out = KeygenOut {
                public_key: hex::encode(pk.to_bytes()),
                secret_key: hex::encode(sk.to_bytes()),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }

        Commands::Sign { root_hex, sk_hex } => {
            let root = hex::decode(root_hex).expect("root_hex must be hex");
            let sk_bytes = hex::decode(sk_hex).expect("sk_hex must be hex");
            let sk = falcon512::SecretKey::from_bytes(&sk_bytes).expect("bad secret key bytes");

            let sig = falcon512::sign(&root, &sk);
            let out = SignOut {
                signature: hex::encode(sig.to_bytes()),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }

        Commands::Verify {
            root_hex,
            sig_hex,
            pk_hex,
        } => {
            let root = hex::decode(root_hex).expect("root_hex must be hex");
            let sig_bytes = hex::decode(sig_hex).expect("sig_hex must be hex");
            let pk_bytes = hex::decode(pk_hex).expect("pk_hex must be hex");

            let sig = falcon512::Signature::from_bytes(&sig_bytes).expect("bad signature bytes");
            let pk = falcon512::PublicKey::from_bytes(&pk_bytes).expect("bad public key bytes");

            let valid = falcon512::verify(&root, &sig, &pk);
            let out = VerifyOut { valid };
            println!("{}", serde_json::to_string(&out).unwrap());
        }

        Commands::Aggregate { count, sigs } => {
            if sigs.len() != count {
                panic!(
                    "count mismatch: --count {} but got {} signatures",
                    count,
                    sigs.len()
                );
            }

            // Parse signatures
            let mut parsed: Vec<falcon512::Signature> = Vec::with_capacity(sigs.len());
            for s in sigs {
                let sig_bytes = hex::decode(s).expect("sig hex must be hex");
                let sig = falcon512::Signature::from_bytes(&sig_bytes).expect("bad signature bytes");
                parsed.push(sig);
            }

            // Fold aggregation: agg = agg(sig1, sig2, ... sigN)
            let mut agg = parsed[0].clone();
            for s in parsed.iter().skip(1) {
                agg = falcon512::aggregate_signatures(&agg, s);
            }

            let out = AggregateOut {
                signature: hex::encode(agg.to_bytes()),
                count,
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }

        Commands::VerifyAgg {
            root_hex,
            sig,
            pk,
            count,
        } => {
            let root = hex::decode(root_hex).expect("root_hex must be hex");
            let sig_bytes = hex::decode(sig).expect("sig must be hex");
            let pk_bytes = hex::decode(pk).expect("pk must be hex");

            let agg_sig =
                falcon512::Signature::from_bytes(&sig_bytes).expect("bad signature bytes");
            let pk = falcon512::PublicKey::from_bytes(&pk_bytes).expect("bad public key bytes");

            let valid = falcon512::verify_aggregated(&root, &agg_sig, &pk, count);
            let out = VerifyOut { valid };
            println!("{}", serde_json::to_string(&out).unwrap());
        }

        Commands::VerifyBatch { input } => {
        let json = fs::read_to_string(input).expect("failed to read batch input file");
        let items: Vec<VerifyBatchItem> =
            serde_json::from_str(&json).expect("invalid batch input json");

        let mut results = Vec::with_capacity(items.len());

        for item in items {
            let root = hex::decode(item.root_hex).expect("root_hex must be hex");
            let sig_bytes = hex::decode(item.sig_hex).expect("sig_hex must be hex");
            let pk_bytes = hex::decode(item.pk_hex).expect("pk_hex must be hex");

            let valid = match (
                falcon512::Signature::from_bytes(&sig_bytes),
                falcon512::PublicKey::from_bytes(&pk_bytes),
            ) {
                (Ok(sig), Ok(pk)) => falcon512::verify(&root, &sig, &pk),
                _ => false,
            };

        results.push(valid);
    }

    let out = VerifyBatchOut {
        valid: results.iter().all(|v| *v),
        results,
    };

    println!("{}", serde_json::to_string(&out).unwrap());
}
    }
}
