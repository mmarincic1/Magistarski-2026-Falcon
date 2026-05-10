use crate::falcon;
use crate::polynomial::{hash_to_point, Polynomial};
use crate::falcon_field::Felt;
use std::ops::{Mul, Sub}; // Potrebno za matematiku u verifikaciji

// ==========================================
// TYPE ALIASES (Da ne moramo pisati <512>)
// ==========================================
pub type SecretKey = falcon::SecretKey<512>;
pub type PublicKey = falcon::PublicKey<512>;
pub type Signature = falcon::Signature<512>;

// ==========================================
// WRAPPER FUNKCIJE (Most do falcon.rs)
// ==========================================

/// Generira par ključeva.
pub fn keygen(seed: [u8; 32]) -> (SecretKey, PublicKey) {
    falcon::keygen::<512>(seed)
}

/// Standardno potpisivanje (Random salt).
pub fn sign(msg: &[u8], sk: &SecretKey) -> Signature {
    falcon::sign::<512>(msg, sk, None)
}

/// Potpisivanje sa zadanim saltom (Potrebno za agregaciju).
pub fn sign_with_salt(msg: &[u8], sk: &SecretKey, salt: [u8; 40]) -> Signature {
    falcon::sign::<512>(msg, sk, Some(salt))
}

/// Standardna verifikacija jednog potpisa.
pub fn verify(msg: &[u8], sig: &Signature, pk: &PublicKey) -> bool {
    falcon::verify::<512>(msg, sig, pk)
}

// ==========================================
// LOGIKA AGREGACIJE (Tvoj diplomski rad)
// ==========================================

/// Zbraja dva potpisa u jedan (s_agg = s_a + s_b).
pub fn aggregate_signatures(sig1: &Signature, sig2: &Signature) -> Signature {
    // Dohvaćamo dekodirane polinome (koji su popunjeni u modified sign funkciji)
    let p1 = sig1.s_decoded.as_ref().expect("Sig1 missing s_decoded");
    let p2 = sig2.s_decoded.as_ref().expect("Sig2 missing s_decoded");

    // Zbrajamo vektore koristeći našu add_poly funkciju
    let s2_agg = p1.add_poly(p2);

    Signature {
        r: sig1.r, // Salt mora biti isti
        s: vec![], // Prazno jer komprimirani dio nije bitan za agg verifikaciju
        s_decoded: Some(s2_agg),
    }
}

/// Verificira agregirani potpis.
/// Formula: || (N*c) - s_agg * h || < Limit
pub fn verify_aggregated(msg: &[u8], agg_sig: &Signature, pk: &PublicKey, num_sigs: usize) -> bool {
    let s2 = agg_sig.s_decoded.as_ref().expect("Missing s2 in agg signature");

    // 1. Hashiranje (Nonce + Msg) -> Točka c
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&agg_sig.r);
    hash_input.extend_from_slice(msg);
    let c = hash_to_point(&hash_input, 512); 

    // 2. Skaliranje točke c (Zbrajamo je samu sa sobom N puta)
    // To je ekvivalent c_agg = c_1 + c_2 + ... c_n (gdje su svi c isti)
    let mut c_agg = c.clone();
    for _ in 1..num_sigs {
        c_agg = c_agg.add_poly(&c);
    }

    // 3. Množenje s2 * h (u prstenu polinoma)
    // Obično množenje daje stupanj 1022, pa moramo reducirati modulo x^N + 1
    let prod = s2.mul(&pk.h); 
    let s2_times_h = prod.reduce_by_cyclotomic(512);
    
    // 4. Izračun vektora s1: s1 = c_agg - s2_h
    // Koristimo standardni Sub trait (-)
    let s1 = c_agg - s2_times_h;

    // 5. Provjera Euklidske norme
    let n_s1 = s1.norm_squared_euclidean();
    let n_s2 = s2.norm_squared_euclidean();
    let total_norm = n_s1 + n_s2;

    // Postavljanje granice
    // Falcon-512 standardni limit je cca 34 milijuna.
    // Za agregaciju N potpisa, očekujemo da norma raste.
    // Ovdje koristimo kvadratni rast (sigurna granica).
    let base_limit: u64 = 34_034_726; 
    let limit = base_limit * (num_sigs as u64) * (num_sigs as u64);

    println!("[DEBUG] Norm: {}, Limit: {}", total_norm, limit);

    total_norm < limit
}