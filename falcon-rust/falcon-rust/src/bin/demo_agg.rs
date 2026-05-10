use falcon_rust::falcon512;

fn main() {
    println!("🦅 FALCON AGREGACIJA (ISTI SALT) 🦅");

    let message = b"Master rad test";
    let seed = [55u8; 32];
    let (sk, pk) = falcon512::keygen(seed);

    // 1. Generiramo PRVI potpis (random salt)
    println!("✍️  Potpis 1 (Generator)...");
    let sig1 = falcon512::sign(message, &sk);
    
    // Kopiramo salt iz prvog potpisa
    let common_salt = sig1.r; 
    println!("   -> Salt: {:?}", &common_salt[0..5]);

    // 2. Generiramo DRUGI potpis (forsiramo ISTI salt)
    println!("✍️  Potpis 2 (Isti salt)...");
    let sig2 = falcon512::sign_with_salt(message, &sk, common_salt);
    println!("   -> Salt: {:?}", &sig2.r[0..5]);

    // 3. Agregacija
    println!("🔗 Agregiram...");
    let agg_sig = falcon512::aggregate_signatures(&sig1, &sig2);

    // 4. Verifikacija
    println!("🔍 Verificiram...");
    let result = falcon512::verify_aggregated(message, &agg_sig, &pk, 2);

    if result {
        println!("\n✅✅✅ USPJEH! Agregacija radi! ✅✅✅");
        println!("Norma je unutar granica jer dijelimo isti c (hash točku).");
    } else {
        println!("\n❌ Neuspjeh.");
    }
}