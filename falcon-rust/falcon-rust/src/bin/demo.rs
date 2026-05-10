use falcon_rust::falcon512;

fn main() {
    println!("========================================");
    println!("🦅  FALCON-512 DEMONSTRACIJA (POPRAVLJENO)  🦅");
    println!("========================================");

    // 1. DEFINIRANJE PORUKE
    let message = b"Ovo je tajna poruka za diplomski rad!";
    println!("\n📝 1. Poruka za potpisivanje: {:?}", String::from_utf8_lossy(message));

    // 2. GENERIRANJE KLJUČEVA
    println!("\n🔑 2. Generiranje ključeva...");
    
    // POPRAVAK 1: Kreiramo 'seed' (sjeme) za nasumičnost.
    // U produkciji ovo treba biti prava nasumičnost (rand), ovdje je fiksno za demo.
    let seed: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8
    ];

    // POPRAVAK 2: Zamijenjen redoslijed (sk, pk). Prvo ide SecretKey, pa PublicKey.
    let (sk, pk) = falcon512::keygen(seed);
    
    println!("   -> Ključevi uspješno generirani.");

    // 3. POTPISIVANJE
    println!("\n✍️  3. Potpisivanje poruke...");
    
    // Sada šaljemo ispravan tip (&sk koji je stvarno SecretKey)
    let signature = falcon512::sign(message, &sk);
    
    // POPRAVAK 3: Uklonjen ispis .len() jer je signature struktura, a ne niz.
    println!("   -> Potpis uspješno kreiran (Falcon objekt).");

    // 4. VERIFIKACIJA (ISPRAVNA)
    println!("\n🔍 4. Verifikacija ORIGINALNE poruke...");
    let valid = falcon512::verify(message, &signature, &pk);

    if valid {
        println!("   ✅ USPJEH: Potpis je VALJAN!");
    } else {
        println!("   ❌ GREŠKA: Potpis nije valjan!");
    }

    // 5. SIMULACIJA NAPADA
    println!("\n🕵️  5. Simulacija napada (Mijenjamo poruku)...");
    let fake_message = b"Ovo je LAZNA poruka!";
    
    let fake_valid = falcon512::verify(fake_message, &signature, &pk);

    if fake_valid {
        println!("   ⚠️ OPASNOST: Lažna poruka je prihvaćena!");
    } else {
        println!("   🛡️ SIGURNOST: Lažna poruka je ispravno ODBIJENA! ❌");
    }

    println!("\n========================================");
}