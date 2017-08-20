#![recursion_limit = "1024"]
#[macro_use] extern crate error_chain;
extern crate cryptopals;


mod errors {
    use super::*;
    error_chain! {
        foreign_links {
            Crypto(cryptopals::Error);
        }
    }
}
use errors::*;


quick_main!(run);


fn run() -> Result<()> {
    set1()?;

    Ok(())
}


fn set1() -> Result<()> {
    println!("* Set 1:");
    part1()?;
    part2()?;
    part3()?;
    Ok(())
}


/// Base64 encode a hex encoded string
fn part1() -> Result<()> {
    println!("  * Challenge 1:");
    println!("   -- base64 encode a hex encoded message --");
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("    input: {}", input);

    let bytes = cryptopals::hex_decode(input.as_bytes())?;
    let base64 = cryptopals::set1::base64(&bytes)?;
    println!("    -> base64: {}", base64);
    Ok(())
}


/// Fixed XOR a hex encoded string
fn part2() -> Result<()> {
    println!("  * Challenge 2:");
    println!("   -- xor-encrypt a hex encoded message --");
    let input = "1c0111001f010100061a024b53535009181c";
    let xor_key = "686974207468652062756c6c277320657965";
    println!("    input: {}", input);
    println!("    xor key: {}", xor_key);

    let input = cryptopals::hex_decode(input.as_bytes())?;
    let xor_key = cryptopals::hex_decode(xor_key.as_bytes())?;

    let xored = cryptopals::set1::xor(&input, &xor_key)?;
    let out = cryptopals::hex_encode(&xored)?;
    println!("    -> xored: {:?}", xored);
    println!("    -> out: {:?}", out);
    Ok(())
}


/// Crack the single character xor decryption key
fn part3() -> Result<()> {
    println!("  * Challenge 3:");
    println!("   -- find the encryption key for a message xor-encrypted with a single character --");
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    println!("    input: {}", input);
    let input_bytes = cryptopals::hex_decode(input.as_bytes())?;
    let cracked = cryptopals::set1::xor_crack::crack_single_char_xor(&input_bytes)?;
    println!("    -> cracked message: {}", cracked.content);
    println!("    -> cracked xor key (byte): {}", cracked.xor_key_n);
    println!("    -> cracked xor key (full hex): {}", cracked.hexed_xor_key);
    Ok(())
}
