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
    Ok(())
}


/// Base64 encode a hex encoded string
fn part1() -> Result<()> {
    println!("  * Challenge 1:");
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("    input: {}", input);

    let bytes = cryptopals::bytes_from_hex(input.as_bytes())?;
    let base64 = cryptopals::base64(&bytes)?;
    println!("    -> base64: {}", base64);
    Ok(())
}


/// Fixed XOR a hex encoded string
fn part2() -> Result<()> {
    println!("  * Challenge 2:");
    let input = "1c0111001f010100061a024b53535009181c";
    let xor_key = "686974207468652062756c6c277320657965";
    println!("    input: {}", input);
    println!("    xor key: {}", xor_key);

    let input = cryptopals::bytes_from_hex(input.as_bytes())?;
    let xor_key = cryptopals::bytes_from_hex(xor_key.as_bytes())?;

    let xored = cryptopals::xor(&input, &xor_key)?;
    let out = cryptopals::hex_from_bytes(&xored)?;
    println!("    -> xored: {:?}", xored);
    println!("    -> out: {:?}", out);
    Ok(())
}

