#![recursion_limit = "1024"]
#[macro_use] extern crate error_chain;
extern crate num;

use num::Integer;


mod errors {
    error_chain! {
        foreign_links {
        }
        errors {
            CharToDigit(c: char) {
                description("failed char to digit parsing")
                display("Unable to convert char: {}", c)
            }
            CharFromDigit(n: u32, base: u32) {
                description("failed parsing char from digit")
                display("Unable to parse number, `{}` to digit of base `{}`", n, base)
            }
            InvalidHex(n: usize) {
                description("hex input invalid length")
                display("hex input length must be a factor of 2, received size: {}", n)
            }
            InvalidXOR(n1: usize, n2: usize) {
                description("invalid xor input and key")
                display("xor input and key must be the same length, received sizes: {}, {}", n1, n2)
            }
        }
    }
}
use errors::*;
pub use errors::Error;


/// Decode hex encoded bytes
pub fn bytes_from_hex(hex_bytes: &[u8]) -> Result<Vec<u8>> {
    let len = hex_bytes.len();
    if len % 2 != 0 { bail!(ErrorKind::InvalidHex(len)) }
    let mut bytes = Vec::with_capacity(len / 2);

    #[inline]
    fn push_byte(bytes: &mut Vec<u8>, buf: &[u8]) {
        bytes.push(buf[1] + (buf[0] * 16));
    }

    let mut buf = [0; 2];
    for chunk in hex_bytes.chunks(2) {
        for (i, c) in chunk.iter().enumerate() {
            let c = *c as char;
            buf[i] = c.to_digit(16)
                .ok_or_else(|| ErrorKind::CharToDigit(c))? as u8;
        }
        push_byte(&mut bytes, &buf);
    }
    Ok(bytes)
}


/// Encode a set of bytes as a hex string
pub fn hex_from_bytes(bytes: &[u8]) -> Result<String> {
    let mut s = String::new();
    for byte in bytes {
        let (div, b) = byte.div_rem(&16);
        let a = div % 16;
        s.push(std::char::from_digit(a as u32, 16).ok_or_else(|| ErrorKind::CharFromDigit(a as u32, 16))?);
        s.push(std::char::from_digit(b as u32, 16).ok_or_else(|| ErrorKind::CharFromDigit(b as u32, 16))?);
    }
    println!("s: {}", s);
    Ok(s)
}


/// base64 encode a set of bytes
pub fn base64(bytes: &[u8]) -> Result<String> {
    #[inline]
    fn three_bytes_to_sixbit_chars(chunk: &[u8]) -> [char; 4] {
        // concat bits
        let buf = chunk.iter().fold(0u32, |acc, byte| (acc << 8) | (*byte as u32) );

        // pull bits off, MSB's to LSB's
        let indices: [u8; 4] = [((buf >> 18) & 63) as u8, ((buf >> 12) & 63) as u8, ((buf >> 6) & 63) as u8, (buf & 63) as u8];

        // translate to chars
        let mut buf = ['A'; 4];
        for (i, ind) in indices.iter().enumerate() {
            buf[i] = if *ind < 26 {
                // uppercase A-Z
                // index = 0, 'A' = 65
                (ind + 65) as char
            } else if *ind < 52 {
                // lowercase a-z
                // index = 26, 'a' = 97
                (ind + 65 + 6) as char
            } else if *ind < 62 {
                // numbers, 0-9
                // index = 52, '0' = 48
                (ind - 4) as char
            } else if *ind < 63 {
                // '+'
                // index = 62, '+' = 43
                '+'
            } else {
                // '/'
                // index = 63, '/' = 47
                '/'
            };
        }
        buf
    }

    let mut enc = String::new();
    for chunk in bytes.chunks(3) {
        let len = chunk.len();
        let chars = if len == 3 {
            three_bytes_to_sixbit_chars(chunk)
        } else {
            // trailing chunk of bytes
            let mut chars = three_bytes_to_sixbit_chars(chunk);
            chars[len-1] = if chars[len-1] == 'A' { '=' } else { chars[len-1] };
            for i in (1..len).rev() {
                if chars[i] == '=' && chars[i-1] == 'A' {
                    chars[i-1] = '=';
                }
            }
            chars
        };
        for c in &chars { enc.push(*c); }
    }
    Ok(enc)
}


/// XOR a set of bytes with a given key
pub fn xor(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() != key.len() { bail!(ErrorKind::InvalidXOR(bytes.len(), key.len())) }
    let mut xored = Vec::with_capacity(bytes.len());
    for (a, b) in bytes.iter().zip(key.iter()) {
        xored.push(a ^ b);
    }
    Ok(xored)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decodes() {
        let expected = "I'm killing your brain like a poisonous mushroom";
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = bytes_from_hex(input.as_bytes()).expect("hex decoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);

        let expected = "hit the bull's eye";
        let input = "686974207468652062756c6c277320657965";
        let bytes = bytes_from_hex(input.as_bytes()).expect("hex decoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    #[test]
    fn base64_encodes() {
        let input = "I'm killing your brain like a poisonous mushroom";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(base64(input.as_bytes()).expect("base64 encoding failed"), expected);
    }
    #[test]
    fn base64_encodes_hex_strings() {
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let byte_input = bytes_from_hex(input.as_bytes()).expect("hex decoding failed");
        assert_eq!(base64(&byte_input).expect("base64 encoding failed"), expected);
    }

    #[test]
    fn xors_things() {
        let input = "1c0111001f010100061a024b53535009181c";
        let xor_key = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let input = bytes_from_hex(input.as_bytes()).expect("failed decoding input hex");
        let xor_key = bytes_from_hex(xor_key.as_bytes()).expect("failed decoding xor-key hex");
        let xored = xor(&input, &xor_key).expect("failed to xor");
        let out = hex_from_bytes(&xored).expect("failed to hex encode");
        assert_eq!(out, expected);
    }
}
