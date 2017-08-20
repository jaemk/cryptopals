#![recursion_limit = "1024"]
#[macro_use] extern crate error_chain;
extern crate num;

use num::Integer;


mod errors {
    error_chain! {
        foreign_links {
            Utf(::std::str::Utf8Error);
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

pub mod set1;


/// Decode hex encoded bytes
pub fn hex_decode(hex_bytes: &[u8]) -> Result<Vec<u8>> {
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
pub fn hex_encode(bytes: &[u8]) -> Result<String> {
    let mut s = String::new();
    for byte in bytes {
        let (div, b) = byte.div_rem(&16);
        let a = div % 16;
        s.push(std::char::from_digit(a as u32, 16).ok_or_else(|| ErrorKind::CharFromDigit(a as u32, 16))?);
        s.push(std::char::from_digit(b as u32, 16).ok_or_else(|| ErrorKind::CharFromDigit(b as u32, 16))?);
    }
    Ok(s)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decodes() {
        let expected = "I'm killing your brain like a poisonous mushroom";
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex_decode(input.as_bytes()).expect("hex decoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);

        let expected = "hit the bull's eye";
        let input = "686974207468652062756c6c277320657965";
        let bytes = hex_decode(input.as_bytes()).expect("hex decoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    #[test]
    fn hex_encodes() {
        let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let input = "I'm killing your brain like a poisonous mushroom";
        let bytes = hex_encode(input.as_bytes()).expect("hex encoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);

        let expected = "686974207468652062756c6c277320657965";
        let input = "hit the bull's eye";
        let bytes = hex_encode(input.as_bytes()).expect("hex encoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }
}
