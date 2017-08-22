#![recursion_limit = "1024"]
#[macro_use] extern crate error_chain;
extern crate num;


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


pub struct Hex<'a> {
    bytes: &'a [u8],
}
impl<'a> Hex<'a> {
    pub fn new(hex_bytes: &'a [u8]) -> Self {
        Self {
            bytes: hex_bytes,
        }
    }

    /// Decode hex encoded bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        let len = self.bytes.len();
        if len % 2 != 0 { bail!(ErrorKind::InvalidHex(len)) }
        let mut bytes = Vec::with_capacity(len / 2);

        #[inline]
        fn push_byte(bytes: &mut Vec<u8>, buf: &[u8]) {
            bytes.push(buf[1] + (buf[0] * 16));
        }

        let mut buf = [0; 2];
        for chunk in self.bytes.chunks(2) {
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
    pub fn encode(&self) -> Result<String> {
        use num::Integer;  // for div_rem
        let mut s = String::new();
        for byte in self.bytes {
            let (div, b) = byte.div_rem(&16);
            let a = div % 16;
            s.push(std::char::from_digit(a as u32, 16).ok_or_else(|| ErrorKind::CharFromDigit(a as u32, 16))?);
            s.push(std::char::from_digit(b as u32, 16).ok_or_else(|| ErrorKind::CharFromDigit(b as u32, 16))?);
        }
        Ok(s)
    }
}


/// xor two slices
pub fn xor<'a>(src: &'a [u8], key: &'a [u8]) -> Result<Vec<u8>> {
    if src.len() != key.len() {
        bail!(ErrorKind::InvalidXOR(src.len(), key.len()))
    }
    let mut buf = Vec::with_capacity(src.len());
    for (a, b) in src.iter().zip(key.iter()) {
        buf.push(a ^ b);
    }
    Ok(buf)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decodes() {
        let expected = "I'm killing your brain like a poisonous mushroom";
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = Hex::new(input.as_bytes()).decode().expect("hex decoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);

        let expected = "hit the bull's eye";
        let input = "686974207468652062756c6c277320657965";
        let bytes = Hex::new(input.as_bytes()).decode().expect("hex decoding failed");
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }

    #[test]
    fn hex_encodes() {
        let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let input = "I'm killing your brain like a poisonous mushroom";
        let s = Hex::new(input.as_bytes()).encode().expect("hex encoding failed");
        assert_eq!(s, expected);

        let expected = "686974207468652062756c6c277320657965";
        let input = "hit the bull's eye";
        let s = Hex::new(input.as_bytes()).encode().expect("hex encoding failed");
        assert_eq!(s, expected);
    }

    #[test]
    fn xors_things() {
        let input = "1c0111001f010100061a024b53535009181c";
        let xor_key = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let input = Hex::new(input.as_bytes()).decode().expect("failed decoding input hex");
        let xor_key = Hex::new(xor_key.as_bytes()).decode().expect("failed decoding xor-key hex");
        let xored = xor(&input, &xor_key).expect("failed to xor");
        let out = Hex::new(&xored).encode().expect("failed to hex encode");
        assert_eq!(out, expected);
    }

    #[test]
    fn xors_with_repeating_key() {
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        let input_bytes = input.as_bytes();
        let repeating_key = "ICE".bytes().cycle().take(input_bytes.len()).collect::<Vec<u8>>();
        let encrypted = xor(input_bytes, &repeating_key)
            .expect("failed xoring input");
        let encoded = Hex::new(&encrypted).encode().expect("failed encoding bytes");
        assert_eq!(expected, encoded);
    }
}
