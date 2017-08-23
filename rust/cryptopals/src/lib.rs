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
            InvalidSlices(n1: usize, n2: usize) {
                description("differently sized input slices")
                display("input slices must be the same length, received sizes: {}, {}", n1, n2)
            }
        }
    }
}
use errors::*;
pub use errors::Error;

pub mod crack;


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


/// base64 encode/decode a set of bytes
pub mod base64 {
    use super::errors::*;
    const A: u8         = 'A' as u8;
    const Z: u8         = 'Z' as u8;
    const LOWER_A: u8   = 'a' as u8;
    const LOWER_Z: u8   = 'z' as u8;
    const ZERO: u8      = '0' as u8;
    const NINE: u8      = '9' as u8;
    const PLUS: u8      = '+' as u8;
    const SLASH: u8     = '/' as u8;
    const EQ: u8        = '=' as u8;

    // base64 indices -- offset => `char-code + offset = index`
    const A_IND: u8         = 0;    // offset -65
    const Z_IND: u8         = 25;   // --- ^^ ---
    const LOWER_A_IND: u8   = 26;   // offset -71
    const LOWER_Z_IND: u8   = 51;   // --- ^^ ---
    const ZERO_IND: u8      = 52;   // offset +4
    const NINE_IND: u8      = 61;   // --- ^^ ---
    const PLUS_IND: u8      = 62;
    const SLASH_IND: u8     = 63;

    pub struct Decode<'a> {
        bytes: &'a [u8],
    }
    impl<'a> Decode<'a> {
        pub fn from_bytes(bytes: &'a [u8]) -> Self {
            Self { bytes }
        }
        pub fn from_str(s: &'a str) -> Self {
            Self { bytes: s.as_bytes() }
        }
        #[inline]
        fn four_chars_to_three_bytes(chunk: &[u8]) -> [u8; 3] {
            let mut bytes = [0; 4];
            // translate char codes to base64 indices
            for (i, c) in chunk.iter().enumerate() {
                bytes[i] = match *c {
                    A...Z               => c - 65,
                    LOWER_A...LOWER_Z   => c - 71,
                    ZERO...NINE         => c + 4,
                    SLASH               => SLASH,
                    PLUS                => PLUS,
                    EQ                  => 0,
                    _ => unimplemented!(),
                };
            }
            // smash the four 6bit chars together and split into three bytes
            let buf = bytes.iter().fold(0u32, |acc, byte| (acc << 6) | (*byte as u32));
            [((buf >> 16) & 255) as u8, ((buf >> 8) & 255) as u8, (buf & 255) as u8]
        }

        pub fn decode(&self) -> Result<Vec<u8>> {
            let mut buf = Vec::with_capacity(self.bytes.len() / 4 * 3);
            for chunk in self.bytes.chunks(4) {
                let bytes = Self::four_chars_to_three_bytes(chunk);
                for b in &bytes { buf.push(*b); }
            }
            let mut discard = 0;
            for b in buf.iter().rev() {
                if *b == 0 { discard += 1; } else { break; }
            }
            if discard > 0 {
                let len = buf.len();
                buf.truncate(len - discard);
            }
            Ok(buf)
        }
    }

    pub struct Encode<'a> {
        bytes: &'a [u8],
        one_line: bool,
    }
    impl<'a> Encode<'a> {
        pub fn from_bytes(bytes: &'a [u8]) -> Self {
            Self {
                bytes: bytes,
                one_line: false,
            }
        }

        /// Dump encoded bytes as one line
        pub fn one_line(&mut self, one_line: bool) -> &mut Self {
            self.one_line = one_line;
            self
        }

        #[inline]
        fn three_bytes_to_sixbit_chars(chunk: &[u8]) -> [char; 4] {
            // concat bits
            let mut buf = chunk.iter().fold(0u32, |acc, byte| (acc << 8) | (*byte as u32) );
            for _ in 0..(3-chunk.len()) {
                buf = buf << 8;
            }

            // pull off 6bit chunks, MSB's to LSB's
            //  11111111 00000000 11111111 00000000
            // |---a----|---b----|---c----|---d----|
            let indices: [u8; 4] = [((buf >> 18) & 63) as u8, ((buf >> 12) & 63) as u8, ((buf >> 6) & 63) as u8, (buf & 63) as u8];

            // translate base64 indices to chars
            let mut buf = ['A'; 4];
            for (i, ind) in indices.iter().enumerate() {
                buf[i] = match *ind {
                    A_IND ... Z_IND             => (ind + 65) as char,
                    LOWER_A_IND ... LOWER_Z_IND => (ind + 71) as char,
                    ZERO_IND ... NINE_IND       => (ind - 4) as char,
                    PLUS_IND                    => '+',
                    SLASH_IND                   => '/',
                    _ => unimplemented!(),
                };
            }
            buf
        }

        pub fn encode(&self) -> Result<String> {

            let mut enc = String::new();
            let mut count = 0;
            for chunk in self.bytes.chunks(3) {
                let len = chunk.len();
                let chars = if len == 3 {
                    Self::three_bytes_to_sixbit_chars(chunk)
                } else {
                    // trailing chunk of bytes
                    let mut chars: [char; 4] = Self::three_bytes_to_sixbit_chars(chunk);
                    chars[3] = if chars[3] == 'A' { '=' } else { chars[3] };
                    for i in (1..len).rev() {
                        if chars[i] == '=' && chars[i-1] == 'A' {
                            chars[i-1] = '=';
                        }
                    }
                    chars
                };
                for c in &chars {
                    if !self.one_line && count == 60 {
                        enc.push('\n');
                        count = 0;
                    }
                    enc.push(*c);
                    count += 1;
                }
            }
            Ok(enc)
        }
    }
}


/// xor two slices
pub fn xor(src: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if src.len() != key.len() {
        bail!(ErrorKind::InvalidSlices(src.len(), key.len()))
    }
    let mut buf = Vec::with_capacity(src.len());
    for (a, b) in src.iter().zip(key.iter()) {
        buf.push(a ^ b);
    }
    Ok(buf)
}


/// Calculates the edit/hamming distance (differing number of bits)
/// between two slices
pub fn edit_dist(a: &[u8], b: &[u8]) -> Result<u32> {
    if a.len() != b.len() {
        bail!(ErrorKind::InvalidSlices(a.len(), b.len()))
    }
    #[inline]
    fn count_ones(n: u8) -> u32 {
        // rust primitive ints have a `count_ones` method that will
        // do a faster popcount if supported. Just doing this for the sake of doing it
        // n.count_ones()
        (0..8).fold(0, |acc, sh| acc + ((n >> sh) & 1) as u32)
    }
    Ok(a.iter().zip(b.iter()).fold(0, |acc, (a, b)| {
        acc + count_ones(a ^ b)
    }))
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

    #[test]
    fn base64_encodes() {
        let input = "I'm killing your brain like a poisonous mushroom";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(base64::Encode::from_bytes(input.as_bytes()).one_line(true).encode().expect("base64 encoding failed"), expected);

        let input = "this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test";
        let expected = "dGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3Q=";
        assert_eq!(base64::Encode::from_bytes(input.as_bytes()).one_line(true).encode().expect("base64 encoding failed"), expected);
    }

    #[test]
    fn base64_decodes() {
        let input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let expected = "I'm killing your brain like a poisonous mushroom";
        let decoded_bytes = base64::Decode::from_bytes(input.as_bytes()).decode().expect("base64 encoding failed");
        let decoded = std::str::from_utf8(&decoded_bytes).expect("bad utf8");
        assert_eq!(decoded, expected);

        let input = "dGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3QgdGhpcyBpcyBhIHRlc3Q=";
        let expected = "this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test this is a test";
        let decoded_bytes = base64::Decode::from_str(input).decode().expect("base64 decoding failed");
        assert_eq!(std::str::from_utf8(&decoded_bytes).expect("bad utf8"), expected);
    }

    #[test]
    fn base64_encodes_hex_strings() {
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let byte_input = Hex::new(input.as_bytes())
            .decode()
            .expect("hex decoding failed");
        assert_eq!(base64::Encode::from_bytes(&byte_input).one_line(true).encode().expect("base64 encoding failed"), expected);
    }

    #[test]
    fn calculates_edit_distance() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        let expected = 37;
        let dist = edit_dist(a.as_bytes(), b.as_bytes()).expect("failed to calculate edit distance");
        assert_eq!(dist, expected);
    }

}
