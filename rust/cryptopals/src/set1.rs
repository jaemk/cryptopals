/*!
Set 1 Challenges
*/
use super::*;


/// base64 encode a set of bytes
///
/// Challenge 1
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
///
/// Challenge 2
pub fn xor(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() != key.len() { bail!(ErrorKind::InvalidXOR(bytes.len(), key.len())) }
    let mut xored = Vec::with_capacity(bytes.len());
    for (a, b) in bytes.iter().zip(key.iter()) {
        xored.push(a ^ b);
    }
    Ok(xored)
}


/// Challenge 3
pub mod xor_crack {
    // https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
    use super::*;
    static EN_FREQ: [f32; 27] = [
        0.0651738, 0.0124248, 0.0217339, 0.0349835,  //'A', 'B', 'C', 'D',...
        0.1041442, 0.0197881, 0.0158610, 0.0492888,
        0.0558094, 0.0009033, 0.0050529, 0.0331490,
        0.0202124, 0.0564513, 0.0596302, 0.0137645,
        0.0008606, 0.0497563, 0.0515760, 0.0729357,
        0.0225134, 0.0082903, 0.0171272, 0.0013692,
        0.0145984, 0.0007836, 0.1918182, //'Y', 'Z', ' '
    ];

    #[allow(non_snake_case)]
    /// Calculate the chi^2 value for this string using English letter frequencies
    fn chi_squared(s: &str) -> Result<f32> {
        let mut counts = [0u8; 27];
        let mut valid_char_count = 0u8;
        let A = 'A' as u8;
        for c in s.to_uppercase().chars() {
            if c == ' ' {
                counts[26] += 1;
                valid_char_count += 1;
                continue;
            }
            let char_n = c as u8;
            if char_n < A { continue; }

            let as_index = char_n - A;
            if as_index < 26 {
                counts[as_index as usize] += 1;
                valid_char_count += 1;
            }
        }
        if valid_char_count == 0 { bail!("bad input") }
        let valid_char_count = valid_char_count as f32;

        Ok(counts.iter().enumerate().fold(0.0, |score, (index, char_count)| {
            let freq = (*char_count as f32) / valid_char_count;
            score + (freq - EN_FREQ[index]).powi(2) / EN_FREQ[index]
        }))
    }

    #[derive(Clone, Debug)]
    pub struct Candidate {
        pub score: f32,
        pub content: String,
        pub hexed_xor_key: String,
        pub xor_key_n: u8
    }
    impl Candidate {
        fn empty() -> Self {
            Self {
                score: std::f32::MAX,
                content: String::new(),
                hexed_xor_key: String::new(),
                xor_key_n: 0,
            }
        }
    }

    /// Insert a `Candidate` at its sorted-position in the list of top candidates, popping
    /// off the last to keep a constant size, returning the new highest score (the last position score)
    fn insert_score(topcandidates: &mut Vec<Candidate>, score: f32, s: &str, hexed_key: String, key_n: u8) -> Result<f32> {
        let len = topcandidates.len();
        for i in 0..len {
            let replace_index: Option<usize> = {
                let candidate = &topcandidates[i];
                if score < candidate.score {
                    Some(i)
                } else {
                    None
                }
            };
            if let Some(index) = replace_index {
                topcandidates.insert(index, Candidate{score: score, content: s.to_owned(), hexed_xor_key: hexed_key, xor_key_n: key_n});
                topcandidates.pop();
                return Ok(topcandidates[len-1].score)
            }
        }
        unreachable!();
    }

    /// Given an message as a set of bytes xor-encrypted with a single-char key, determine the xor key.
    ///
    /// This solution uses character frequency analysis to rank the decoded string's in order of
    /// "most likely to be an english phrase". The lower the string's score, the higher its rank.
    pub fn crack_single_char_xor(bytes: &[u8]) -> Result<Candidate> {
        let mut topten: Vec<Candidate> = vec![Candidate::empty(); 10];
        let mut highest_score = std::f32::MAX;
        let len = bytes.len();
        for n in 0..std::u8::MAX {
            let key = vec![n; len];
            let decoded = xor(&bytes, &key)?;
            let s = match std::str::from_utf8(&decoded) { Ok(s) => s, _ => continue, };
            let score = match chi_squared(s) { Ok(f) => f, _ => continue, };
            if score < highest_score {
                highest_score = insert_score(&mut topten, score, s, hex_encode(&key)?, n)?;
            }
        }
        Ok(topten.remove(0))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

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
        let byte_input = hex_decode(input.as_bytes()).expect("hex decoding failed");
        assert_eq!(base64(&byte_input).expect("base64 encoding failed"), expected);
    }

    #[test]
    fn xors_things() {
        let input = "1c0111001f010100061a024b53535009181c";
        let xor_key = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let input = hex_decode(input.as_bytes()).expect("failed decoding input hex");
        let xor_key = hex_decode(xor_key.as_bytes()).expect("failed decoding xor-key hex");
        let xored = xor(&input, &xor_key).expect("failed to xor");
        let out = hex_encode(&xored).expect("failed to hex encode");
        assert_eq!(out, expected);
    }
}
