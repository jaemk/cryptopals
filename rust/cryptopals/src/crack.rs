/*!
Cracking things
*/
use super::*;


/// xor cracking
pub mod xor {
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

    /// Calculate the chi^2 value for this string using English letter frequencies
    ///
    /// Some modifications:
    ///   - ignore inputs with 0 valid chars
    ///   - ignore inputs with invalid char ratios > 10%
    fn chi_squared(s: &[u8]) -> Result<f32> {
        let mut counts = [0u32; 27];
        let mut valid_char_count = 0u32;
        const A: u8 = 'A' as u8;
        const LOWER_A: u8 = 'a' as u8;
        const SPACE: u8 = ' ' as u8;
        //for c in s.to_uppercase().chars() {
        for c in s {
            if *c == SPACE {
                counts[26] += 1;
                valid_char_count += 1;
                continue;
            }
            let char_n = if *c > LOWER_A { c - 32 } else { *c };
            //let char_n = c as u8;
            if char_n < A || char_n > LOWER_A { continue; }

            let as_index = char_n - A;
            if as_index < 26 {
                counts[as_index as usize] += 1;
                valid_char_count += 1;
            }
        }
        if valid_char_count == 0 { bail!("bad input") }
        let valid_char_count = valid_char_count as f32;
        let invalid_ratio = (s.len() as f32 - valid_char_count) / s.len() as f32;
        if invalid_ratio > 0.1 { bail!("high invalid ratio") }

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
        pub fn empty() -> Self {
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
    fn insert_candidate(topcandidates: &mut Vec<Candidate>, new: Candidate) -> Result<f32> {
        let len = topcandidates.len();
        for i in 0..len {
            let replace_index: Option<usize> = {
                let candidate = &topcandidates[i];
                if new.score < candidate.score {
                    Some(i)
                } else {
                    None
                }
            };
            if let Some(index) = replace_index {
                topcandidates.insert(index, new);
                topcandidates.pop();
                return Ok(topcandidates[len-1].score)
            }
        }
        unreachable!();
    }

    #[inline]
    fn lenient_ascii_from_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|b| if *b < 128 { *b as char } else { '.' }).collect()
    }

    /// Given an message as a set of bytes xor-encrypted with a single-char key, determine the xor key.
    ///
    /// This solution uses character frequency analysis to rank the decoded string's in order of
    /// "most likely to be an english phrase". The lower the string's score, the higher its rank.
    /// Ignores any xor keys that produce invalid unicode.
    pub fn crack_single_char_xor(bytes: &[u8]) -> Result<Candidate> {
        let mut topten: Vec<Candidate> = vec![Candidate::empty(); 10];
        let mut highest_score = std::f32::MAX;
        let len = bytes.len();
        for n in 0..std::u8::MAX {
            let key = vec![n; len];
            let decrypted = xor(&bytes, &key)?;
            let score = match chi_squared(&decrypted) {
                Ok(f) => f,
                _ => {
                    //println!("{:?}", e);
                    continue
                }
            };
            if score < highest_score {
                let new = Candidate {
                    score: score,
                    content: lenient_ascii_from_bytes(&decrypted),
                    hexed_xor_key: Hex::new(&key).encode()?,
                    xor_key_n: n
                };
                highest_score = insert_candidate(&mut topten, new)?;
            }
        }
        //println!("{:#?}", &topten[0..5]);
        Ok(topten.remove(0))
    }


    /// From a list of hex encoded strings, find the one that's encrypted by a single-char xor
    ///
    /// Challenge 4
    pub fn find_single_char_xord_string(strings: &[&str]) -> Result<Candidate> {
        let mut topten = vec![Candidate::empty(); 10];
        let mut highest_score = std::f32::MAX;
        for s in strings {
            let decoded = Hex::new(s.as_bytes()).decode()?;
            let best_candidate = crack_single_char_xor(&decoded)?;
            if best_candidate.score < highest_score {
                highest_score = insert_candidate(&mut topten, best_candidate)?;
            }
        }
        Ok(topten.remove(0))
    }


    #[inline]
    fn normalized_average_edit_dist(chunks: &[Vec<u8>]) -> Result<f32> {
        let keysize = chunks[0].len();
        let n_chunks = chunks.len();
        //let mut total = 0;
        let mut total = 0.;
        for i in 1..n_chunks {
            //total += edit_dist(&chunks[i-1], &chunks[i])?;
            total += edit_dist(&chunks[i-1], &chunks[i])? as f32 / keysize as f32;
        }
        //let avg = (total as f32) / (n_chunks as f32);
        //Ok(avg / (keysize as f32))
        Ok(total / n_chunks as f32)
    }

    #[inline]
    fn insert_keylen_score(top: &mut Vec<(usize, f32)>, keylen: usize, score: f32) -> Result<f32> {
        let len = top.len();
        let mut replace_index = None;
        for i in 0..len {
            if score < top[i].1 {
                replace_index = Some(i);
                break;
            }
        }
        if let Some(i) = replace_index {
            top.insert(i, (keylen, score));
            top.pop();
            return Ok(top[len-1].1);
        }
        unreachable!()
    }

    pub fn crack_repeating_key_xor(bytes: &[u8]) -> Result<Candidate> {
        let max_keysize = 40;
        let mut top = vec![(0, std::f32::MAX); max_keysize - 2];
        let mut highest_score = std::f32::MAX;
        for len in 2..max_keysize {
            let chunks = bytes.chunks(len).take(2).map(|chunk| chunk.to_owned()).collect::<Vec<_>>();
            let score = normalized_average_edit_dist(&chunks)?;
            if score < highest_score {
                highest_score = insert_keylen_score(&mut top, len, score)?;
            }
        }
        println!("{:?}", &top[0..5]);
        let keylen = top[0].0;
        let mut transpose = vec![Vec::with_capacity(bytes.len() / keylen); keylen];
        for chunk in bytes.chunks(keylen) {
            for (i, byte) in chunk.iter().enumerate() {
                transpose[i].push(*byte);
            }
        }

        //println!("{:?}", &transpose[0..5]);
        let key_candidates = transpose.iter().map(|block| crack_single_char_xor(block.as_slice())).collect::<Result<Vec<_>>>()?;
        //println!("{:?}", key_candidates);
        let key = key_candidates.iter().map(|cand| cand.xor_key_n).collect::<Vec<u8>>();
        let key = key.iter().cycle().cloned().take(bytes.len()).collect::<Vec<u8>>();
        let decr = xor(bytes, &key)?;
        let s = std::str::from_utf8(&decr)?;
        println!("{:?}", s);
        Ok(Candidate::empty())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cracks_single_char_xor() {
        let expected = "Cooking MC's like a pound of bacon";
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let decoded = Hex::new(input.as_bytes())
            .decode()
            .expect("failed deciding input hex");
        let decrypted = xor::crack_single_char_xor(&decoded).expect("failed cracking single char xor");
        assert_eq!(decrypted.content, expected);
        assert_eq!(decrypted.xor_key_n, 88);
    }
}
