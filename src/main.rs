use base64::prelude::*; // Import Base64 encoding utilities
use hex;
use itertools::Itertools;



// ===================================================================================
// Challenge 1: Convert Hex to Base64
fn convert_hex_to_base64(hex_string: &str) -> Result<String, hex::FromHexError> {
    // Decode hex string into raw bytes (Vec<u8>)
    let bs = hex::decode(hex_string)?;

    // Use the base64 crate to encode the original byte array
    // and convert it into a Base64 string.
    let bb = BASE64_STANDARD.encode(bs);

    Ok(bb)
}

// ===================================================================================
/// Challenge 2: Fixed XOR
///
/// Write a function that takes two equal-length buffers and produces their XOR combination.
///
/// If your function works properly, then when you feed it the string:
///
/// `1c0111001f010100061a024b53535009181c`
///
/// ... after hex decoding, and when XOR'd against:
///
/// `686974207468652062756c6c277320657965`
///
/// ... it should produce:
///
/// `746865206b696420646f6e277420706c6179`
fn fixed_xor() {
    // First input hex string
    let hex_string1 = "1c0111001f010100061a024b53535009181c";
    let bytes_array1 = hex::decode(hex_string1).expect("Invalid hex in input1");

    // Second input hex string
    let hex_string2 = "686974207468652062756c6c277320657965";
    let bytes_array2 = hex::decode(hex_string2).expect("Invalid hex in input2");

    // XOR the bytes
    let xored_bytes: Vec<u8> = bytes_array1
        .iter()
        .zip(bytes_array2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();

    // Encode the XOR result to a hex string
    let result_hex = hex::encode(xored_bytes);

    // Check the result against the expected value
    let expected = "746865206b696420646f6e277420706c6179";
    assert_eq!(
        result_hex, expected,
        "XOR result does not match expected value"
    );
    println!("EXPECTED RESULT:    {}", expected);
    println!("CALCULATEDS RESULT: {}", result_hex);
}

// ===================================================================================
/// Challenge 3: Single-byte XOR cipher
///
/// The following hex-encoded string:
///
/// `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
///
/// ... has been XOR'd against a single character. Find the key and decrypt the message.
///
/// ### Strategy:
/// - XOR the bytes with every possible single-byte key (0–255).
/// - For each result, score the resulting plaintext using English character frequency.
/// - Return the key that yields the highest score (most likely English sentence).
///
/// ### Scoring:
/// Uses relative character frequency in the English language to determine how "English-like"
/// a given byte sequence is.

static ENG_LETTER_FREQUENCY: &[(char, f32)] = &[
    ('a', 0.0651738),
    ('b', 0.0124248),
    ('c', 0.0217339),
    ('d', 0.0349835),
    ('e', 0.1041442),
    ('f', 0.0197881),
    ('g', 0.0158610),
    ('h', 0.0492888),
    ('i', 0.0558094),
    ('j', 0.0009033),
    ('k', 0.0050529),
    ('l', 0.0331490),
    ('m', 0.0202124),
    ('n', 0.0564513),
    ('o', 0.0596302),
    ('p', 0.0137645),
    ('q', 0.0008606),
    ('r', 0.0497563),
    ('s', 0.0515760),
    ('t', 0.0729357),
    ('u', 0.0225134),
    ('v', 0.0082903),
    ('w', 0.0171272),
    ('x', 0.0013692),
    ('y', 0.0145984),
    ('z', 0.0007836),
    (' ', 0.1918182),
];

/// Returns the frequency score of a given character.
fn get_char_score(c: char) -> f32 {
    let c = c.to_ascii_lowercase();
    for &(ch, freq) in ENG_LETTER_FREQUENCY {
        if ch == c {
            return freq;
        }
    }
    0.0
}

/// Returns the total score of a sentence based on character frequency.
fn get_sentence_score(input_bytes: &[u8]) -> f32 {
    input_bytes.iter().map(|&b| get_char_score(b as char)).sum()
}

/// Tries to decrypt a single-byte XOR cipher by brute-forcing all possible keys.
/// Returns the key, its score, and the best decrypted sentence.
fn detect_single_char_xor_cipher(bytes: &[u8]) -> (u8, f32, String) {
    // Decode the hex string to bytes

    let mut max_score = 0.;
    let mut best_sentence = String::new();
    let mut best_char: u8 = 0;
    // Try to XOR with all ASCII characters
    for x in 0..=255 {
        let xor_bytes: Vec<u8> = bytes.into_iter().map(|a| a ^ x).collect();

        if let Ok(sentence) = String::from_utf8(xor_bytes.clone()) {
            let score = get_sentence_score(&xor_bytes); // or: get_sentence_score(sentence.as_bytes())

            if score > max_score {
                max_score = score;
                best_sentence = sentence;
                best_char = x;
            }
        }
    }

    (best_char, max_score, best_sentence)
}

fn get_optimal_repeating_key_size(data: &[u8]) -> (usize, f32) {
    // Now `data` is Vec<u8>
    let mut hdmin: f32 = f32::MAX;
    let mut ksmin: usize = 0;

    for key_sz in 2..=40 {
        let chunks: Vec<&[u8]> = data.chunks(key_sz).take(4).collect();

        let combs = chunks.into_iter().combinations(2).collect::<Vec<_>>();

        let hd_norm: f32 = combs
            .iter()
            .map(|x| ham_dist(x.get(0).unwrap(), x.get(1).unwrap()) as f32)
            .fold(0.0, |acc, x| acc + x)
            / combs.len() as f32
            / key_sz as f32;

        if hd_norm < hdmin {
            hdmin = hd_norm;
            ksmin = key_sz;
        }

        println!("KEYSIZE({:?}): NormHammDist({:?})", key_sz, hd_norm);
    }

    println!("MIN(Normalized Hamming Distance) = {:?}", hdmin);
    println!("Corresponding KEYSIZE = {:?}", ksmin);

    (ksmin, hdmin)
}

fn repeating_key_xor_cipher(key_bytes: &[u8], clear_text_bytes: &[u8]) -> String {
    // let key_bytes = key.as_bytes();
    // let text_bytes = clear_text.as_bytes();

    let cipher: Vec<u8> = clear_text_bytes
        .iter()
        .enumerate()
        .map(|(i, &byte)| key_bytes[i % key_bytes.len()] ^ byte)
        .collect();

    hex::encode(cipher)
}

fn decipher_repeating_key_xor(cipher_text_bytes: &[u8]) {
    // Get minimum KEYSIZE
    let (ksmin, _) = get_optimal_repeating_key_size(cipher_text_bytes);

    // At this point the choice of the KEYSIZE with the minimal Normalized

    // The next step is to break the ciphertext into blocks of KEYSIZE length
    let ks_grouped: Vec<&[u8]> = cipher_text_bytes.chunks(ksmin).collect();

    // Transpose the ks_grouped "matrix" nr_rows x kdmin_cols
    let ks_grouped_ts: Vec<Vec<u8>> = (0..ksmin)
        .map(|col_idx| {
            ks_grouped
                .iter()
                .filter_map(|row| row.get(col_idx)) // returns None if "col_idx" > "subarray's index"
                .copied() // copy the value (since `get` returns a reference)
                .collect()
        })
        .collect();

    println!(
        "Rows: {:?}, Cols: {:?}",
        ks_grouped_ts[0].len(),
        ks_grouped_ts.len()
    );

    let mut key: Vec<u8> = Vec::new();

    // Solve the single char/byte XOR as in Challenge 3 for each row
    for i in 0..=ksmin - 1 {
        let best_char = detect_single_char_xor_cipher(&ks_grouped_ts[i]);
        key.push(best_char.0);
    }

        // println!("{:?}", String::from_utf8(key));

    let deciphered_text_bytes = repeating_key_xor_cipher(&key, cipher_text_bytes)

}

fn main() {
    let input = std::fs::read_to_string(
        r"/Users/belane/Projects/Current/cryptochallenge/data/set1chall6.txt",
    )
    .unwrap();

    // Remove trailing whitespace and newlines
    let fdata = BASE64_STANDARD
        .decode(input.replace('\n', "").replace('\r', ""))
        .unwrap();

    decipher_repeating_key_xor(&fdata);
}
