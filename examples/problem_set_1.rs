// :dep hex
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use base64::prelude::*; // Import Base64 encoding utilities
use hex;
use itertools::Itertools;
use std::collections::HashMap;

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

// ===================================================================================
// Challenge 4: Detect single-character XOR

/// Detect single-character XOR
///
/// One of the 60-character hex-encoded strings in the given input file
/// has been encrypted using a single-character XOR cipher.
///
/// ### Task:
/// - Read and decode each line from the file as a hex string.
/// - Use the logic from Challenge 3 to try every possible single-byte key on each line.
/// - Score each decoded result using English character frequency.
/// - Identify and return the line that produces the most "English-like" plaintext.
///
/// ### Hint:
/// Reuse your `detect_single_char_xor_cipher()` function from Challenge 3
/// to evaluate each line and select the one with the highest score.
fn detect_single_char_xor_cipher_from_file(filename: &str) {
    let best_result = std::fs::read_to_string(filename)
        .expect("Failed to read file")
        .lines()
        .filter_map(|line| hex::decode(line.as_bytes()).ok()) // Safely decode
        .map(|he| detect_single_char_xor_cipher(&he))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    if let Some((key, score, plaintext)) = best_result {
        println!("Best key: {:?} (char: '{}')", key, key as char);
        println!("Score: {:.4}", score);
        println!("Decrypted message: {}", plaintext);
    }
}

// ===================================================================================
/// Challenge 5: Implement repeating-key XOR
///
/// This challenge involves encrypting a plaintext using a repeating-key XOR cipher.
/// In this method, each byte of the plaintext is XOR'd with a corresponding byte of
/// the key, repeating the key in a cyclic manner as needed.
///
/// ### Example:
/// Encrypt the following text with the key `"ICE"`:
///
/// ```text
/// Burning 'em, if you ain't quick and nimble
/// I go crazy when I hear a cymbal
/// ```
///
/// The expected output is the following hex-encoded string:
///
/// ```text
/// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
/// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
/// ```
///
/// ### Arguments:
/// - `key_bytes`: Byte slice of the key to use for encryption (e.g. `"ICE".as_bytes()`).
/// - `clear_text_bytes`: Byte slice of the plaintext to encrypt.
///
/// ### Returns:
/// - A `Vec<u8>` containing the XOR-encrypted bytes.
///
/// ### Tip:
/// Encode the result with `hex::encode(...)` to view it as a hex string.
fn repeating_key_xor_cipher(key_bytes: &[u8], clear_text_bytes: &[u8]) -> Vec<u8> {
    let cipher_text_bytes: Vec<u8> = clear_text_bytes
        .iter()
        .enumerate()
        .map(|(i, &byte)| key_bytes[i % key_bytes.len()] ^ byte)
        .collect();

    cipher_text_bytes
}

// ===================================================================================
/// Challenge 6: Break repeating-key XOR
///
/// This challenge involves decrypting a Base64-encoded ciphertext that was encrypted
/// using a repeating-key XOR cipher (also known as a Vigenère cipher).
///
/// ### Problem:
/// You're given a file (./data/set1chall6.txt) that's been encrypted with
/// repeating-key XOR and then Base64-encoded. Your goal is to determine the
/// encryption key and decrypt the message.
///
/// ---
///
/// ### Step-by-step Guide:
///
/// 1. **Guess the Key Size:**
///     - Try different `KEYSIZE` values (typically from 2 to 40).
///     - For each candidate key size:
///         - Take the first and second chunks of `KEYSIZE` bytes from the ciphertext.
///         - Compute the **Hamming distance** (edit distance) between these chunks.
///         - Normalize by dividing by `KEYSIZE`.
///     - The key size(s) with the **lowest normalized distance** are your best guesses.
///
/// 2. **Validate Hamming Distance:**
///     - The distance between `"this is a test"` and `"wokka wokka!!!"` should be **37**.
///     - Implement a function to compute Hamming distance by counting differing bits.
///
/// 3. **Break the Cipher:**
///     - Once you have a likely key size:
///         - Split the ciphertext into `KEYSIZE`-length blocks.
///         - **Transpose** the blocks: form new blocks where each block contains all the
///           bytes at a specific position in each `KEYSIZE` block (i.e., column-wise grouping).
///         - Each transposed block is now a single-byte XOR cipher.
///         - Use your solution from **Challenge 3** to solve each block and recover a single key byte.
///
/// 4. **Recover the Full Key:**
///     - Combine the best single-byte keys from each transposed block to get the full repeating key.
///     - Use your function from **Challenge 5** to decrypt the ciphertext using the repeating key.
///
/// ---
///
/// ### Notes:
/// - This challenge is one of the most fundamental exercises in classic cryptanalysis.
/// - If you can successfully solve it, you're well-prepared to take on more advanced attacks.
///
/// ### Output:
/// - The discovered key and the fully decrypted plaintext.
fn decipher_repeating_key_xor(cipher_text_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
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
                .filter_map(|row| row.get(col_idx))
                .copied()
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

    let deciphered_text_bytes = repeating_key_xor_cipher(&key, cipher_text_bytes);

    (key, deciphered_text_bytes)
}

/// Computes the Hamming distance between two equal-length byte slices.
fn ham_dist(bs1: &[u8], bs2: &[u8]) -> usize {
    assert_eq!(bs1.len(), bs2.len());
    let mut hd: usize = 0;

    for (b1, b2) in bs1.iter().zip(bs2.iter()) {
        hd += (b1 ^ b2).count_ones() as usize;
    }

    hd
}

/// Estimates the optimal repeating-key size for a repeating-key XOR cipher
/// by minimizing the normalized average Hamming distance across byte chunks.
///
/// # Arguments
/// * `data` - The ciphertext as a slice of bytes.
///
/// # Returns
/// A tuple containing the best key size and its normalized Hamming distance.
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

        // println!("KEYSIZE({:?}): NormHammDist({:?})", key_sz, hd_norm);
    }

    println!("MIN(Normalized Hamming Distance) = {:?}", hdmin);
    println!("Corresponding KEYSIZE = {:?}", ksmin);

    (ksmin, hdmin)
}

// ===================================================================================
/// Challenge 7: AES in ECB mode
///
/// # Overview
/// This function involves decrypting data that has been encrypted with AES-128 in ECB mode.
///
/// The encryption key is:
/// `"YELLOW SUBMARINE"`
///
/// The input ciphertext is expected to be a byte slice containing a sequence of 16-byte blocks
/// (AES block size), encrypted using AES-128 in ECB mode.
///
/// # Arguments
/// * `cipher_bytes` - A slice of bytes representing the AES-128-ECB encrypted ciphertext.
///
/// # Returns
/// A `Vec<u8>` containing the plaintext bytes after decryption.
///
/// # Example
/// ```
/// let plaintext = decrypt_aes128_ecb(&ciphertext_bytes);
/// println!("Decrypted text: {:?}", String::from_utf8_lossy(&plaintext));
/// ```
///
/// # Dependencies
/// Requires the `aes` and `block-modes` crates (or just `aes` for low-level API).
fn decrypt_aes128_ecb(key: &[u8], cipher_bytes: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    assert_eq!(key_len, 16_usize); // AES128 has a key of a fixed length of 16 bytes
    let mut blocks = cipher_bytes
        .chunks_exact(key_len)
        .map(GenericArray::clone_from_slice)
        .collect::<Vec<_>>();

    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);

    cipher.decrypt_blocks(&mut blocks);

    let mut flat = Vec::with_capacity(blocks.len() * key_len);
    for block in &blocks {
        flat.extend_from_slice(block.as_slice());
    }

    flat
}

// ===================================================================================
/// Challenge 8: Detect AES in ECB mode
fn count_duplicate_vecs(chunks: Vec<&[u8]>) -> usize {
    let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();

    for slice in chunks {
        let key = slice.to_vec(); // convert &[u8] to Vec<u8>
        *counts.entry(key).or_insert(0) += 1;
    }

    // Count total number of duplicate *elements*
    let total_duplicates: usize = counts.values().filter(|&&c| c > 1).map(|&c| c - 1).sum();
    total_duplicates
}

fn challenge8() {
    let file_content_b64 = std::fs::read_to_string(
        r"/Users/belane/Projects/Current/cryptochallenge/data/set1chall8.txt",
    )
    .unwrap();

    let lines: Vec<Vec<u8>> = file_content_b64
        .lines()
        .filter_map(|line| hex::decode(line).ok())
        .collect();

    let chunked_lines: Vec<Vec<&[u8]>> = lines
        .iter()
        .map(|line| line.chunks(16).collect::<Vec<&[u8]>>())
        .collect();

    let mut max_idx = 0_usize;
    let mut max_dups = 0_usize;

    for (i, c) in chunked_lines.iter().enumerate() {
        let dups = count_duplicate_vecs(c.to_vec());
        if dups > max_dups {
            max_dups = dups;
            max_idx = i;
        }
    }

    println!("IDX: {:?}\nMAX_DUPS: {:?}", max_idx, max_dups);
}

// ===================================================================================

fn main() {
    // Challange 1
    println!("Challange 1");
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    match convert_hex_to_base64(hex_string) {
        Ok(calculated_base64_string) => {
            assert!(expected_result == calculated_base64_string);
            println!("EXPECTED RESULT:    {}", expected_result);
            println!("CALCULATEDS RESULT: {}", calculated_base64_string);
        }
        Err(e) => {
            eprintln!("FAILED: Error occurred: {}", e);
        }
    }
    println!("========================================================================");

    // Challange 2
    println!("Challange 2");
    fixed_xor();
    println!("========================================================================");

    // Challange 3
    println!("Challange 3");
    let ciphertext_bytes =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();
    let (key, score, plaintext) = detect_single_char_xor_cipher(&ciphertext_bytes);

    println!("Best key: {:?} (char: '{}')", key, key as char);
    println!("Score: {:.4}", score);
    println!("Decrypted message: {}", plaintext);
    println!("========================================================================");

    // Challange 4
    println!("Challange 4");
    let filename = "/Users/belane/Projects/Current/cryptochallenge/data/set1chall4.txt";
    detect_single_char_xor_cipher_from_file(filename);
    println!("========================================================================");

    // Challange 5
    println!("Challange 5");
    let cleartext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let test_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let calculated_ciphertex = repeating_key_xor_cipher("ICE".as_bytes(), cleartext.as_bytes());
    assert_eq!(test_ciphertext, hex::encode(&calculated_ciphertex));
    println!("EXPECTED RESULT:    {}", test_ciphertext);
    println!("CALCULATEDS RESULT: {}", hex::encode(&calculated_ciphertex));
    println!("========================================================================");

    // Challange 6
    println!("Challange 6");
    let file_content_b64 = std::fs::read_to_string(
        r"/Users/belane/Projects/Current/cryptochallenge/data/set1chall6.txt",
    )
    .unwrap();

    let file_content_in_bytes = BASE64_STANDARD
        .decode(file_content_b64.replace('\n', "").replace('\r', ""))
        .unwrap();

    let (dec_key, file_content) = decipher_repeating_key_xor(&file_content_in_bytes);

    println!("ENCRYPTION KEY:    {:?}", String::from_utf8(dec_key));
    println!(
        "FILE CONTENT:\n{}",
        String::from_utf8(file_content).unwrap()
    );

    println!("========================================================================");

    // Challange 7
    println!("Challange 7");

    let file_content_b64 = std::fs::read_to_string(
        r"/Users/belane/Projects/Current/cryptochallenge/data/set1chall7.txt",
    )
    .unwrap();

    let file_content_in_bytes = BASE64_STANDARD
        .decode(file_content_b64.replace('\n', "").replace('\r', ""))
        .unwrap();

    let file_content = decrypt_aes128_ecb(b"YELLOW SUBMARINE", &file_content_in_bytes);
    println!(
        "FILE CONTENT:\n{}",
        String::from_utf8(file_content).unwrap()
    );

    println!("========================================================================");

    // Challange 7
    println!("Challange 8");
    challenge8();
}
