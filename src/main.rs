use aes::cipher::{
    generic_array::typenum::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::prelude::*;
use itertools::Itertools; // Import Base64 encoding utilities

fn repeating_key_xor_cipher(key_bytes: &[u8], clear_text_bytes: &[u8]) -> Vec<u8> {
    let cipher_text_bytes: Vec<u8> = clear_text_bytes
        .iter()
        .enumerate()
        .map(|(i, &byte)| key_bytes[i % key_bytes.len()] ^ byte)
        .collect();

    cipher_text_bytes
}

pub fn decrypt_message(base64_bytes: &[u8], key_str: &str) -> String {
    let key = GenericArray::clone_from_slice(key_str.as_bytes());

    // Construct blocks of 16 byte size for AES-128
    let mut blocks = Vec::new();
    (0..base64_bytes.len()).step_by(16).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(&base64_bytes[x..x + 16]));
    });

    // Initialize cipher
    let cipher = Aes128::new(&key);
    cipher.decrypt_blocks(&mut blocks);

    blocks.iter().flatten().map(|&x| x as char).collect()
}

fn main() {
    let file_content_b64 = std::fs::read_to_string(
        r"/Users/belane/Projects/Current/cryptochallenge/data/set1chall7.txt",
    )
    .unwrap();

    let file_content_in_bytes = BASE64_STANDARD
        .decode(file_content_b64.replace('\n', "").replace('\r', ""))
        .unwrap();

    let mut blocks = file_content_in_bytes
        .chunks_exact(16)
        .map(GenericArray::clone_from_slice)
        .collect::<Vec<_>>();

    let key = GenericArray::from_slice("YELLOW SUBMARINE".as_bytes());
    let cipher = Aes128::new(&key);

    cipher.decrypt_blocks(&mut blocks);

    let mut flat = Vec::with_capacity(blocks.len() * 16);
    for block in &blocks {
        flat.extend_from_slice(block.as_slice());
    }

    println!("DECRYPTED FILE CONTENT:    {:?}", String::from_utf8(flat));
}
