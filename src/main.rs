use aes::cipher::{
    generic_array::typenum::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::prelude::*;
use std::collections::HashMap;

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

fn main() {
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

    // // println!("{:?}", chunked_lines.get(0).unwrap());

    // let hs = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    // let bts = hex::decode(hs).unwrap();
    // let chunks: Vec<&[u8]> = bts.chunks(16).collect();

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

    // let chunks: Vec<[u8; 16]> = vec![
    //     [
    //         189, 32, 170, 216, 32, 201, 227, 135, 234, 87, 64, 133, 102, 229, 132, 76,
    //     ],
    //     [
    //         189, 32, 170, 216, 32, 201, 227, 135, 234, 87, 64, 133, 102, 229, 132, 76,
    //     ],
    //     [
    //         189, 32, 170, 216, 32, 201, 227, 135, 234, 87, 64, 133, 102, 229, 132, 76,
    //     ],
    // ];

    // let end = usize::min(i + 16, tc.len());
    // chunks.push(&tc[i..end]);
    // let file_content_in_bytes = file_content_b64.lines();

    // let mut blocks = file_content_in_bytes
    //     .chunks_exact(16)
    //     .map(GenericArray::clone_from_slice)
    //     .collect::<Vec<_>>();

    // let key = GenericArray::from_slice("YELLOW SUBMARINE".as_bytes());
    // let cipher = Aes128::new(&key);

    // cipher.decrypt_blocks(&mut blocks);

    // let mut flat = Vec::with_capacity(blocks.len() * 16);
    // for block in &blocks {
    //     flat.extend_from_slice(block.as_slice());
    // }

    // println!("DECRYPTED FILE CONTENT:    {:?}", String::from_utf8(flat));
}
