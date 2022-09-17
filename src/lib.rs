mod utils;

use aes::Aes128;
use aes::cipher::BlockEncrypt;
use aes::cipher::generic_array::GenericArray;
use hex::FromHex;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    #[wasm_bindgen(js_namespace = console)]
    fn log(msg: &str);

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_arr(arr: &[u8]);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

use md5;

const PADDING: [u8; 32] = [0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
                           0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A];

fn split_in_blocks(data: Vec<u8>) -> Vec<[u8; 16]> {
    let i = 0;
    let vec = Vec::new();
    
    while i < data.len() {
        let mut arr: [u8; 16] = [0; 16];

        for j in 0..16 {
            if i + j < data.len() {
                arr[i] = data[i + j];
            } else {
                arr[i] = 0;
            }
        }
    }

    vec
}

#[wasm_bindgen]
pub fn alg_1(obj_num: i32, gen_num: i32, key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let mut data = data;
    // let num_data = data.parse::<i32>().unwrap();
    // let ultimo_byte = data.as_bytes().last().unwrap();
    let ultimo_byte = data.last().unwrap();

    if ultimo_byte % 16 == 0 {
        // AES
        console_log!("Using AES");

        new_key.append(&mut vec![0x73, 0x41, 0x6C, 0x54]);

        let hash = md5::compute(new_key);

        let key = GenericArray::from(hash.0);
    
        let cipher = Aes128::new(&key);

        let blocks = split_in_blocks(data);        

        let mut encrypted_blocks: Vec<u8> = Vec::new();
        for i in blocks {
            let mut block = GenericArray::from(i);
            cipher.encrypt_block(&mut block);
            let mut block = block.to_vec();
            encrypted_blocks.append(&mut block);
        }

        encrypted_blocks

    } else {
        // RC4
        console_log!("Using RC4");

        let hash = md5::compute(new_key);

        let mut rc4 = Rc4::<U16>::new(hash.as_slice().into());
        rc4.apply_keystream(&mut data);

        data
    }
    
}

#[wasm_bindgen]
pub fn alg_2(o: &str, p: i32, id: &str) -> Vec<u8> {
    let mut pswd_padded = Vec::from(PADDING);

    let mut o = Vec::from_hex(o).unwrap();
    pswd_padded.append(&mut o);

    let mut p_array = Vec::from(p.to_le_bytes());
    pswd_padded.append(&mut p_array);

    let mut id = Vec::from_hex(id).unwrap();
    pswd_padded.append(&mut id);

    // console_log!("{:02X?}", pswd_padded);

    let mut hash = md5::compute(pswd_padded);

    // console_log!("{:02X?} {}", hash.as_slice(), hash.len());

    for _i in 0..50 {
        hash = md5::compute(hash.as_slice());
    }

    // console_log!("{:02X?} {}", hash.0, hash.len());

    hash.0.to_vec()
}

use rc4::{consts::*, KeyInit, StreamCipher};
use rc4::{Rc4};

fn apply_xor(vec: &Vec<u8>, val: u8) -> Vec<u8> {
    let mut vec_ret = Vec::<u8>::new();

    for i in vec {
        vec_ret.push(*i ^ val);
    }

    vec_ret
}

#[wasm_bindgen]
pub fn test_alg2() {
    let hash = alg_2("347a1c17c0286dc0bdad432e7246432b67404a5a19737b19ea10ea0b6b39f89e", -1044, "a07832b34bb0befc21122fcc7cf669f9");

    let mut padding = Vec::from(PADDING);
    let mut id = Vec::from_hex("a07832b34bb0befc21122fcc7cf669f9").unwrap();
    padding.append(&mut id);

    let hash_padding = md5::compute(padding);

    let mut rc4 = Rc4::<U16>::new(hash.as_slice().into());
    let mut data = hash_padding.0.to_vec();
    rc4.apply_keystream(&mut data);

    for i in 1..=19 {
        let key = apply_xor(&hash, i);
        let mut rc4 = Rc4::<U16>::new(key.as_slice().into());
        rc4.apply_keystream(&mut data);
    }

    console_log!("{:02X?}", data.as_slice());
}