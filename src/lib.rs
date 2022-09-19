mod utils;

use aes::Aes128;
use aes::cipher::BlockEncrypt;
use aes::cipher::generic_array::GenericArray;
use hex::FromHex;
use wasm_bindgen::prelude::*;
use rc4::{consts::*, KeyInit, StreamCipher};
use rc4::{Rc4};

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


#[wasm_bindgen]
pub fn decrypt(obj_num: i32, gen_num: i32, key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let mut data = data;
    let last_byte = data.last().unwrap();

    if last_byte % 16 == 0 {
        // TODO AES

        panic!("AES not yet implemented.")

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
pub fn get_key(o: &str, p: i32, id: &str) -> Vec<u8> {
    let mut pswd_padded = Vec::from(PADDING);

    let mut o = Vec::from_hex(o).unwrap();
    pswd_padded.append(&mut o);

    let mut p_array = Vec::from(p.to_le_bytes());
    pswd_padded.append(&mut p_array);

    let mut id = Vec::from_hex(id).unwrap();
    pswd_padded.append(&mut id);


    let mut hash = md5::compute(pswd_padded);

    for _i in 0..50 {
        hash = md5::compute(hash.as_slice());
    }

    hash.0.to_vec()
}