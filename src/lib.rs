mod utils;

use aes::cipher::BlockEncryptMut;
use aes::cipher::generic_array::GenericArray;
use hex::FromHex;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use rc4::{consts::*, KeyInit, StreamCipher};
use rc4::{Rc4};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use rand::prelude::*;

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

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u8(num: u8);

    #[wasm_bindgen(js_namespace = console)]
    fn error(msg: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

use md5;

const PADDING: [u8; 32] = [0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
                           0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A];

// fn split_in_blocks(data: &Vec<u8>) -> Vec<GenericArray<u8, U16>> {
//     let mut i = 0;
//     let mut vec = Vec::new();
    
//     while i < data.len() {
//         let padding = 16 - (data.len() % 16);

//         let mut arr: GenericArray<u8, U16> = GenericArray::clone_from_slice(&vec![padding as u8; 16]);

//         for j in 0..(16 - padding) {
//             if i + j < data.len() {
//                 arr[j] = data[i + j];
//             } else {
//                 arr[j] = 0;
//             }
//         }

//         i += 16;
//         vec.push(arr);

//         if padding == 0x10 {vec.push(arr)}

//         console_log!("A {:?}", arr.as_slice());
//     }

//     vec
// }

// #[wasm_bindgen]
// pub fn test_split_in_blocks() {
//     let data = vec![0x01, 0x02, 0xF0];
//     let blocks = split_in_blocks(&data);

//     for i in blocks {
//         assert_eq!(i.as_slice(), &[0x01, 0x02, 0xF0, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D]);
//     }
// }

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

#[wasm_bindgen]
pub fn encrypt(obj_num: i32, gen_num: i32, key: Vec<u8>, stream: Vec<u8>) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let mut data = stream;
    let last_byte = data.last().unwrap();

    if /* last_byte % 16 == 0 */ true {
        // AES (Testing needed)
        console_log!("Using AES");

        new_key.append(&mut vec![0x73, 0x41, 0x6C, 0x54]);

        let hash = md5::compute(new_key);

        let key = hash.0;

        let mut iv = [0x00u8; 16];
        for i in &mut iv {
            *i = rand::random::<u8>();
        }
        let mut iv_vec = iv.to_vec();

        let data_len = data.len();

        let div = (data_len + 16) / 16;
        let mut data_extended = vec![0x00; div * 16];
        for (pos, element) in data.iter().enumerate() {
            data_extended[pos] = *element;
        }

        let mut pt = Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut data_extended, data_len)
            .unwrap()
            .to_vec();

        iv_vec.append(&mut pt);

        iv_vec

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
pub fn decrypt(obj_num: i32, gen_num: i32, key: Vec<u8>, stream: Vec<u8>) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let mut data = stream;
    let last_byte = data.last().unwrap();

    if /* last_byte % 16 == 0 */ true {
        // AES (Testing needed)
        console_log!("Using AES");

        new_key.append(&mut vec![0x73, 0x41, 0x6C, 0x54]);

        let hash = md5::compute(new_key);

        let key = hash.0;

        let mut iv = [0x00u8; 16];
        for (elem, i) in data.iter().zip(0..16) {
            iv[i] = *elem;
        }

        let pt = Aes128CbcDec::new(&key.into(), &iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut data[16..])
            .unwrap();

        pt.to_vec()

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
    set_panic_hook();

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