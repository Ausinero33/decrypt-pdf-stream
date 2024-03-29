mod utils;

use aes::cipher::BlockEncryptMut;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hex::FromHex;
use md5;
use rc4::Rc4;
use rc4::{consts::*, KeyInit, StreamCipher};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
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

const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

// https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf

#[wasm_bindgen]
pub fn encrypt(
    obj_num: i32,
    gen_num: i32,
    key: Vec<u8>,
    stream: Vec<u8>,
    rev: i32,
    cfm: &str,
) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let data = stream;

    if rev < 4 {
        use_rc4(data, new_key)
    } else {
        match cfm {
            "None" => data,
            "V2" => use_rc4(data, new_key),
            "AESV2" => use_aes_encrypt(data, new_key),
            _ => panic!("Wrong CFM"),
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(
    obj_num: i32,
    gen_num: i32,
    key: Vec<u8>,
    stream: Vec<u8>,
    rev: i32,
    cfm: &str,
) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let data = stream;

    if rev < 4 {
        use_rc4(data, new_key)
    } else {
        match cfm {
            "None" => data,
            "V2" => use_rc4(data, new_key),
            "AESV2" => use_aes_decrypt(data, new_key),
            _ => panic!("Wrong CFM"),
        }
    }
}

fn use_rc4(mut data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    console_log!("Using RC4");

    let hash = md5::compute(key);

    let mut rc4 = Rc4::<U16>::new(hash.as_slice().into());
    rc4.apply_keystream(&mut data);

    data
}

fn use_aes_encrypt(data: Vec<u8>, mut key: Vec<u8>) -> Vec<u8> {
    console_log!("Using AES");

    key.append(&mut vec![0x73, 0x41, 0x6C, 0x54]);

    let hash = md5::compute(key);

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
        .unwrap_or_default()
        .to_vec();

    iv_vec.append(&mut pt);

    iv_vec
}

fn use_aes_decrypt(mut data: Vec<u8>, mut key: Vec<u8>) -> Vec<u8> {
    console_log!("Using AES");

    key.append(&mut vec![0x73, 0x41, 0x6C, 0x54]);

    let hash = md5::compute(key);

    let key = hash.0;

    let mut iv = [0x00u8; 16];
    for (elem, i) in data.iter().zip(0..16) {
        iv[i] = *elem;
    }

    let pt = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut data[16..])
        .unwrap();

    pt.to_vec()
}

#[wasm_bindgen]
pub fn get_key(o: &str, p: i32, id: &str, rev: i32) -> Vec<u8> {
    set_panic_hook();

    let mut pswd_padded = Vec::from(PADDING);

    let mut o = Vec::from_hex(o).unwrap();
    pswd_padded.append(&mut o);

    let mut p_array = Vec::from(p.to_le_bytes());
    pswd_padded.append(&mut p_array);

    let mut id = Vec::from_hex(id).unwrap();
    pswd_padded.append(&mut id);

    if rev >= 4 {
        pswd_padded.append(&mut vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    let mut hash = md5::compute(pswd_padded);

    if rev >= 3 {
        for _i in 0..50 {
            hash = md5::compute(hash.as_slice());
        }
    }

    hash.0.to_vec()
}

#[wasm_bindgen]
pub fn get_key_from_password(pw: &str, o: Vec<u8>, p: i32, id: Vec<u8>, rev: i32) -> Vec<u8> {
    set_panic_hook();

    let mut pswd_padded = Vec::from(pw.as_bytes());

    pswd_padded.truncate(32);

    if pswd_padded.len() < 32 {
        for i in 0..32 - pswd_padded.len() {
            pswd_padded.push(PADDING[i]);
        }
    }

    let mut o_tmp = o.clone();
    pswd_padded.append(&mut o_tmp);

    let mut p_array = Vec::from(p.to_le_bytes());
    pswd_padded.append(&mut p_array);

    let mut id_mut = id.clone();
    pswd_padded.append(&mut id_mut);

    if rev >= 4 {
        pswd_padded.append(&mut vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    let mut hash = md5::compute(pswd_padded);

    if rev >= 3 {
        for _i in 0..50 {
            hash = md5::compute(hash.as_slice());
        }
    }

    hash.0.to_vec()
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use crate::{get_key_from_password, get_key};

    #[test]
    fn test_pw() {
        let pw = "";
        let o = Vec::from_hex("347a1c17c0286dc0bdad432e7246432b67404a5a19737b19ea10ea0b6b39f89e").unwrap();
        let id = Vec::from_hex("a07832b34bb0befc21122fcc7cf669f9").unwrap();
        let x = get_key_from_password(pw, o, -1044, id, 3);
    

        let y = get_key("347a1c17c0286dc0bdad432e7246432b67404a5a19737b19ea10ea0b6b39f89e", -1044, "a07832b34bb0befc21122fcc7cf669f9", 3);
        assert_eq!(x, y);
    }
}
