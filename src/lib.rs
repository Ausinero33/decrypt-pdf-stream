mod utils;
mod deflate;

use std::sync::Mutex;

use aes::cipher::BlockEncryptMut;
use deflate::filters::FlateDecode;
use hex::FromHex;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use crypto::{rc4::Rc4, symmetriccipher::SynchronousStreamCipher};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use md5;
use lazy_static::lazy_static;

lazy_static! {
    static ref PDF: Mutex<PDF_Struct> = Mutex::new(PDF_Struct::new());
}

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

pub(crate) use console_log;

const PADDING: [u8; 32] = [0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
                           0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A];

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

// https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf

#[wasm_bindgen]
pub fn encrypt(obj_num: i32, gen_num: i32, key: Vec<u8>, stream: Vec<u8>, rev: i32, cfm: &str) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let mut new_key = key;
    new_key.append(&mut obj_num.to_vec());
    new_key.append(&mut gen_num.to_vec());

    let data = stream;

    if rev < 4 {
        use_rc4(&data, &new_key)
    } else {
        match cfm {
            "None" => data,
            "V2" => use_rc4(&data, &new_key),
            "AESV2" => use_aes_encrypt(&data, new_key),
            _ => panic!("Wrong CFM")
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(obj_num: i32, gen_num: i32, key: &[u8], stream: Vec<u8>, rev: i32, cfm: &str) -> Vec<u8> {
    let obj_num = &obj_num.to_le_bytes()[0..3];
    let gen_num = &gen_num.to_le_bytes()[0..2];

    let new_key = [key, obj_num, gen_num].concat();

    if rev < 4 {
        use_rc4(&stream, &new_key)
    } else {
        match cfm {
            "None" => stream.to_vec(),
            "V2" => use_rc4(&stream, &new_key),
            "AESV2" => use_aes_decrypt(stream, new_key),
            _ => panic!("Wrong CFM")
        }
    }
}

fn use_rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    console_log!("Using RC4");

    let hash = md5::compute(key);

    let mut res = Vec::new();
    let mut rc4 = Rc4::new(&hash.0);
    rc4.process(data, &mut res);
    
    res
}

fn use_aes_encrypt(data: &[u8], mut key: Vec<u8>) -> Vec<u8> {
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

// #[derive(Clone, Copy)]
// enum Filter {
//     // Values: Predictor, Colors, BitsPerComponent, Columns
//     FlateDecode(i32, i32, i32, i32),
//     // Values: Predictor, Colors, BitsPerComponent, Columns, EarlyChange
//     LZWDecode(i32, i32, i32, i32, i32),
// }


#[derive(Default)]
struct Object {
    stream: Vec<u8>,
    filter: Option<Box<dyn crate::deflate::filters::Filter + Send + Sync>>,
}

struct PDF_Struct {
    // encryption_info: //TODO
    objects: Vec<Object>,
}

impl PDF_Struct {
    pub fn new() -> Self {
        Self { 
            objects: Vec::new() 
        }
    }
}

// TODO Returns the Object stored in PDF_OBJECTS
fn get_obj(obj_num: i32) -> Object {
    PDF.lock().unwrap().objects.pop().unwrap()
}

#[wasm_bindgen]
pub fn parse_obj() {
    // TODO
    PDF.lock().unwrap().objects.push(Object::default())
}

#[wasm_bindgen]
pub fn add_obj(index_start: usize, index_end: usize, doc: &[u8]) {
    console_log!("{:02X?}", doc[index_start..index_end].to_vec());
    PDF.lock().unwrap().objects.push(
        Object { 
            stream: doc[index_start..index_end].to_vec(), 
            filter: Some(Box::new(FlateDecode {
                predictor: 12,
                columns: 5,
                ..Default::default()
            }))
        }
    )
}