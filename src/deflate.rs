use flate2::write::ZlibDecoder;
use wasm_bindgen::prelude::*;
use std::io::Write;

use crate::utils::set_panic_hook;
use crate::*;

#[allow(dead_code)]
#[wasm_bindgen]
pub fn deflate(stream: Vec<u8>) -> Vec<u8> {
    set_panic_hook();

    let mut writer = Vec::new();
    let mut z = ZlibDecoder::new(writer);
    z.write_all(&stream[..]).unwrap();
    writer = z.finish().unwrap();

    let mut val = 0;
    let mut str = String::new();
    for i in &writer {
        val += 1;
        str.push_str(&format!("{:02X} ", i));

        if val == 6 {
            val = 0;
            str.push('\n');
        }
    }
    crate::console_log!("{}", str);

    writer
}