use flate2::write::ZlibDecoder;
use wasm_bindgen::prelude::*;
use std::io::Write;

use crate::utils::set_panic_hook;
use crate::*;

#[allow(dead_code)]
#[wasm_bindgen]
pub fn deflate(stream: Vec<u8>, column: i32) -> Vec<u8> {
    set_panic_hook();

    let mut writer = Vec::new();
    let mut z = ZlibDecoder::new(writer);
    z.write_all(&stream[..]).unwrap();
    writer = z.finish().unwrap();

    // let mut val = 0;
    // let mut str = String::new();

    // for i in &writer {
    //     val += 1;
    //     str.push_str(&format!("{:02X} ", i));

    //     if val == column + 1 {
    //         val = 0;
    //         str.push('\n');
    //     }
    // }
    // console_log!("{}", str);

    let c = column as usize;
    let writer = filter_up(writer, c);

    // let mut val = 0;
    // let mut str = String::new();

    // for i in &writer {
    //     val += 1;
    //     str.push_str(&format!("{:02X} ", i));

    //     if val == column {
    //         val = 0;
    //         str.push('\n');
    //     }
    // }
    // console_log!("{}", str);

    writer
}

#[wasm_bindgen]
pub fn format_stream(stream: Vec<u8>, w: Vec<i32>) -> String {
    assert!(w.len() == 3);

    let mut res = String::new();

    let mut line = String::new();
    let mut i = 0;
    while i < stream.len() {
        for _j in 0..w[0] {
            line.push_str(&format!("{:02X}", i));
            i += 1;
        }
        line.push(' ');

        for _j in 0..w[1] {
            line.push_str(&format!("{:02X}", i));
            i += 1;
        }
        line.push(' ');

        for _j in 0..w[2] {
            line.push_str(&format!("{:02X}", i));
            i += 1;
        }
        line.push('\n');
        res.push_str(&line);
        line.clear();
    }

    res
}

fn filter_up(data: Vec<u8>, column: usize) -> Vec<u8> {
    let mut res = Vec::new();

    let pixels = column + 1;
    let scanlines = data.len() / pixels;

    for i in 0..scanlines {
        for j in 1..pixels {
            let up = match i.checked_sub(1) {
                Some(v) => res[v * (pixels - 1) + j - 1],
                None => 0
            };

            res.push(data[i * pixels + j] + up);
        };
    }
    
    res
}
