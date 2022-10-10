use flate2::write::ZlibDecoder;
use wasm_bindgen::prelude::*;
use std::io::Write;

use crate::utils::set_panic_hook;
use crate::*;

#[allow(dead_code)]
#[wasm_bindgen]
pub fn decompress(obj: Object) -> Vec<u8> {
    set_panic_hook();

    if let Some(filter) = obj.filter {
        match filter {
            Filter::FlateDecode(pred, color, bpc, column) => {
                let mut writer = Vec::new();
                let mut z = ZlibDecoder::new(writer);
                z.write_all(&obj.stream[..]).unwrap();
                writer = z.finish().unwrap();
                
                apply_predictor(&writer, pred, column) 
            },
            Filter::LZWDecode(pred, color, bpc, cols, early_change) => {
                Vec::new()  // TODO
            }
        }
    } else {
        obj.stream
    }
}

fn apply_predictor(data: &[u8], predictor: i32, column: i32) -> Vec<u8> {
    match predictor {
        1 => data.to_vec(),
        2 => data.to_vec(),     // TODO TIFF PRED 2
        10 => data.to_vec(),    // TODO PNG NONE
        11 => data.to_vec(),    // TODO PNG SUB
        12 => png_up(data, column as usize),
        13 => data.to_vec(),    // TODO PNG AVG
        14 => data.to_vec(),    // TODO PNG PAETH
        15 => data.to_vec(),    // TODO PNG OPTIMUM
        _ => data.to_vec(),
    }
}

#[allow(dead_code)]
#[wasm_bindgen]
pub fn format_stream(stream: Vec<u8>, w: Vec<i32>) -> String {
    assert!(w.len() == 3);

    let mut res = String::new();
    let line_length = w.iter().sum::<i32>() as usize;

    let mut line = String::new();
    let mut i = 0;
    while i < stream.len() {
        for j in &w {
            for _k in 0..*j {
                line.push_str(&format!("{:02X}", stream[i]));
                i += 1;
            }
            let c = if i % line_length != 0 {
                ' '
            } else {
                '\n'
            };
            line.push(c);
        }

        res.push_str(&line);
        line.clear();
    }

    res
}

fn png_up(data: &[u8], column: usize) -> Vec<u8> {
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
