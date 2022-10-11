use wasm_bindgen::prelude::*;

use crate::utils::set_panic_hook;
use crate::*;

pub mod filters;

#[allow(dead_code)]
#[wasm_bindgen]
pub fn decompress(obj_num: i32) -> Vec<u8> {
    set_panic_hook();

    let obj = get_obj(obj_num);

    if let Some(filter) = obj.filter {
        filter.apply(&obj.stream)
    } else {
        obj.stream.clone()
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
