use flate2::write::ZlibDecoder;
use std::io::Write;

pub trait Filter {
    fn apply(&self, stream: &[u8]) -> Vec<u8>;
}

#[derive(Default)]
pub struct FlateDecode{
    // Predictor, Colors, BitsPerComponent, Columns
    pub predictor: i32,
    pub colors: i32,
    pub bits_per_component: i32,
    pub columns: i32
}

impl Filter for FlateDecode {
    fn apply(&self, stream: &[u8]) -> Vec<u8> {
        let mut writer = Vec::new();
        let mut z = ZlibDecoder::new(writer);
        z.write_all(stream).unwrap();
        writer = z.finish().unwrap();
        
        apply_predictor(&writer, self.predictor, self.columns) 
    }
}

unsafe impl Send for FlateDecode {}
unsafe impl Sync for FlateDecode {}

//     // Values: Predictor, Colors, BitsPerComponent, Columns, EarlyChange
//     LZWDecode(i32, i32, i32, i32, i32),
#[derive(Default)]
pub struct LZWDecode {
    pub predictor: i32,
    pub colors: i32,
    pub bits_per_component: i32,
    pub columns: i32,
    pub early_change: i32
}

impl Filter for LZWDecode {
    fn apply(&self, stream: &[u8]) -> Vec<u8> {
        // TODO
        stream.to_vec()
    }
}
unsafe impl Send for LZWDecode {}
unsafe impl Sync for LZWDecode {}

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