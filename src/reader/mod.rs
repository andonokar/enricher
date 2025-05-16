use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use flate2::read::GzDecoder;

pub fn read_lines_from_folder<P: AsRef<Path>>(folder_path: P, batch_id: i32) -> io::Result<Vec<(i32, String)>> {
    let mut all_lines = Vec::new();

    for entry in fs::read_dir(folder_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let file = File::open(&path)?;
            let reader: Box<dyn BufRead> = if let Some(ext) = path.extension() {
                if ext == "gz" {
                    Box::new(BufReader::new(GzDecoder::new(file)))
                } else {
                    Box::new(BufReader::new(file))
                }
            } else {
                Box::new(BufReader::new(file))
            };

            for line_result in reader.lines() {
                let line = line_result?;
                all_lines.push((batch_id, line));
            }
        }
    }

    Ok(all_lines)
}