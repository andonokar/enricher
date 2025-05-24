use crate::reader::read_lines_from_folder;
use std::io;
use std::time::Instant;
use crate::parser::parse;

mod reader;
mod parser;
mod errors;
mod action_names;

fn main() -> io::Result<()> {
    let folder_path = "./data";
    let lines = read_lines_from_folder(folder_path, 1725637800)?;

    let start = Instant::now();
    let enrichables: Vec<_> = lines.into_iter()
        .map(|(batch_id, line)| parse(batch_id, line)).collect();
    let duration = start.elapsed();
    println!("Time elapsed in map-collect operation: {:?}", duration);
    Ok(())
}
