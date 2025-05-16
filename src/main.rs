use crate::reader::read_lines_from_folder;
use std::io;
use std::sync::atomic::compiler_fence;

mod reader;
mod parser;
mod errors;

fn main() -> io::Result<()> {
    let folder_path = "./data";
    let lines = read_lines_from_folder(folder_path, 1725637800)?;
    let split = lines.into_iter();
    Ok(())
}
