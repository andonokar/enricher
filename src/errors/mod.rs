#[derive(Debug)]
pub enum Errors {
    EmptyLine,
    ParsingError(String),
    EmptyBody,
    InvalidLineEntry
}