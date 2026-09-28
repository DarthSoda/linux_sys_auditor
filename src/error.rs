use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("I/O error occured: {0}")]
    IoError(#[from] io::Error), // Audotmatically converts standard std::io::Error

    #[error("Data parsing error: {0}")]
    ParsingError(String),

    #[error("File read error: {0}")]
    FileReadError(String),

    #[error("Access denied to procfs path")]
    ProcAccessDenied,
}
