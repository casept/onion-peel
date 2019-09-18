use std::fmt;
use std::io;

/// An InitError is returned in case initializing the `Server` or `Client` structs fails.
pub enum InitError {
    ParserError(String),
    MissingEnvVarError(String),
    EmptyEnvVarError(String),
    CreateStateDirectoryError(io::Error),
    ReadCookieError(io::Error),
    SpecVersionError(String),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::ParserError(msg) => write!(f, "Failed to parse an env var: {}", msg),
            InitError::MissingEnvVarError(var) => write!(f, "Required env var '{}' is missing", var),
            InitError::EmptyEnvVarError(var) => write!(f, "Required env var '{}' is empty", var),
            InitError::CreateStateDirectoryError(err) => write!(f, "Failed to create directory for storing state: {}", err),
            InitError::ReadCookieError(err) => write!(f, "Failed to read extended ORPort authentication cookie: {}", err),
            InitError::SpecVersionError(versions) => write!(f, "We only support version 1 of the pluggable transport spec, but the parent process didn't offer it (offered instead: '{}')", versions),
        }
    }
}
