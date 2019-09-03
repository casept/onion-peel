use std::fmt;
use std::fmt::Display;

pub enum Severity {
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error => write!(f, "error"),
            Warning => write!(f, "warning"),
            Notice => write!(f, "notice"),
            Info => write!(f, "info"),
            Debug => write!(f, "debug"),
        }
    }
}
