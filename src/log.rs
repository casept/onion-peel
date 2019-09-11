use std::fmt;
use std::fmt::Display;

/// Represents the different levels of severity a log message may have.
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
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Notice => write!(f, "notice"),
            Severity::Info => write!(f, "info"),
            Severity::Debug => write!(f, "debug"),
        }
    }
}
