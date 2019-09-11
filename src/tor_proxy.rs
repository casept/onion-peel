use std::fmt;

/// Represents the types of proxies that a pluggable transport client may
/// provide for the tor client to connect through.
pub enum TorProxyTypes {
    SOCKS5,
    SOCKS4,
}

impl fmt::Display for TorProxyTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TorProxyTypes::SOCKS5 => write!(f, "socks5"),
            TorProxyTypes::SOCKS4 => write!(f, "socks4"),
        }
    }
}