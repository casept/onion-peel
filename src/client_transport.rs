use std::net::SocketAddr;

use crate::tor_proxy::TorProxyTypes;

/// Represents a client-side pluggable transport.
#[derive(Clone)]
pub struct ClientTransport {
    pub(crate) name: String,
    pub(crate) should_enable: bool,
    pub(crate) status_reported: bool,
}

impl ClientTransport {
    pub(crate) fn new(name: String) -> ClientTransport {
        return ClientTransport {
            name: name,
            should_enable: false,
            status_reported: false,
        };
    }

    /// Calling this will notify the parent process that the transport
    /// has been successfully initialized and is ready to forward traffic sent to the SOCKS proxy listening on `bind_addr`.
    /// The proxy must speak the protocol specified by `proxy_type`.
    ///
    /// If success or failure have already been reported, this will panic.
    pub fn report_success(&mut self, proxy_type: TorProxyTypes, bind_addr: SocketAddr) {
        if self.status_reported {
            panic!("Attempt to report transport status twice");
        }
        println!("CMETHOD {} {} {}", self.name, proxy_type, bind_addr);
        self.status_reported = true;
    }

    /// Tells the parent process that the server for `transport_name`
    /// could not be initialized successfully.
    ///
    /// `error_msg` is a human-readable description of the problem.
    ///
    /// If success or failure have already been reported, this will panic.
    pub fn report_failure(&mut self, error_msg: String) {
        if self.status_reported {
            panic!("Attempt to report transport status twice");
        }
        println!("CMETHOD-ERROR {} {}", self.name, error_msg);
        self.status_reported = true;
    }

    /// Returns the name of the transport
    pub fn get_name(&self) -> String {
        return self.name.clone();
    }
}
