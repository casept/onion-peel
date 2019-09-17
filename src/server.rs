use std::io;
use std::io::prelude::*;
use std::net;
use std::time;
use std::{clone::Clone, env, fs, path};

use crate::ext_orport;
use crate::log;
use crate::parsers;
use crate::server_transport::ServerTransport;
use crate::shared_config::SharedConfig;



/// This object is a handle to allow interaction with the parent process by your server-side pluggable transport implementation(s).
///
/// It provides methods for both retrieving configuration dictated by the parent process,
/// as well as telling it about the state of the transport(s).
#[derive(Clone)]
pub struct Server {
    shared_config: SharedConfig,
    transports: Vec<ServerTransport>,
    destination: DestinationRelay,
}

impl Server {
    fn new(supported_transports: Vec<String>) -> Server {
        let mut server = Server {
            shared_config: SharedConfig::new(),
            transports: Vec::new(),
            // TODO: Make this field an Option
            destination: DestinationRelay::ORPort("0xDEADBEEF".to_string()), // This will always be overridden by init()
        };

        for transport_name in supported_transports {
            server.transports.push(ServerTransport::new(transport_name));
        }

        return server;
    }

    /// Reads the parent processes desired configuration for the server end of your pluggable transport(s).
    ///
    /// This will panic if a non-recoverable protocol violation by the parent process occurs.
    pub fn init(supported_transports: Vec<String>) -> Server {
        let mut s = Server::new(supported_transports);
        s.shared_config = SharedConfig::init();

        // Check which transports the parent process wants us to enable
        match env::var("TOR_PT_SERVER_TRANSPORTS") {
            Ok(val) => {
                let mut transport_names: Vec<String> = Vec::new();
                for transport in &s.transports {
                    transport_names.push(transport.name.clone());
                }
                match parsers::parse_transports_to_enable(transport_names, val) {
                    Some(val1) => {
                        for transport_to_enable in val1 {
                            for transport in &mut s.transports {
                                if transport.name == transport_to_enable {
                                    transport.set_should_enable(true);
                                    break;
                                }
                            }
                        }
                    }
                    None => {
                        // The spec requires us to send this after we've finished initializing every transport we're capable of handling.
                        // In this case, there are none so we send it immediately.
                        println!("SMETHODS DONE");
                        // TODO: More robust error handling
                        panic!("Parent process didn't ask us to enable a transport we support, exiting!");
                    }
                }
            }
            Err(e) => {
                println!(
                    "ENV-ERROR could not read list of transports requested: {}",
                    e
                );
                panic!(
                    "Could not read list of transports requested by parent process: {}",
                    e
                );
            }
        }

        // Parse the list of arguments to the various transports provided by the parent process
        match env::var("TOR_PT_SERVER_TRANSPORT_OPTIONS") {
            Ok(val) => {
                let mut transport_names: Vec<String> = Vec::new();
                for transport in &s.transports {
                    transport_names.push(transport.name.clone());
                }
                match parsers::parse_transport_options(transport_names, val) {
                    Some(transport_options) => {
                        for (name, options) in transport_options.iter() {
                            for transport in &mut s.transports {
                                if transport.name == *name {
                                    transport.set_options(options.clone());
                                }
                            }
                        }
                    }
                    None => (),
                }
            }
            Err(error) => match error {
                env::VarError::NotPresent => (),
                env::VarError::NotUnicode(_) => panic!(
                    "Could not read transport options specified by parent process: {}",
                    error
                ),
            },
        }

        // Parse the list of IP addresses and ports each supported transport should listen on
        match env::var("TOR_PT_SERVER_BINDADDR") {
            Ok(val) => {
                let mut transport_names: Vec<String> = Vec::new();
                for transport in &s.transports {
                    transport_names.push(transport.name.clone());
                }
                let bind_addresses = parsers::parse_bind_addresses(transport_names, val);
                for (name, address) in bind_addresses.iter() {
                    for transport in &mut s.transports {
                        if transport.name == *name {
                            transport.set_bind_addr(*address);
                        }
                    }
                }
            }
            Err(error) => match error {
                env::VarError::NotPresent => (),
                env::VarError::NotUnicode(_) => panic!(
                    "Could not read transport options specified by parent process: {}",
                    error
                ),
            },
        }

        let mut have_destination = false;
        // Parse out which entry node/relay to forward deobfuscated traffic to
        match env::var("TOR_PT_ORPORT") {
            Ok(val) => {
                if val != "" {
                    have_destination = true;
                    s.destination = DestinationRelay::ORPort(val.clone());
                }
            }
            Err(error) => match error {
                env::VarError::NotPresent => (), // Is handled while parsing TOR_PT_EXTENDED_SERVER_PORT
                env::VarError::NotUnicode(_) => panic!(
                    "Could not read transport options specified by parent process: {}",
                    error
                ),
            },
        }

        // Parse out which entry node/relay supporting the extended ORPort protocol to forward deobfuscated traffic to
        let mut extended_orport = String::new();
        match env::var("TOR_PT_EXTENDED_SERVER_PORT") {
            Ok(val) => {
                    if val != "" {
                        extended_orport = val;
                    } else {
                        if !have_destination {
                            println!("ENV-ERROR neither TOR_PT_ORPORT nor TOR_PT_EXTENDED_SERVER_PORT set in server mode");
                            panic!("Parent process did not tell us where we should send traffic to!");
                        }
                    }
            },
            Err(error) => match error {
                env::VarError::NotPresent => {
                    if !have_destination {
                        println!("ENV-ERROR neither TOR_PT_ORPORT nor TOR_PT_EXTENDED_SERVER_PORT set in server mode");
                        panic!("Parent process did not tell us where we should send traffic to!");
                    }
                },
                env::VarError::NotUnicode(_) => panic!("Could not read extended ORPort transport options specified by parent process: {}", error),
            },
        }

        // If we've been passed an extended ORPort, we also need a cookie to use it.
        // Therefore we only check for it when an extended ORPort is set and fail if it's not obtainable.
        if extended_orport != "" {
            match env::var("TOR_PT_AUTH_COOKIE_FILE") {
                Ok(val) => {
                    // Read the cookie into memory
                    let mut f: fs::File;
                    match fs::File::open(val) {
                        Ok(val1) => f = val1,
                        Err(error1) => {
                            println!(
                                "ENV-ERROR TOR_PT_AUTH_COOKIE_FILE could not be opened: {}",
                                error1
                            );
                            panic!(
                                "Could not open extended ORPort authentication cookie file: {}",
                                error1
                            );
                        }
                    }

                    let mut content: Vec<u8> = Vec::new();
                    match f.read_to_end(&mut content) {
                        Ok(_) => (),
                        Err(error2) => {
                            println!(
                                "ENV-ERROR could not read contents of TOR_PT_AUTH_COOKIE file: {}",
                                error2
                            );
                            panic!(
                                "Could not read extended ORPort authentication cookie file: {}",
                                error2
                            );
                        }
                    }
                    // We prefer the extended ORPort over the regular ORPort,
                    // therefore we overwrite it unconditionally here
                    s.destination = DestinationRelay::ExtORPort(extended_orport, content);
                }
                Err(error) => match error {
                    env::VarError::NotPresent => {
                        println!("ENV-ERROR No TOR_PT_AUTH_COOKIE_FILE when TOR_PT_EXTENDED_SERVER_PORT set");
                        panic!("Parent process asked us to use extended ORPort but didn't tell us where to find the required auth cookie!");
                    }
                    env::VarError::NotUnicode(_) => panic!(
                        "Could not read path to extended ORPort auth cookie: {}",
                        error
                    ),
                },
            }
        }

        return s;
    }

    /// Returns the subset of the pluggable transports your server
    /// advertised as supporting which the parent process actually wants you to initialize.
    ///
    /// You are expected to attempt to initialize each of these transports, and report
    /// the success/failure by calling the transport's `report_success` or `report_failure` methods.
    /// Once you've done this for all transports, you have to call the server's `report_setup_done`.
    pub fn get_transports_to_initialize(&mut self) -> Option<Vec<&mut ServerTransport>> {
        // TODO: Call `report_setup_done` automatically once all transports are ready/failed
        let mut transports_to_enable: Vec<&mut ServerTransport> = Vec::new();
        for transport in &mut self.transports {
            if transport.get_should_enable() {
                transports_to_enable.push(transport);
            }
        }
        if transports_to_enable.len() > 0 {
            return Some(transports_to_enable);
        } else {
            return None;
        }
    }

    /// Tells the parent process that the server
    /// has tried to enable all requested transports, and either succeeded or failed (and reported that for each transport).
    ///
    /// If this method is called before success/failure has been reported for each transport that
    /// was to be enabled it will panic.
    pub fn report_setup_done(&self) {
        for transport in &self.transports {
            if !transport.status_reported {
                panic!("Attempt to call report_setup_done() without first reporting status of all transports");
            }
        }
        println!("SMETHODS DONE");
    }



    /// Returns the `path` to a directory
    /// the parent process allows your pluggable transport(s) to store files in.
    ///
    /// Note that your transport(s) should not store files anywhere else.
    pub fn get_transport_state_location(&self) -> path::PathBuf {
        return self.shared_config.transport_state_location.clone();
    }

    /// Passes along a human-readable log message with severity `sev` to the parent.
    pub fn write_log_message(sev: log::Severity, msg: String) {
        println!("LOG SEVERITY={} MESSAGE={}", sev, msg);
    }

    /// Returns an object which allows for dialing the relay which actually forwards traffic to
    /// the tor network.
    pub fn get_relay_dialer(&self) -> RelayDialer {
        // This is done to sort out some ownership issues
        return RelayDialer{relay: self.destination.clone()};
    }
}

/// An object which allows establishing a connection to a relay
/// which is the entry point of traffic into the tor network.
#[derive(Clone)]
pub struct RelayDialer {
    relay: DestinationRelay,
}

impl RelayDialer {
    /// Returns an opened `net::TcpStream` to the (extended) ORPort-compliant destination for all client traffic,
    /// which is where your server should forward traffic to.
    ///
    /// In tor's case, this is usually a tor relay.
    pub fn dial(
        &self,
        transport: &ServerTransport,
        client_addr: net::SocketAddr,
    ) -> Result<net::TcpStream, io::Error> {
        let mut stream;
        match &self.relay {
            DestinationRelay::ORPort(addr) => {
                // ORPort is just for forwarding plain TCP traffic
                // TODO: Timeout
                stream = net::TcpStream::connect(addr)?;
            }
            DestinationRelay::ExtORPort(addr, cookie) => {
                // Extended ORPort requires to negotiate a connection first
                stream = net::TcpStream::connect(addr)?;
                // As the negotiation requires sending data, we set a reasonable timeout
                stream.set_read_timeout(Some(time::Duration::from_secs(20)))?;
                stream.set_write_timeout(Some(time::Duration::from_secs(20)))?;
                ext_orport::negotiate_connection(
                    cookie.to_vec(),
                    transport.name.clone(),
                    client_addr,
                    &mut stream,
                )?;
                // Remove the timeout again, whether to apply a new one is up to the consumer
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
            }
        }
        return Ok(stream);
    }
}

/// Represents the relay that the PT server forwards data to once it exits the transport's tunneling and is deobfuscated.
#[derive(Clone)]
enum DestinationRelay {
    ORPort(String),
    ExtORPort(String, Vec<u8>),
}