use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::prelude::*;
use std::{clone::Clone, env, fs, net::SocketAddr, path};

use crate::log;
use crate::shared_config::SharedConfig;

/// `DestinationRelay` represents the relay that the PT server forwards data to once it exits the transport's tunneling and is deobfuscated.
#[derive(Clone)]
pub enum DestinationRelay {
    ORPort(String),
    ExtORPort(String, String),
}

impl DestinationRelay {
    /// Returns the address of the relay in the format host:port.
    pub fn get_addr(&self) -> String {
        match self {
            DestinationRelay::ORPort(address) => return address.clone(),
            DestinationRelay::ExtORPort(address, _) => return address.clone(),
        }
    }

    /// Returns the cookie needed for connecting to a relay via the ExtORPort protocol.
    /// If the relay is not an ExtORPort relay, this will be `None`.
    pub fn get_cookie(&self) -> Option<String> {
        match self {
            DestinationRelay::ORPort(_) => return None,
            DestinationRelay::ExtORPort(_, cookie) => return Some(cookie.clone()),
        }
    }
}

/// This object is a handle to allow interaction with the parent process by your server-side pluggable transport implementation(s).
///
/// It provides methods for both retrieving configuration dictated by the parent process,
/// as well as telling it about the state of the transport(s).
#[derive(Clone)]
pub struct Server {
    shared_config: SharedConfig,
    supported_transports: Vec<String>,
    transports_to_enable: Option<Vec<String>>,
    transport_options: Option<HashMap<String, HashMap<String, String>>>,
    bind_addresses: HashMap<String, Option<SocketAddr>>,
    destination: DestinationRelay,
}

impl Server {
    fn new(supported_transports: Vec<String>) -> Server {
        return Server {
            shared_config: SharedConfig::new(),
            supported_transports: supported_transports,
            transports_to_enable: None,
            transport_options: None,
            bind_addresses: HashMap::new(),
            destination: DestinationRelay::ORPort("0xDEADBEEF".to_string()), // This will always be overridden by init()
        };
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
                match crate::parsers::parse_transports_to_enable(
                    s.supported_transports.clone(),
                    val,
                ) {
                    Some(val1) => s.transports_to_enable = Some(val1),
                    None => {
                        // The spec requires us to send this after we've finished initializing every transport we're capable of handling.
                        // In this case, there are none so we send it immediately.
                        println!("SMETHODS DONE");
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
                s.transport_options =
                    crate::parsers::parse_transport_options(s.supported_transports.clone(), val)
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
                s.bind_addresses =
                    crate::parsers::parse_bind_addresses(s.supported_transports.clone(), val)
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
                have_destination = true;
                s.destination = DestinationRelay::ORPort(val.clone());
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
                if have_destination {
                    println!("ENV-ERROR both TOR_PT_ORPORT and TOR_PT_EXTENDED_SERVER_PORT set");
                    panic!("Parent process specified both ORPort and extended ORPort. Therefore, we don't know which one to send traffic to!");
                } else {
                    extended_orport = val;
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

                    let mut content = String::new();
                    match f.read_to_string(&mut content) {
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
    /// the success/failure by calling
    /// `report_success` or `report_failure` with the name of the transport.
    /// Once you've done this for all transports, you have to call `report_setup_done`.
    pub fn get_transports_to_initialize(&self) -> Option<Vec<String>> {
        // TODO: Call `report_setup_done` automatically once all transports are ready/failed
        return self.transports_to_enable.clone();
    }

    /// Calling this will notify the parent process that the pluggable transport `transport`
    /// has been successfully initialized and is ready to accept clients on the address `bind_addr`.
    ///
    /// Via `options`, arbitrary key-value pairs can be passed to the parent process,
    /// which can in turn pass them on to clients via tor's BridgeDB or another system.
    pub fn report_success(
        &self,
        transport: String,
        bind_addr: SocketAddr,
        options: Option<BTreeMap<String, String>>,
    ) {
        match options {
            None => println!("SMETHOD {} {}", transport, bind_addr),
            Some(opts) => println!(
                "SMETHOD {} {} ARGS:{}",
                transport,
                bind_addr,
                Server::escape_and_format_opts(opts)
            ),
        }
    }

    /// Tells the parent process that the server for `transport_name`
    /// could not be initialized successfully.
    pub fn report_failure(&self, transport_name: String, error_msg: String) {
        // TODO: Make report_success for same transport uncallable
        // TODO: This should be done by creating and returning a `transport` object
        println!("SMETHOD-ERROR {} {}", transport_name, error_msg);
    }

    /// Tells the parent process that the server
    /// has tried to enable all requested transports, and either succeeded or failed (and reported that for each transport).
    pub fn report_setup_done(&self) {
        println!("SMETHODS DONE");
    }

    /// Returns the (extended) ORPort-compliant destination for all client traffic,
    /// which is where your server should forward traffic to.
    ///
    /// In tor's case, this is usually a tor relay.
    pub fn get_destination_relay(&self) -> DestinationRelay {
        return self.destination.clone();
    }

    /// Returns the `path` to a directory
    /// the parent process allows your pluggable transport to store files in.
    ///
    /// Note that your transport should not store files anywhere else.
    pub fn get_transport_state_location(&self) -> path::PathBuf {
        return self.shared_config.transport_state_location.clone();
    }

    /// Returns the `SocketAddr` that the PT `transport` should listen for client
    /// connections on.
    ///
    /// If the transport isn't among the transports the parent process has requested
    /// your pluggable transport to serve, this will return `None`.
    pub fn get_bind_address(&self, transport: String) -> Option<SocketAddr> {
        // TODO: Be more explicit about error/panic
        return self.bind_addresses[&transport].clone();
    }

    /// Writes a human-readable log message with severity `sev`.
    pub fn write_log_message(sev: log::Severity, msg: String) {
        println!("LOG SEVERITY={} MESSAGE={}", sev, msg);
    }

    /// Writes a message describing the status of the transport in key-value pairs.
    ///
    /// This information is usually not parsed by the parent process, it merely serves to inform the user.
    ///
    /// If `transport` is not part of the transports which the parent process requested to enable,
    /// this will panic.
    pub fn write_status_message(&self, transport: String, messages: HashMap<String, String>) {
        if !self
            .transports_to_enable
            .as_ref()
            .unwrap()
            .contains(&transport)
        {
            // TODO: Make this a method of `transport` and make this check obsolete
            panic!(
                "Attempt to write status message for unrequested transport {}",
                transport
            );
        }
        let mut concat_messages = String::new();
        for (key, value) in messages {
            concat_messages.push_str(&key);
            concat_messages.push('=');
            concat_messages.push_str(&value);
            concat_messages.push(' ');
        }
        println!("STATUS TRANSPORT={} {}", transport, concat_messages);
    }

    fn escape_and_format_opts(input: BTreeMap<String, String>) -> String {
        // The spec requires that extra arguments clients should know about
        // (which are e.g. distributed on BridgeDB)
        // be encoded in key=value pairs as K1=V1,K2=V2. All "=" and "," occurring in keys/values must be escaped with "\"
        let mut result = String::new();
        let mut i = 1;
        let last = input.len();
        for (key, value) in input {
            let escaped_key = key.replace("=", r#"\="#).replace(",", r#"\,"#);
            let escaped_value = value.replace("=", r#"\="#).replace(",", r#"\,"#);
            result.push_str(&escaped_key);
            result.push('=');
            result.push_str(&escaped_value);
            // Trailing comas are not allowed, so check how far into the iterator we are first
            if i < last {
                result.push(',');
            }
            i = i + 1;
        }
        return result;
    }
}

// TESTS TESTS TESTS TESTS

#[test]
fn test_escape_and_format_opts_no_opts() {
    let input: BTreeMap<String, String> = BTreeMap::new();
    let expected_output = "";
    assert_eq!(expected_output, Server::escape_and_format_opts(input));
}
#[test]
fn test_escape_and_format_opts_single_opt() {
    let mut input: BTreeMap<String, String> = BTreeMap::new();
    input.insert("key1".to_string(), "value1".to_string());
    let expected_output = "key1=value1";
    assert_eq!(expected_output, Server::escape_and_format_opts(input));
}
#[test]
fn test_escape_and_format_opts_multiple_opts() {
    let mut input: BTreeMap<String, String> = BTreeMap::new();
    input.insert("key1".to_string(), "value1".to_string());
    input.insert("key2".to_string(), "value2".to_string());
    let expected_output = "key1=value1,key2=value2";
    assert_eq!(expected_output, Server::escape_and_format_opts(input));
}
#[test]
fn test_escape_and_format_opts_single_opt_escaped() {
    let mut input: BTreeMap<String, String> = BTreeMap::new();
    input.insert(r#"key=1"#.to_string(), r#"value=1"#.to_string());
    let expected_output = r#"key\=1=value\=1"#;
    assert_eq!(expected_output, Server::escape_and_format_opts(input));
}
#[test]
fn test_escape_and_format_opts_multiple_opts_escaped() {
    let mut input: BTreeMap<String, String> = BTreeMap::new();
    input.insert(r#"key,2"#.to_string(), r#"value,2"#.to_string());
    input.insert(r#"key=1"#.to_string(), r#"value=1"#.to_string());
    let expected_output = r#"key\=1=value\=1,key\,2=value\,2"#;
    assert_eq!(expected_output, Server::escape_and_format_opts(input));
}
