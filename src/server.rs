use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::prelude::*;
use std::{clone::Clone, env, fs, net::SocketAddr, path};

use crate::log;
use crate::shared_config::SharedConfig;

#[derive(Clone)]
pub enum Destination {
    ORPort(String),
    ExtORPort(String, String),
}

impl Destination {
    pub fn get_addr(&self) -> String {
        match self {
            Destination::ORPort(address) => return address.clone(),
            Destination::ExtORPort(address, _) => return address.clone(),
        }
    }

    pub fn get_cookie(&self) -> Option<String> {
        match self {
            Destination::ORPort(_) => return None,
            Destination::ExtORPort(_, cookie) => return Some(cookie.clone()),
        }
    }
}

pub struct Server {
    shared_config: SharedConfig,
    supported_transports: Vec<String>,
    transports_to_enable: Option<Vec<String>>,
    transport_options: Option<HashMap<String, HashMap<String, String>>>,
    bind_addresses: HashMap<String, Option<SocketAddr>>,
    destination: Destination,
}

impl Server {
    fn new(supported_transports: Vec<String>) -> Server {
        return Server {
            shared_config: SharedConfig::new(),
            supported_transports: supported_transports,
            transports_to_enable: None,
            transport_options: None,
            bind_addresses: HashMap::new(),
            destination: Destination::ORPort("0xDEADBEEF".to_string()), // This will always be overridden by init()
        };
    }

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
                s.destination = Destination::ORPort(val.clone());
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
                    s.destination = Destination::ExtORPort(extended_orport, content);
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

    pub fn get_transports_to_initialize(&self) -> Option<Vec<String>> {
        return self.transports_to_enable.clone();
    }

    pub fn report_success(
        &self,
        transport_name: String,
        bind_addr: SocketAddr,
        options: Option<BTreeMap<String, String>>,
    ) {
        match options {
            None => println!("SMETHOD {} {}", transport_name, bind_addr),
            Some(opts) => println!(
                "SMETHOD {} {} ARGS:{}",
                transport_name,
                bind_addr,
                Server::escape_and_format_opts(opts)
            ),
        }
    }

    pub fn report_failure(&self, transport_name: String, error_msg: String) {
        println!("SMETHOD-ERROR {} {}", transport_name, error_msg);
    }

    pub fn report_setup_done(&self) {
        println!("SMETHODS DONE");
    }

    pub fn get_destination(&self) -> Destination {
        return self.destination.clone();
    }

    pub fn get_transport_state_location(&self) -> path::PathBuf {
        return self.shared_config.transport_state_location.clone();
    }
    pub fn get_bind_address(&self, transport: String) -> Option<SocketAddr> {
        return self.bind_addresses[&transport].clone();
    }

    pub fn write_log_message(sev: crate::log::Severity, msg: String) {
        println!("LOG SEVERITY={} MESSAGE={}", sev, msg);
    }

    pub fn write_status_message(transport: String, messages: HashMap<String, String>) {
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

// TODO: Test escape_and_format_opts
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
