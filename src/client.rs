use crate::client_transport::ClientTransport;
use crate::log;
use crate::parsers;
use crate::shared_config::SharedConfig;
use crate::upstream_proxy::UpstreamProxy;
use crate::init_error::InitError;

use std::clone::Clone;
use std::collections::HashMap;
use std::env;
use std::path;

/// This object is a handle to allow interaction with the parent process by your client-side pluggable transport implementation(s).
///
/// It provides methods for both retrieving configuration dictated by the parent process,
/// as well as telling it about the state of the transport(s).
#[derive(Clone)]
pub struct Client {
    shared_config: SharedConfig,
    transports: Vec<ClientTransport>,
    upstream_proxy_uri: Option<UpstreamProxy>,
}

impl Client {
    fn new(supported_transports: Vec<String>) -> Client {
        let mut client = Client {
            shared_config: SharedConfig::new(),
            transports: Vec::new(),
            upstream_proxy_uri: None,
        };
        for transport in supported_transports {
            client.transports.push(ClientTransport::new(transport));
        }

        return client;
    }

    /// Reads the parent processes desired configuration for the client end of your pluggable transport(s).
    /// If the parent didn't request to enable any transports we support, instead of the `Client` `None` will be returned.
    /// 
    /// An error is returned if the parent process violates the pluggable transport specification.
    /// In that case, you MUST terminate your program (or be in violation of the spec).
    pub fn init(supported_transports: Vec<String>) -> Result<Option<Client>, InitError> {
        let mut c = Client::new(supported_transports);
        c.shared_config = SharedConfig::init()?;

        // Check which transports the parent process wants us to enable
        match env::var("TOR_PT_CLIENT_TRANSPORTS") {
            Ok(val) => {
                let mut transport_names: Vec<String> = Vec::new();
                for transport in &c.transports {
                    transport_names.push(transport.name.clone());
                }
                match parsers::parse_transports_to_enable(transport_names, val) {
                    Some(val1) => {
                        for transport_to_enable in val1 {
                            for transport in &mut c.transports {
                                if transport.name == transport_to_enable {
                                    transport.should_enable = true;
                                    break;
                                }
                            }
                        }
                    },
                    None => return Ok(None),
                }
            },
            Err(e) => match e {
                env::VarError::NotPresent => return Err(InitError::MissingEnvVarError("TOR_PT_CLIENT_TRANSPORTS".to_string())),
                env::VarError::NotUnicode(_) => return Err(InitError::ParserError(format!("Could not parse list of transports requested by parent process: {}",e))),
            }
        }

        // Check whether the transport should use a proxy for upstream traffic
        match env::var("TOR_PT_PROXY") {
            Ok(val) => c.upstream_proxy_uri = Some(val.parse().unwrap()),
            Err(error) => match error {
                env::VarError::NotPresent => (),
                env::VarError::NotUnicode(_) => return Err(InitError::ParserError(
                    format!("Could not read proxy URI specified by parent process: {}",
                    error)
                )),
            },
        }

        return Ok(Some(c));
    }

    /// Returns the upstream proxy that your transport(s) must tunnel all traffic through.
    ///
    /// If the parent did not specify a proxy, `None` is returned.
    pub fn get_upstream_proxy(&self) -> Option<UpstreamProxy> {
        match &self.upstream_proxy_uri {
            Some(val) => return Some(val.clone()),
            None => return None,
        }
    }

    /// Returns the subset of the pluggable transports your client
    /// advertised as supporting which the parent process actually wants you to initialize.
    ///
    /// You are expected to attempt to initialize each of these transports, and report
    /// the success/failure by calling the transport's `report_success` or `report_failure` methods.
    /// Once you've done this for all transports, you have to call the client's `report_setup_done`.
    pub fn get_transports_to_initialize(&mut self) -> Option<Vec<&mut ClientTransport>> {
        // TODO: Call `report_setup_done` automatically once all transports are ready/failed
        let mut transports_to_enable: Vec<&mut ClientTransport> = Vec::new();
        for transport in &mut self.transports {
            if transport.should_enable {
                transports_to_enable.push(transport);
            }
        }
        if transports_to_enable.len() > 0 {
            return Some(transports_to_enable);
        } else {
            return None;
        }
    }

    /// Returns the `path` to a directory
    /// the parent process allows your pluggable transport(s) to store files in.
    ///
    /// Note that your transport(s) should not store files anywhere else.
    pub fn get_transport_state_location(&self) -> path::PathBuf {
        return self.shared_config.transport_state_location.clone();
    }

    /// Tells the parent process that the client
    /// has tried to enable all requested transports, and either succeeded or failed (and reported that for each transport).
    ///
    /// At this point, the parent must be able to push traffic through the SOCKS proxies of all successfully started transports.
    ///
    /// If this method is called before success/failure has been reported for each transport that
    /// was to be enabled it will panic.
    pub fn report_setup_done(&self) {
        for transport in &self.transports {
            if !transport.status_reported {
                panic!("Attempt to call report_setup_done() without first reporting status of all transports");
            }
        }
        println!("CMETHODS DONE");
    }

    /// Passes along a human-readable log message with severity `sev` to the parent.
    pub fn write_log_message(sev: log::Severity, msg: String) {
        println!("LOG SEVERITY={} MESSAGE={}", sev, msg);
    }

    /// Writes a message describing the status of the transport in key-value pairs.
    ///
    /// This information is usually not parsed by the parent process, it merely serves to inform the user.
    ///
    /// If `transport` is not part of the transports which the parent process requested to enable,
    /// this will panic.
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

    /// Reports whether the parent expects your transport(s) to shut down when it closes stdin.
    ///
    /// If `true` is returned, you should follow this order, or your program won't shut down cleanly.
    ///
    /// If `false` is returned, the parent will send a `SIGTERM` and take care of killing your process by itself.
    pub fn should_exit_on_stdin_close(&self) -> bool {
        return self.shared_config.exit_on_stdin_close;
    }
}

// TODO: Test parse_transports_to_enable
// TODO: Test parse_transports_to_initialize
// FIXME: Allow specifying arguments to client via SOCKS auth field
