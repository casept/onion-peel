use crate::shared_config::SharedConfig;
use std::clone::Clone;
use std::env;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path;
use std::str;
use std::collections::HashMap;

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

#[derive(Default, Clone)]
pub struct UpstreamProxy {
    pub protocol: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub port: u16,
    pub host: String,
}

#[derive(Debug)]
pub struct ParseUpstreamProxyError;
impl fmt::Display for ParseUpstreamProxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid proxy string format")
    }
}
impl Error for ParseUpstreamProxyError {}

impl str::FromStr for UpstreamProxy {
    type Err = ParseUpstreamProxyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Detect/error on malformed input
        // Proxy URI format: <proxy_type>://[<user_name>[:<password>][@]<ip>:<port>
        // We want to avoid depending on regex, so this is a bit complicated
        // The protocol is just whatever is to the left of the first "://"
        let protocol: String = s.splitn(2, "://").collect::<Vec<&str>>()[0].to_owned();
        // Test whether we need to extract credentials by checking whether the string contains an "@"
        // "@" is not a legal character in hostnames, so the presence of an "@" right before the
        // hostname:port portion means that it's separating credentials from it.
        let have_creds: bool;
        let username: Option<String>;
        let password: Option<String>;
        if s.contains("@") {
            have_creds = true;
            // What makes this tricky is that the spec doesn't disallow "@" in usernames and passwords.
            // What can be easily done, however, is separating out the entire username:password package.
            // It's between the first "://" to the left and the last "@" to the right.
            let username_and_pass = s.rsplitn(2, "://").collect::<Vec<&str>>()[0]
                .rsplitn(2, "@")
                .collect::<Vec<&str>>()[1]
                .to_owned();

            // We can assume that the first ":" we find is the separator between username and password
            // (allowing ":" in then would make unambiguous parsing impossible).
            // If there's no ":" in the string it's therefore safe to assume that we don't have a password, only a username.
            if !username_and_pass.contains(":") {
                username = Some(username_and_pass);
                password = None;
            } else if username_and_pass.starts_with(":") {
                // Could also be the case that we only have a password.
                // In that case, we probably only have a single ":" at the beginning of the entire thing.
                username = None;
                password =
                    Some(username_and_pass.splitn(1, ":").collect::<Vec<&str>>()[0].to_owned());
            // Remove the ":"
            } else {
                // We have both a username and password
                username =
                    Some(username_and_pass.splitn(2, ":").collect::<Vec<&str>>()[0].to_owned());
                password =
                    Some(username_and_pass.splitn(2, ":").collect::<Vec<&str>>()[1].to_owned());
            }
        } else {
            have_creds = false;
            username = None;
            password = None;
        }

        // A port is mandatory, so we can extract it by taking whatever is behind the last ":"
        let port = s.rsplitn(2, ":").collect::<Vec<&str>>()[0].to_owned();
        // A hostname is also mandatory, and is delimited by either the "@" to the left and ":" to the right (if we have credentials)
        // or by "://" to the left and ":" to the right (if we don't have credentials)
        let host: String;
        if have_creds {
            // Discard everything to the left of "@" and to the right of ":"
            host = s.rsplitn(2, "@").collect::<Vec<&str>>()[0]
                .splitn(2, ":")
                .collect::<Vec<&str>>()[0]
                .to_owned();
        } else {
            // Discard everything to the left of "://" and to the right of ":"
            host = s.rsplitn(2, "://").collect::<Vec<&str>>()[0]
                .splitn(2, ":")
                .collect::<Vec<&str>>()[0]
                .to_owned();
        }

        return Ok(UpstreamProxy {
            protocol: protocol,
            username: username,
            password: password,
            port: port.parse().unwrap(),
            host: host,
        });
    }
}

impl fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut credentials = String::new();
        match &self.username {
            Some(username) => credentials.push_str(&username),
            None => (),
        }
        match &self.password {
            Some(password) => {
                // If the username isn't present, don't insert the ":" separator
                if credentials.len() != 0 {
                    credentials.push(':');
                }
                credentials.push_str(&password);
            }
            None => (),
        }
        if credentials.len() != 0 {
            credentials.push('@');
        }

        if credentials.len() != 0 {
            write!(
                f,
                "{}://{}{}:{}",
                self.protocol, credentials, self.host, self.port
            )
        } else {
            write!(f, "{}://{}:{}", self.protocol, self.host, self.port)
        }
    }
}

// TODO: Test UpstreamProxy

pub struct Client {
    shared_config: SharedConfig,
    supported_transports: Vec<String>,
    transports_to_enable: Option<Vec<String>>,
    upstream_proxy_uri: Option<UpstreamProxy>,
}

impl Client {
    fn new(supported_transports: Vec<String>) -> Client {
        return Client {
            shared_config: SharedConfig::new(),
            supported_transports: supported_transports,
            transports_to_enable: None,
            upstream_proxy_uri: None,
        };
    }

    pub fn init(supported_transports: Vec<String>) -> Client {
        let mut c = Client::new(supported_transports);
        c.shared_config = SharedConfig::init();

        // Check which transports the parent process wants us to enable
        match env::var("TOR_PT_CLIENT_TRANSPORTS") {
            Ok(val) => {
                match crate::parsers::parse_transports_to_enable(
                    c.supported_transports.clone(),
                    val,
                ) {
                    Some(val1) => c.transports_to_enable = Some(val1),
                    None => panic!(
                        "Parent process didn't ask us to enable a transport we support, aborting!"
                    ),
                }
            }
            Err(e) => panic!(
                "Could not parse list of transports requested by parent process: {}",
                e
            ),
        }

        // Check whether the transport should use a proxy for upstream traffic
        match env::var("TOR_PT_PROXY") {
            Ok(val) => c.upstream_proxy_uri = Some(val.parse().unwrap()),
            Err(error) => match error {
                env::VarError::NotPresent => (),
                env::VarError::NotUnicode(_) => panic!(
                    "Could not read proxy URI specified by parent process: {}",
                    error
                ),
            },
        }

        return c;
    }

    pub fn get_upstream_proxy(&self) -> Option<UpstreamProxy> {
        match &self.upstream_proxy_uri {
            Some(val) => return Some(val.clone()),
            None => return None,
        }
    }

    pub fn get_transports_to_initialize(&self) -> Option<Vec<String>> {
        return self.transports_to_enable.clone();
    }

    pub fn get_transport_state_location(&self) -> path::PathBuf {
        return self.shared_config.transport_state_location.clone();
    }

    pub fn report_success(
        &self,
        transport_name: String,
        proxy_type: TorProxyTypes,
        bind_addr: SocketAddr,
    ) {
        println!("CMETHOD {} {} {}", transport_name, proxy_type, bind_addr)
    }

    pub fn report_failure(&self, transport_name: String, error_msg: String) {
        println!("CMETHOD-ERROR {} {}", transport_name, error_msg);
    }

    pub fn report_setup_done(&self) {
        println!("CMETHODS DONE");
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
}

// TODO: Test parse_transports_to_enable
// TODO: Test parse_transports_to_initialize
// FIXME: Allow specifying arguments to client via SOCKS auth field