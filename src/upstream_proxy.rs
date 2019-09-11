use std::fmt;
use std::error::Error;
use std::str;

/// Represents a proxy that the pluggable transport client must send all traffic through.
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

        // TODO: Getters for fields consumer should have access to
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
