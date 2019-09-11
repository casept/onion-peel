use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

/// Represents a server-side pluggable transport.
#[derive(Clone)]
pub struct ServerTransport {
    pub(crate) name: String,
    should_enable: bool,
    pub(crate) status_reported: bool,
    options: Option<HashMap<String, String>>,
    bind_address: Option<SocketAddr>,
}

impl ServerTransport {
    pub(crate) fn new(name: String) -> ServerTransport {
        return ServerTransport {
            name: name,
            should_enable: false,
            status_reported: false,
            options: None,
            bind_address: None,
        };
    }

    pub(crate) fn set_should_enable(&mut self, val: bool) {
        self.should_enable = val;
    }
    pub(crate) fn get_should_enable(&self) -> bool {
        return self.should_enable;
    }
    pub(crate) fn set_options(&mut self, options: HashMap<String, String>) {
        self.options = Some(options);
    }
    pub fn get_options(&self) -> Option<HashMap<String, String>> {
        return self.options.clone();
    }
    pub(crate) fn set_bind_addr(&mut self, bind_addr: Option<SocketAddr>) {
        self.bind_address = bind_addr;
    }

    /// Returns the name of the transport
    pub fn get_name(&self) -> String {
        return self.name.clone();
    }

    /// Returns the `SocketAddr` that the transport should listen for client
    /// connections on.
    pub fn get_bind_addr(&self) -> Option<SocketAddr> {
        return self.bind_address;
    }

    /// Writes a message describing the status of the transport in key-value pairs.
    ///
    /// This information is usually not parsed by the parent process, it merely serves to inform the user.
    pub fn write_status_message(&self, transport: String, messages: HashMap<String, String>) {
        // Sanity check - the consumer shouldn't be able to get a ServerTransport that shouldn't be initialized.
        if !self.should_enable {
            panic!("Attempt to write status message for transport that shouldn't be enabled!");
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

    /// Calling this will notify the parent process that the pluggable transport
    /// has been successfully initialized and is ready to accept clients on the address `bind_addr`.
    ///
    /// Via `options`, arbitrary key-value pairs can be passed to the parent process,
    /// which can in turn pass them on to clients via tor's BridgeDB or another system.
    ///
    /// If success or failure have already been reported, this will panic.
    pub fn report_success(
        &mut self,
        bind_addr: SocketAddr,
        options: Option<BTreeMap<String, String>>,
    ) {
        if self.status_reported {
            panic!("Attempt to report transport status twice");
        }
        match options {
            None => println!("SMETHOD {} {}", self.name, bind_addr),
            Some(opts) => println!(
                "SMETHOD {} {} ARGS:{}",
                self.name,
                bind_addr,
                ServerTransport::escape_and_format_opts(opts)
            ),
        }
        self.status_reported = true;
    }

    /// Tells the parent process that the server for `transport_name`
    /// could not be initialized successfully.
    ///
    /// `error_msg` is a human-readable description of the problem.
    ///
    /// If success or failure have already been reported, this will panic.
    pub fn report_failure(&mut self, transport_name: String, error_msg: String) {
        if self.status_reported {
            panic!("Attempt to report transport status twice");
        }
        println!("SMETHOD-ERROR {} {}", transport_name, error_msg);
        self.status_reported = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_escape_and_format_opts_no_opts() {
        let input: BTreeMap<String, String> = BTreeMap::new();
        let expected_output = "";
        assert_eq!(
            expected_output,
            ServerTransport::escape_and_format_opts(input)
        );
    }
    #[test]
    fn test_escape_and_format_opts_single_opt() {
        let mut input: BTreeMap<String, String> = BTreeMap::new();
        input.insert("key1".to_string(), "value1".to_string());
        let expected_output = "key1=value1";
        assert_eq!(
            expected_output,
            ServerTransport::escape_and_format_opts(input)
        );
    }
    #[test]
    fn test_escape_and_format_opts_multiple_opts() {
        let mut input: BTreeMap<String, String> = BTreeMap::new();
        input.insert("key1".to_string(), "value1".to_string());
        input.insert("key2".to_string(), "value2".to_string());
        let expected_output = "key1=value1,key2=value2";
        assert_eq!(
            expected_output,
            ServerTransport::escape_and_format_opts(input)
        );
    }
    #[test]
    fn test_escape_and_format_opts_single_opt_escaped() {
        let mut input: BTreeMap<String, String> = BTreeMap::new();
        input.insert(r#"key=1"#.to_string(), r#"value=1"#.to_string());
        let expected_output = r#"key\=1=value\=1"#;
        assert_eq!(
            expected_output,
            ServerTransport::escape_and_format_opts(input)
        );
    }
    #[test]
    fn test_escape_and_format_opts_multiple_opts_escaped() {
        let mut input: BTreeMap<String, String> = BTreeMap::new();
        input.insert(r#"key,2"#.to_string(), r#"value,2"#.to_string());
        input.insert(r#"key=1"#.to_string(), r#"value=1"#.to_string());
        let expected_output = r#"key\=1=value\=1,key\,2=value\,2"#;
        assert_eq!(
            expected_output,
            ServerTransport::escape_and_format_opts(input)
        );
    }
}
