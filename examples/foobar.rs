use onion_peel;
/// This example demonstrates a pluggable transport that replaces each 0 with "foo" and each 1 with "bar".
///
/// Obviously, it provides no additional protection and is to be used for demonstration purposes only.
use std::convert::TryInto;

use socks5_frontend;

use std::io;
use std::io::Read;
use std::io::Write;
use std::net;
use std::str;
use std::thread;
use std::time;

fn main() {
    // The parent process communicates initial configuration to us via environment variables.
    // init() reads them and panics in case the requested configuration violates the PT specification
    // or the library doesn't support the requested configuration, as these sorts of errors are not recoverable.

    // Determine whether tor wants us to run as client or as server
    let side = onion_peel::get_side();
    match side {
        onion_peel::ProtoSide::ClientSide => {
            client(onion_peel::Client::init(vec!["foobar".to_string()]))
        }
        onion_peel::ProtoSide::ServerSide => {
            server(onion_peel::Server::init(vec!["foobar".to_string()]))
        }
    }
}

fn client(mut client: onion_peel::Client) {
    // Check whether we should use an upstream proxy (tor -> PT client -> upstream proxy -> PT server)
    // TODO: User must indicate the supported proxy protocols
    match client.get_upstream_proxy() {
        // For the sake of simplicity this example application does not support upstream proxies.
        // Note that according to the specification your transport *must* support this.
        // As the library can't know which types of upstream proxies your application supports,
        // it's up to you to decide which proxy protocols you wish to handle.
        // Remember to call client.report_upstream_proxy_success() if you can connect to the proxy,
        // and client.report_upstream_proxy_failure() to report that you can't.
        Some(_) => panic!("We don't support upstream proxies!"),
        None => (),
    };

    // The next steps have to be performed for each of our transports tor has requested to be initialized
    let transports_wrapped = client.get_transports_to_initialize();
    match transports_wrapped {
        Some(transports) => {
            for transport in transports {
                // For each supported pluggable transport initialize a proxy (SOCKS4 or 5, preferably 5).
                // This proxy is where traffic from the tor client enters, after which it's your job to (de)obfuscate it and send it along.
                // Usually a good idea to bind to localhost so your proxy can't be (ab)used by others on the network.
                let addr = "127.0.0.1:1080".parse::<net::SocketAddr>().unwrap(); // TODO: Pick random free port
                client_bind(addr);

                // Tell tor that the transport has been successfully initialized
                transport.report_success(onion_peel::TorProxyTypes::SOCKS5, addr);
                // Or that the transport has failed to initialize
                // server.report_failure(transport_name, "Could not initialize transport forwarder because foobar")
            }
            client.report_setup_done();

            // And wait for the parent to close stdout as the signal to clean up and shut down.
            // Otherwise, terminating us is up to the parent.
            // Blocking here is important, as without it the main thread exits immediately and your transports stop working!
            let stdin = io::stdin();
            let mut line_buffer = String::new();
            loop {
                if client.should_exit_on_stdin_close() {
                    // Check for EOF of stdin
                    match stdin.read_line(&mut line_buffer) {
                        Ok(0) => break,
                        Ok(_) => (),
                        Err(e) => panic!(e),
                    }
                    line_buffer.clear();
                }
                thread::sleep(time::Duration::from_secs(1));
            }
        }
        None => panic!("No transports to enable!"),
    };
}

fn client_bind(addr: net::SocketAddr) {
    // Tor expects us to start a SOCKS proxy here which binds to bind_addr, receives connections from the tor client,
    // obfuscates the traffic and sends it back out (possibly via the proxy URL tor specified)
    // You should spawn a thread here, so that client() can continue to bring up other transports and notify tor on their status.
    // When running as a client, tor expects you to provide a SOCKS proxy.
    // This proxy will be set up here.
    // We'll use the socks5_frontend library here, but any other SOCKS5 implementation will also work.

    let proxy_server = socks5_frontend::Server::init(
        addr,
        Some(time::Duration::from_secs(1)),
        vec![socks5_frontend::AuthMethod::NoAuth],
        None,
        None,
    )
    .unwrap();
    thread::spawn(move || {
        for may_be_error_conn in proxy_server {
            let conn = may_be_error_conn.unwrap();
            // For each client, open a new TCP connection to the server and start relaying data.
            // This is where you would add actual obfuscation if this were a real PT.
            // Try to dial the requested host
            let remote_addr = conn.get_destination_address_string();

            match net::TcpStream::connect(remote_addr) {
                Ok(remote_stream) => {
                    // Set a timeout for the remote end as well
                    remote_stream
                        .set_read_timeout(Some(time::Duration::from_secs(5)))
                        .unwrap();
                    remote_stream
                        .set_write_timeout(Some(time::Duration::from_secs(5)))
                        .unwrap();
                    // If successful, tell the client to expect data to start being relayed
                    let ready_conn = conn.report_success().unwrap();

                    // Start relaying data between the two streams
                    // by spawning 2 threads to continuously copy on both directions.
                    // This is not very efficient, but good enough for a demo.
                    // We need to clone the stream here because both the reading and writing threads need a mutable handle
                    let mut client_stream_1 = ready_conn.get_stream();
                    let mut client_stream_2 = client_stream_1.try_clone().unwrap();
                    let mut server_stream_1 = remote_stream;
                    let mut server_stream_2 = server_stream_1.try_clone().unwrap();
                    // Client => Server
                    thread::spawn(move || {
                        // Encode each byte
                        let mut buf: [u8; 1] = [0];
                        let mut result_buf: [u8; 24] = [0; 24];
                        loop {
                            client_stream_1.read_exact(&mut buf).unwrap();
                            result_buf = encode(buf[0]);
                            server_stream_1.write_all(&result_buf).unwrap();
                        }
                    });
                    thread::spawn(move || {
                        // Decode each byte
                        let mut buf: [u8; 24] = [0; 24];
                        let mut result_buf: [u8; 1] = [0];
                        loop {
                            server_stream_2.read_exact(&mut buf).unwrap();
                            result_buf[0] = decode(buf);
                            client_stream_2.write_all(&result_buf).unwrap();
                        }
                    });
                }
                // If that fails, tell the client
                // Note that in a real-world program you should look at the error closely
                // and invoke the most appropriate error reporting method.
                Err(err) => match err.kind() {
                    io::ErrorKind::ConnectionRefused => conn.report_connection_refused().unwrap(),
                    io::ErrorKind::NotFound => conn.report_destination_unreachable().unwrap(),
                    io::ErrorKind::UnexpectedEof => conn.report_destination_unreachable().unwrap(),
                    _ => conn.report_destination_unreachable().unwrap(),
                },
            };
        }
    });
}

fn server(mut server: onion_peel::Server) {
    let relay_dialer = server.get_relay_dialer();
    match server.get_transports_to_initialize() {
        Some(transports) => {
            for transport in transports {
                // Bind to receive obfuscated traffic from the PT client on the address requested by tor
                let bind_addr: net::SocketAddr;
                match transport.get_bind_addr() {
                    Some(addr) => bind_addr = addr,
                    // You should choose a sane default here.
                    // You should probably consider using 0.0.0.0 (and the IPv6 equivalent) here,
                    // as you probably want clients from any network to be able to connect
                    None => {
                        bind_addr = net::SocketAddr::new(
                            net::IpAddr::V4(net::Ipv4Addr::new(0, 0, 0, 0)),
                            1234,
                        )
                    }
                }
                server_bind(bind_addr, transport.clone(), relay_dialer.clone());

                // Tell tor that the transport has been successfully initialized
                transport.report_success("127.0.0.1:1234".parse().unwrap(), None);
                // Or that the transport has failed to initialize
                // server.report_failure(transport_name, "Could not initialize transport forwarder because foobar")
            }
            // Once all transports have been launched, tell tor that it can start pushing traffic
            server.report_setup_done();

            // And wait for the parent to close stdout as the signal to clean up and shut down.
            // Otherwise, terminating us is up to the parent.
            // Blocking here is important, as without it the main thread exits immediately and your transports stop working!
            let stdin = io::stdin();
            let mut line_buffer = String::new();
            loop {
                if server.should_exit_on_stdin_close() {
                    // Check for EOF of stdin
                    match stdin.read_line(&mut line_buffer) {
                        Ok(0) => break,
                        Ok(_) => (),
                        Err(e) => panic!(e),
                    }
                    line_buffer.clear();
                }
                thread::sleep(time::Duration::from_secs(1));
            }
        }
        None => panic!("no transports to initialize!"),
    }
}

fn server_bind(
    bind_addr: net::SocketAddr,
    transport: onion_peel::ServerTransport,
    relay_dialer: onion_peel::RelayDialer,
) {
    // This is where you actually set up a listener to receive traffic obfuscated by the client component.
    // In our case, that simply means forwarding the data we receive.
    // You should spawn a thread here, so that server() can continue to bring up other transports and notify tor on their status.
    thread::spawn(move || {
        let listener = net::TcpListener::bind(bind_addr).unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(time::Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(time::Duration::from_secs(5)))
                        .unwrap();

                    // Connect to the destination tor relay
                    let relay_stream = relay_dialer
                        .dial(&transport, stream.peer_addr().unwrap())
                        .unwrap();
                    let mut client_stream_1 = stream.try_clone().unwrap();
                    let mut client_stream_2 = client_stream_1.try_clone().unwrap();
                    let mut relay_stream_1 = relay_stream;
                    let mut relay_stream_2 = relay_stream_1.try_clone().unwrap();
                    // Client => Relay
                    thread::spawn(move || {
                        // Decode each byte
                        let mut buf: [u8; 24] = [0; 24];
                        let mut result_buf: [u8; 1] = [0];
                        loop {
                            client_stream_1.read_exact(&mut buf).unwrap();
                            result_buf[0] = decode(buf);
                            relay_stream_1.write_all(&result_buf).unwrap();
                        }
                    });
                    // Relay => Client
                    thread::spawn(move || {
                        // Encode each byte
                        let mut buf: [u8; 1] = [0];
                        let mut result_buf: [u8; 24] = [0; 24];
                        loop {
                            relay_stream_2.read_exact(&mut buf).unwrap();
                            result_buf = encode(buf[0]);
                            client_stream_2.write_all(&result_buf).unwrap();
                        }
                    });
                }
                Err(err) => panic!("Failed to accept client: {}", err),
            }
        }
    });
}

fn encode(msg_byte: u8) -> [u8; 24] {
    // Take each bit and replace it with either "foo" for 0 or "bar" for 1.
    fn get_bit_at(input: u8, n: u8) -> bool {
        if n < 8 {
            return input & (1 << n) != 0;
        } else {
            return false;
        }
    }

    let mut result: [u8; 24] = [0; 24];
    for i in 0..8 {
        if !get_bit_at(msg_byte, i) {
            result[(i * 3) as usize] = 0x66; // ASCII 'f'
            result[(i * 3 + 1) as usize] = 0x6f; // ASCII 'o'
            result[(i * 3 + 2) as usize] = 0x6f; // ASCII 'o'
        } else {
            result[(i * 3) as usize] = 0x62; // ASCI 'b'
            result[(i * 3 + 1) as usize] = 0x61; // ASCII 'a'
            result[(i * 3 + 2) as usize] = 0x72; // ASCII 'r'
        }
    }
    return result;
}

fn decode(msg: [u8; 24]) -> u8 {
    let mut result: u8 = 0;
    fn set_bit_at(mut input: u8, n: u8) -> u8 {
        input |= 1 << n;
        return input;
    }

    // Split the input buffer into 8 strings
    let mut msg_str: [&str; 8] = [&""; 8];
    for (i, part) in msg.chunks(3).enumerate() {
        msg_str[i] = str::from_utf8(part).unwrap();
    }
    // Iterate over the input buffer, taking 3 characters at a time
    for i in 0..8 {
        match msg_str[i] {
            "foo" => (), // All bits are already 0, do nothing
            "bar" => result = set_bit_at(result, i.try_into().unwrap()), // Set the bit to 1
            _ => panic!("Unrecognized sequence: {}", msg_str[i]),
        }
    }
    return result;
}
