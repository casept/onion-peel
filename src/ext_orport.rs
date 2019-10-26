use std::convert::TryInto;
use std::io;
use std::io::prelude::*;
use std::net;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use ring::{hmac, rand};

const SAFE_COOKIE: u8 = 1;
const NO_SUPPORTED_METHODS: u8 = 0;


// Status codes for ExtORPort cookie auth
const STATUS_SUCCESS: u8 = 1;
const STATUS_FAILURE: u8 = 0;

pub(crate) fn negotiate_connection(
    cookie_with_header: Vec<u8>,
    pt_name: String,
    client_addr: net::SocketAddr,
    mut stream: &mut net::TcpStream,
) -> Result<(), io::Error> {
    let auth_types = read_auth_types(stream)?;
    // As of now, only SAFE_COOKIE (type 1) is specified
    if !auth_types.contains(&SAFE_COOKIE) {
        // Tell the server we can't use any of the methods and panic
        let no_acceptable_methods_buf: [u8; 1] = [NO_SUPPORTED_METHODS];
        stream.write_all(&no_acceptable_methods_buf)?;
        panic!("Failed extORPort authentication: Server didn't offer any known auth methods");
    } else {
        let safe_cookie_buf: [u8; 1] = [SAFE_COOKIE];
        stream.write_all(&safe_cookie_buf)?;
    }

    safe_cookie_handshake(&mut stream, cookie_with_header)?;

    // Send metadata about the connection to the relay
    send_metadata(&mut stream, pt_name, client_addr)?;

    // Determine whether the relay is OK with forwarding our traffic
    let msg = recv_msg(&mut stream)?;
    // TODO: Error handling
    if msg.command != ExtORCommand::Okay {
        panic!(
            "ExtORPort server didn't send expected Okay, sent {:?}",
            msg.command.to_bytes()
        );
    } else {
        return Ok(());
    }
}

fn read_auth_types(stream: &mut net::TcpStream) -> Result<Vec<u8>, io::Error> {
    let mut auth_types: Vec<u8> = Vec::new();
    let mut current_byte_buf: [u8; 1] = [0];
    loop {
        stream.read_exact(&mut current_byte_buf)?;
        if current_byte_buf[0] == 0 {
            break;
        }
        auth_types.push(current_byte_buf[0]);
    }

    // Without an ORPort connection traffic can't be forwarded and the server is useless,
    // therefore a panic is probably appropriate
    // TODO: Reconsider
    if auth_types.is_empty() {
        panic!("Failed extORPort authentication: Server didn't send any auth methods");
    }

    return Ok(auth_types);
}

fn safe_cookie_handshake(
    stream: &mut net::TcpStream,
    cookie_with_header: Vec<u8>,
) -> Result<(), io::Error> {
    // The first 32 bytes of the cookie should be identical to a particular string
    if !cookie_with_header.starts_with("! Extended ORPort Auth Cookie !\x0a".as_bytes()) {
        panic!(
            "Failed extORPort cookie auth: Expected cookie header to be {:?}, was {:?}",
            "! Extended ORPort Auth Cookie !\x0a",
            cookie_with_header.split_at(32).0
        );
    }

    // The next 32 bytes are the actual cookie
    // TODO: Off by 1?
    let cookie_slice = cookie_with_header.split_at(32).1;
    let mut cookie: [u8; 32] = [0; 32];
    let mut i = 0;
    for byte in cookie_slice {
        cookie[i] = *byte;
        i += 1;
    }

    // Perform a handshake to mutually authenticate client and server
    let rng = rand::SystemRandom::new();
    let client_nonce: [u8; 32] = rand::generate(&rng).unwrap().expose();
    stream.write_all(&client_nonce)?;

    let mut server_hash: [u8; 32] = [0; 32];
    stream.read_exact(&mut server_hash)?;

    let mut server_nonce: [u8; 32] = [0; 32];
    stream.read_exact(&mut server_nonce)?;

    // Verify the server hash
    if !verify_server_hash(cookie, server_nonce, client_nonce, server_hash) {
        // TODO: Error handling
        // We must terminate the connection in case of a mismatch
        stream.shutdown(net::Shutdown::Both)?;
        panic!("Computed server hash does not match provided server hash");
    }

    // Compute and send our own hash for the server to verify
    let client_hash = compute_client_hash(cookie, server_nonce, client_nonce);
    stream.write_all(&client_hash)?;

    // Check whether the server considers our hash valid
    let mut status_buf: [u8; 1] = [0];
    stream.read_exact(&mut status_buf)?;
    match status_buf[0] {
        STATUS_SUCCESS => return Ok(()),
        STATUS_FAILURE => panic!("Server rejected our extORPort authentication attempt"),
        _ => panic!("Server supplied invalid status code for extORPort authentication"),
    }
}

fn verify_server_hash(
    cookie: [u8; 32],
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
    server_hash: [u8; 32],
) -> bool {
    //  HMAC-SHA256(CookieString, "ExtORPort authentication server-to-client hash" | ClientNonce | ServerNonce)
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice("ExtORPort authentication server-to-client hash".as_bytes());
    msg.extend_from_slice(&client_nonce);
    msg.extend_from_slice(&server_nonce);
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, &cookie);
    match hmac::verify(&s_key, &msg.as_ref(), &server_hash) {
        Ok(_) => return true,
        Err(_) => return false,
    }
}

fn compute_client_hash(cookie: [u8; 32], server_nonce: [u8; 32], client_nonce: [u8; 32]) -> [u8; 32] {
    // HMAC-SHA256(CookieString, "ExtORPort authentication client-to-server hash" | ClientNonce | ServerNonce)
    let parts = [
        "ExtORPort authentication client-to-server hash".as_bytes(),
        &client_nonce,
        &server_nonce,
    ];
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, &cookie);
    let mut s_ctx = hmac::Context::with_key(&s_key);
    for part in &parts {
        s_ctx.update(part);
    }
    let tag_tag = s_ctx.sign();
    let tag = tag_tag.as_ref();
    if tag.len() != 32 {
        panic!("Unexpected HMAC tag length: expected 32, got {}", tag.len());
    } else {
        let mut tag_array: [u8; 32] = [0; 32];
        let mut i = 0;
        for byte in tag {
            tag_array[i] = *byte;
            i += 1;
        }
        return tag_array;
    }
}

#[derive(PartialEq)]
enum ExtORCommand {
    Done,
    UserAddr,
    Transport,
    Okay,
    Deny,
    Control,
    Unknown,
}

impl ExtORCommand {
    fn from_bytes(bytes: [u8; 2]) -> ExtORCommand {
        match bytes {
            // Commands from transport to relay for ExtORPort protocol
            [0x00, 0x00] => ExtORCommand::Done,
            [0x00, 0x01] => ExtORCommand::UserAddr,
            [0x00, 0x02] => ExtORCommand::Transport,
            // Commands from relay to transport for ExtORPort protocol
            [0x10, 0x00] => ExtORCommand::Okay,
            [0x10, 0x01] => ExtORCommand::Deny,
            [0x10, 0x02] => ExtORCommand::Control,
            _ => ExtORCommand::Unknown,
        }
    }

    fn to_bytes(&self) -> [u8; 2] {
        match self {
            ExtORCommand::Done => [0x00, 0x00],
            ExtORCommand::UserAddr => [0x00, 0x01],
            ExtORCommand::Transport => [0x00, 0x02],
            ExtORCommand::Okay => [0x10, 0x00],
            ExtORCommand::Deny => [0x10, 0x01],
            ExtORCommand::Control => [0x10, 0x02],
            ExtORCommand::Unknown => panic!("Attempt to serialize unknown ExtORCommand"),
        }
    }
}

struct ExtORMessage {
    command: ExtORCommand,
    body: Option<Vec<u8>>,
}

impl ExtORMessage {
    fn read_from_stream(stream: &mut net::TcpStream) -> Result<ExtORMessage, io::Error> {
        // Read the type of command
        let mut command_buf: [u8; 2] = [0xDE, 0xAD];
        stream.read_exact(&mut command_buf)?;
        let command = ExtORCommand::from_bytes(command_buf);

        // Determine whether the command has a meaningful body
        // If the command doesn't, the spec states that the body is ignored (but not absent!)
        // In order to not mess up the alignment of our reads with the server, we simply read it anyway
        // and ignore it.
        let ignore_body;
        match command {
            ExtORCommand::Done => ignore_body = true,
            ExtORCommand::UserAddr => ignore_body = false,
            ExtORCommand::Transport => ignore_body = false,
            ExtORCommand::Okay => ignore_body = true,
            ExtORCommand::Deny => ignore_body = true,
            ExtORCommand::Control => ignore_body = false,
            ExtORCommand::Unknown => ignore_body = false,
        }

        // Read the length of message to follow (requires endianess conversion)
        let body_len = stream.read_u16::<NetworkEndian>()?;
        // Read the message itself
        let mut body_buf: Vec<u8> = vec![0xDE; body_len.try_into().unwrap()];
        stream.read_exact(&mut body_buf)?;

        if ignore_body {
            return Ok(ExtORMessage {
                command,
                body: None,
            });
        } else {
            return Ok(ExtORMessage {
                command,
                body: Some(body_buf),
            });
        }
    }

    fn write_to_stream(&self, stream: &mut net::TcpStream) -> Result<(), io::Error> {
        // Send the type of command
        let cmd_buf: [u8; 2] = self.command.to_bytes();
        stream.write_all(&cmd_buf)?;

        // Calculate the length of the body
        // If we don't have a body, the length is 0
        let body_len: u16;
        match &self.body {
            Some(val) => body_len = val.len().try_into().unwrap(),
            None => body_len = 0,
        }
        stream.write_u16::<NetworkEndian>(body_len)?;

        // Send the body
        if body_len > 0 {
            stream.write_all(&self.body.as_ref().unwrap())?;
        }

        return Ok(());
    }
}

/// Send metadata which the relay expects before the connection's data is transferred
fn send_metadata(
    stream: &mut net::TcpStream,
    transport_name: String,
    client_addr: net::SocketAddr,
) -> Result<(), io::Error> {
    send_client_addr(stream, client_addr)?;
    send_transport_name(stream, transport_name)?;
    send_setup_done(stream)?;
    return Ok(());
}

/// Send the address of the client to the PT
fn send_client_addr(
    mut stream: &mut net::TcpStream,
    client_addr: net::SocketAddr,
) -> Result<(), io::Error> {
    // Tell the server the client's address
    // The formatting differs between v4 and v6 addresses
    // v4: 1.2.3.4:5678
    // v6: [1:2::3:4]:5678
    let ip: String;
    match client_addr.ip() {
        net::IpAddr::V4(addr) => ip = format!("{}", addr),
        net::IpAddr::V6(addr) => ip = format!("[{}]", addr),
    }
    let port = client_addr.port();
    let addr_body_str: String = format!("{}:{}", ip, port);
    let addr_body: &[u8] = addr_body_str.as_bytes();
    let addr_msg = ExtORMessage {
        command: ExtORCommand::UserAddr,
        body: Some(addr_body.to_vec()),
    };
    addr_msg.write_to_stream(&mut stream)?;
    return Ok(());
}

/// Send the name of the PT to the relay
fn send_transport_name(
    mut stream: &mut net::TcpStream,
    transport_name: String,
) -> Result<(), io::Error> {
    let transport_msg = ExtORMessage {
        command: ExtORCommand::Transport,
        body: Some(transport_name.as_bytes().to_vec()),
    };
    transport_msg.write_to_stream(&mut stream)?;
    return Ok(());
}

/// Report to the relay that we're going to send client traffic next
fn send_setup_done(mut stream: &mut net::TcpStream) -> Result<(), io::Error> {
    let done_msg = ExtORMessage {
        command: ExtORCommand::Done,
        body: None,
    };
    done_msg.write_to_stream(&mut stream)?;
    return Ok(());
}

/// Receive a message from the relay
fn recv_msg(stream: &mut net::TcpStream) -> Result<ExtORMessage, io::Error> {
    let msg = ExtORMessage::read_from_stream(stream)?;
    // TODO: error handling
    match msg.command {
        // Only a client should send these
        ExtORCommand::Done => panic!("Got client-only message from extORPort server!"),
        ExtORCommand::UserAddr => panic!("Got client-only message from extORPort server!"),
        ExtORCommand::Transport => panic!("Got client-only message from extORPort server!"),
        ExtORCommand::Okay => (),
        ExtORCommand::Deny => (),
        ExtORCommand::Control => (),
        ExtORCommand::Unknown => (),
    }
    return Ok(msg);
}
