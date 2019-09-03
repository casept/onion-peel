use std::env;

pub mod client;
mod parsers;
pub mod log;
pub mod server;
mod shared_config;
mod transport;

pub enum ProtoSide {
    ClientSide,
    ServerSide,
}

pub fn get_side() -> ProtoSide {
    // Determine whether tor wants us to run as a client or server.
    // While this information is not explicitly provided to us, we can infer it based on whether the
    // TOR_PT_CLIENT_TRANSPORTS env var is set (it must be set if we're to serve as a client).
    match env::var("TOR_PT_CLIENT_TRANSPORTS") {
        Ok(_) => return ProtoSide::ClientSide,
        Err(error) => match error {
            env::VarError::NotPresent => return ProtoSide::ServerSide,
            env::VarError::NotUnicode(_) => panic!(
                "Could not determine whether parent wants us to act as client or server: {}",
                error
            ),
        },
    }
}

// TODO: Expose exit_on_stdin_close
// TODO: Documentation
