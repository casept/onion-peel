use std::{env, fs, path};
use crate::init_error::InitError;

// Shared by both client and server implementations.
#[derive(Clone)]
pub(crate) struct SharedConfig {
    pub transport_state_location: path::PathBuf,
    pub exit_on_stdin_close: bool,
}

impl SharedConfig {
    pub(crate) fn init() -> Result<SharedConfig, InitError> {
        let mut sc = SharedConfig::new();
        // Parse protocol versions the parent process supports
        match env::var("TOR_PT_MANAGED_TRANSPORT_VER") {
            Ok(val) => {
                if val != "" {
                    SharedConfig::parse_pt_versions(val)?;
                } else {
                    return Err(InitError::EmptyEnvVarError("TOR_PT_MANAGED_TRANSPORT_VER".to_string()));
                }
            },
            Err(e) => match e {
                env::VarError::NotPresent => return Err(InitError::MissingEnvVarError("TOR_PT_MANAGED_TRANSPORT_VER".to_string())),
                env::VarError::NotUnicode(_) => return Err(InitError::ParserError(
                format!("Could not get list of managed transport versions supported by parent process: {}",e))),
        }
        }

        // Obtain the directory the plugable transport is allowed to store persistent data in
        match env::var("TOR_PT_STATE_LOCATION") {
            Ok(val) => {
                if val != "" {
                    sc.transport_state_location = path::PathBuf::from(val);
                } else {
                    println!("ENV-ERROR TOR_PT_STATE_LOCATION not set");
                    return Err(InitError::EmptyEnvVarError("TOR_PT_STATE_LOCATION".to_string()))
                }
            },
            Err(e) => match e {
                env::VarError::NotPresent => return Err(InitError::MissingEnvVarError("TOR_PT_STATE_LOCATION".to_string())),
                env::VarError::NotUnicode(_) => return Err(InitError::ParserError(
                format!("Failed to obtain the path to where we're allowed to store files: {}", e))),
        }
        }

        // Check whether we're supposed to terminate when stdin is closed
        match env::var("TOR_PT_EXIT_ON_STDIN_CLOSE") {
            Ok(val) => {
                if val == "1" {
                    sc.exit_on_stdin_close = true;
                } else {
                    sc.exit_on_stdin_close = false;
                }
            }
            Err(error) => match error {
                env::VarError::NotPresent => return Err(InitError::MissingEnvVarError("TOR_PT_EXIT_ON_STDIN_CLOSE".to_string())),
                env::VarError::NotUnicode(_) => return Err(InitError::ParserError(
                    format!("Could not figure out whether to exit on parent closing stdin: {}", error))),
            },
        }

        // Create the directory where we're allowed to store state
        match fs::create_dir_all(sc.transport_state_location.clone()) {
            Ok(_) => (),
            Err(err) => return Err(InitError::CreateStateDirectoryError(err)),
        };

        return Ok(sc);
    }

    pub(crate) fn new() -> SharedConfig {
        SharedConfig {
            transport_state_location: path::PathBuf::new(),
            exit_on_stdin_close: false,
        }
    }

    fn parse_pt_versions(s: String) -> Result<(), InitError> {
        // The versions are a coma-separated list
        let items_str: Vec<&str> = s.split(",").collect();
        let mut items: Vec<String> = Vec::new();
        for item in items_str {
            items.push(item.to_owned())
        }

        // As of now (August 2019), only version 1 of the PT spec has been published.
        // Therefore, this library doesn't know how to deal with other versions.
        if !items.contains(&"1".to_string()) {
            // Tell parent process that there's no compatible version
            println!("VERSION-ERROR no-version");
            return Err(InitError::SpecVersionError(s));
        } else {
            // Tell parent we'll use version 1
            println!("VERSION 1");
        }
        return Ok(());
    }
}
