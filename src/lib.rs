use std::{collections::HashMap, net::SocketAddr, sync::Arc};

mod quic;
mod config;
mod error;
use config::Config;
use error::Error;