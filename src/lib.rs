use std::net::SocketAddr;

mod config;
mod error;
use config::Config;
use error::Error;

use quiche::ConnectionId;
pub struct Connection {
    inner: std::pin::Pin<Box<quiche::Connection>>,
}

impl Connection {
    pub fn connect(cfg: Config, to: SocketAddr) -> Result<Self, Error> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        // Initialize authentication
        config.load_verify_locations_from_file(&cfg.auth.ca_cert_file);
        config.load_cert_chain_from_pem_file(&cfg.auth.cert_file);
        config.load_priv_key_from_pem_file(&cfg.auth.key_file);
        
        let scid = ConnectionId::from_ref(&[0xba, 16]);

        Ok(Connection { inner: quiche::connect(None, &scid, to, &mut config)? })
    }
}