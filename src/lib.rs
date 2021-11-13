use std::{net::SocketAddr};

mod config;
mod error;
use config::Config;
use error::Error;

use quiche::ConnectionId;
use bytes::{Bytes, BytesMut};

const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct Connection {
    inner: std::pin::Pin<Box<quiche::Connection>>,
}

impl Connection {
    pub fn connect(cfg: Config, to: SocketAddr) -> Result<Self, Error> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        // Configure connection
        config.set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")?;
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.load_verify_locations_from_file(&cfg.auth.ca_cert_file)?;
        config.load_cert_chain_from_pem_file(&cfg.auth.cert_file)?;
        config.load_priv_key_from_pem_file(&cfg.auth.key_file)?;

        let scid = ConnectionId::from_ref(&[0xba, 16]);

        Ok(Connection {
            inner: quiche::connect(None, &scid, to, &mut config)?,
        })
    }

    pub fn accept(cfg: Config, from: SocketAddr) -> Result<Self, Error> {
        unimplemented!()
    }

    pub fn send_to_topic(&mut self, topic: String, bytes: Bytes) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn recv_from_topic(&mut self, topic: String, bytes: &mut BytesMut) -> Result<(), Error> {
        unimplemented!()
    }
}
