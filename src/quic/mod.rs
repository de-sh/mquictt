
use crate::error::Error;

pub(crate) mod client;
pub(crate) mod server;

use bytes::{Bytes, BytesMut};

pub struct Connection {}

impl Connection {
    pub fn create_stream() -> Result<u64, Error> {
        unimplemented!()
    }

    pub fn send_to_stream(&mut self, stream_id: u64, bytes: Bytes) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn recv_from_stream(&mut self, stream_id: u64, bytes: &mut BytesMut) -> Result<(), Error> {
        unimplemented!()
    }
}

const MAX_DATAGRAM_SIZE: usize = 1350;
