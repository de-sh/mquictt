#![allow(unreachable_code)]
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use bytes::{BufMut, Bytes, BytesMut};
use mqttbytes::{
    v4::{self, Connect, Packet, Publish, Subscribe, Unsubscribe},
    QoS,
};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{config::Config, error::Error, Connection};

/// Used to map topics to stream ids and vice-versa.
// TODO: maybe we can avoid storing topics and/or u64 twice
#[derive(Debug, Clone)]
struct Mapper {
    id_to_topic: HashMap<u64, String>,
    topic_to_id: HashMap<String, u64>,
}

impl Mapper {
    fn new() -> Self {
        Mapper {
            id_to_topic: HashMap::new(),
            topic_to_id: HashMap::new(),
        }
    }

    fn get_topic(&mut self, stream_id: u64) -> Option<&String> {
        self.id_to_topic.get(&stream_id)
    }

    fn get_id(&mut self, topic: &str) -> Option<&u64> {
        self.topic_to_id.get(topic)
    }
}

#[derive(Debug)]
pub(crate) enum ClientEvent {
    NewPublish(Bytes),
    NewSubscribe(Bytes),
    Payload(Bytes),
    Close,
    UnSubscribe,
}

pub struct Publisher {
    topic: String,
    stream_id: u64,
    conn: Arc<Mutex<Connection>>,
    buf: BytesMut,
}

impl Publisher {
    pub fn publish(&mut self, payload: Bytes) -> Result<(), Error> {
        if let Err(e) =
            Publish::from_bytes(&self.topic, QoS::AtMostOnce, payload).write(&mut self.buf)
        {
            return Err(Error::MQTT(e));
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), Error> {
        let mut conn = self.conn.lock().unwrap();
        let buf = std::mem::replace(&mut self.buf, BytesMut::new());
        conn.send_to_stream(self.stream_id, buf.freeze())?;
        Ok(())
    }
}

// TODO: blocking flush, for which Connection::blocking_send_to_stream is needed
// impl Drop for Publisher {
//     fn drop(&mut self) {
//         self.flush();
//     }
// }

pub struct Subscriber {
    stream_id: u64,
    topic: String,
    conn: Arc<Mutex<Connection>>,
    buf: BytesMut,
}

impl Subscriber {
    pub async fn recv(&mut self) -> Result<Bytes, Error> {
        let mut conn = self.conn.lock().unwrap();
        loop {
            match v4::read(&mut self.buf, 1024 * 1024) {
                Ok(Packet::Publish(publish)) => return Ok(publish.payload),
                Ok(_) => continue,
                Err(mqttbytes::Error::InsufficientBytes(_)) => {
                    conn.recv_from_stream(self.stream_id, &mut self.buf)?
                }

                Err(e) => return Err(Error::MQTT(e)),
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), Error> {
        let mut conn = self.conn.lock().unwrap();
        let mut buf = BytesMut::new();
        if let Err(e) = Unsubscribe::new(&self.topic).write(&mut buf) {
            return Err(Error::MQTT(e));
        };
        conn.send_to_stream(self.stream_id, buf.freeze())
    }
}

// TODO: blocking flush, for which Connection::blocking_send_to_stream is needed
// impl Drop for Subscriber {
//     fn drop(&mut self) {
//         let _ = self
//             .sender
//             .blocking_send((self.stream_id, ClientEvent::UnSubscribe));
//     }
// }

/// A MQTT client which runs on top of QUIC protocol. Creates a new stream for each publish stream
/// and expects the server to create a new stream for each subscription.
pub struct Client {
    conn: Arc<Mutex<Connection>>,
}

impl Client {
    pub async fn new(
        server_addr: SocketAddr,
        config: Config,
        id: impl Into<String>,
    ) -> Result<Self, Error> {
        let mut conn = Connection::connect(config, server_addr)?;
        let mut buf = BytesMut::new();

        // sending connect
        if let Err(e) = Connect::new(id).write(&mut buf) {
            return Err(Error::MQTT(e));
        }
        let stream_id = conn.create_stream()?;
        conn.recv_from_stream(stream_id, &mut buf)?;

        // wait for connack
        loop {
            match v4::read(&mut buf, 1024 * 1024) {
                Ok(Packet::ConnAck(_)) => break,
                Ok(_) => continue,
                Err(mqttbytes::Error::InsufficientBytes(_)) => {
                    conn.recv_from_stream(stream_id, &mut buf)?;
                    continue;
                }

                Err(e) => return Err(Error::MQTT(e)),
            };
        }

        Ok(Client {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn subscribe(&self, topic: impl Into<String>) -> Result<Subscriber, Error> {
        let mut conn = self.conn.lock().unwrap();
        let topic = topic.into();
        let mut buf = BytesMut::new();
        if let Err(e) = Subscribe::new(&topic, QoS::AtMostOnce).write(&mut buf) {
            return Err(Error::MQTT(e));
        };
        let stream_id = conn.create_stream()?;
        conn.send_to_stream(stream_id, buf.freeze())?;
        Ok(Subscriber {
            conn: self.conn.clone(),
            topic,
            stream_id,
            buf: BytesMut::new(),
        })
    }

    pub fn publish(&self, topic: impl Into<String>) -> Result<Publisher, Error> {
        let mut conn = self.conn.lock().unwrap();
        let stream_id = conn.create_stream()?;
        Ok(Publisher {
            conn: self.conn.clone(),
            topic: topic.into(),
            stream_id,
            buf: BytesMut::new(),
        })
    }
}
