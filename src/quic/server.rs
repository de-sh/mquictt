use std::collections::HashMap;
use std::net;
use std::sync::Arc;

use super::MAX_DATAGRAM_SIZE;
use crate::config::Config;
use crate::error::Error;

use log::{debug, error, info, trace, warn};
use mio::Interest;
use ring::rand::*;

struct PartialResponse {
    body: Vec<u8>,
    written: usize,
}

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,
    partial_responses: HashMap<u64, PartialResponse>,
}

pub struct QuicServer {
    cfg: Arc<Config>,
    clients: HashMap<quiche::ConnectionId<'static>, Client>,
}

impl QuicServer {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self {
            cfg,
            clients: HashMap::new(),
        }
    }

    pub async fn accept_clients(&mut self) -> Result<(), Error> {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Setup event loop.
        let mut poll = mio::Poll::new()?;
        let mut events = mio::Events::with_capacity(1024);

        // Create the UDP listening socket, and register it with the event loop.
        let sockaddr = self.cfg.addr.to_owned() + &self.cfg.port;
        let socket = net::UdpSocket::bind(sockaddr)?;
        let mut socket = mio::net::UdpSocket::from_std(socket);
        poll.registry().register(
            &mut socket,
            mio::Token(0),
            Interest::READABLE | Interest::READABLE,
        )?;

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
            .map_err(|_| Error::RingUnspecified)?;

        loop {
            let timeout = self.clients.values().filter_map(|c| c.conn.timeout()).min();
            poll.poll(&mut events, timeout)?;

            // Read incoming UDP packets from the socket and try initiating a connection,
            // until there are no more packets to read.
            'read: loop {
                // If event loop reports no events, the timeout must have expired,
                // handle it without attempting to read packets, then proceed with send loop.
                if events.is_empty() {
                    self.clients.values_mut().for_each(|c| c.conn.on_timeout());
                    break 'read;
                }

                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        // No more UDP packets to read, so end read loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break 'read;
                        }
                        panic!("recv() failed: {:?}", e);
                    }
                };

                debug!("Received {} bytes", len);

                let pkt_buf = &mut buf[..len];

                // Parse the QUIC packet's header.
                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    }
                };

                trace!("got packet {:?}", hdr);

                let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                let conn_id = (&conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN])
                    .to_vec()
                    .into();

                // Lookup a connection based on the packet's connection ID. If there
                // is no connection matching, create a new one.
                let client = if !self.clients.contains_key(&hdr.dcid)
                    && !self.clients.contains_key(&conn_id)
                {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue 'read;
                    }

                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");

                        let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);

                    let scid = quiche::ConnectionId::from_ref(&scid);

                    // Token is always present in Initial packets.
                    let token = match hdr.token.as_ref() {
                        Some(t) => t,
                        None => return Err(Error::MissingToken),
                    };

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let new_token = mint_token(&hdr, &from);
                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )?;
                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    let odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue 'read;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry packet,
                    // instead of changing it again.
                    let scid = hdr.dcid.clone();

                    debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);
                    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
                    // Configure connection
                    config.load_verify_locations_from_file(&self.cfg.auth.ca_cert_file)?;
                    config.load_cert_chain_from_pem_file(&self.cfg.auth.cert_file)?;
                    config.load_priv_key_from_pem_file(&self.cfg.auth.key_file)?;
                    let client = Client {
                        conn: quiche::accept(&scid, None, from, &mut config)?,
                        partial_responses: HashMap::new(),
                    };

                    self.clients.insert(scid.clone(), client);

                    self.clients.get_mut(&scid).ok_or(Error::MissingClient)?
                } else {
                    match self.clients.get_mut(&hdr.dcid) {
                        Some(v) => v,
                        None => self.clients.get_mut(&conn_id).ok_or(Error::MissingClient)?,
                    }
                };

                let recv_info = quiche::RecvInfo { from };

                // Process potentially coalesced packets.
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                        continue 'read;
                    }
                };

                debug!("{} processed {} bytes", client.conn.trace_id(), read);

                if client.conn.is_in_early_data() || client.conn.is_established() {
                    // Handle writable streams.
                    for stream_id in client.conn.writable() {
                        handle_writable(client, stream_id);
                    }

                    // Process all readable streams.
                    for s in client.conn.readable() {
                        while let Ok((read, fin)) = client.conn.stream_recv(s, &mut buf) {
                            debug!("{} received {} bytes", client.conn.trace_id(), read);

                            let stream_buf = &buf[..read];

                            debug!(
                                "{} stream {} has {} bytes (fin? {})",
                                client.conn.trace_id(),
                                s,
                                stream_buf.len(),
                                fin
                            );

                            handle_stream(client, s, stream_buf, "examples/root");
                        }
                    }
                }
            }

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            for client in self.clients.values_mut() {
                loop {
                    let (write, send_info) = match client.conn.send(&mut out) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            debug!("{} done writing", client.conn.trace_id());
                            break;
                        }

                        Err(e) => {
                            error!("{} send failed: {:?}", client.conn.trace_id(), e);

                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }

                    debug!("{} written {} bytes", client.conn.trace_id(), write);
                }
            }

            // Garbage collect closed connections.
            self.clients.retain(|_, ref mut c| {
                debug!("Collecting garbage");

                if c.conn.is_closed() {
                    info!(
                        "{} connection collected {:?}",
                        c.conn.trace_id(),
                        c.conn.stats()
                    );
                }

                !c.conn.is_closed()
            });
        }
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// TODO: this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// TODO: this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(src: &net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Handles incoming HTTP/0.9 requests.
fn handle_stream(client: &mut Client, stream_id: u64, buf: &[u8], root: &str) {
    let conn = &mut client.conn;

    if buf.len() > 4 && &buf[..4] == b"GET " {
        let uri = &buf[4..buf.len()];
        let uri = String::from_utf8(uri.to_vec()).unwrap();
        let uri = String::from(uri.lines().next().unwrap());
        let uri = std::path::Path::new(&uri);
        let mut path = std::path::PathBuf::from(root);

        for c in uri.components() {
            if let std::path::Component::Normal(v) = c {
                path.push(v)
            }
        }

        info!(
            "{} got GET request for {:?} on stream {}",
            conn.trace_id(),
            path,
            stream_id
        );

        let body = std::fs::read(path.as_path()).unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

        info!(
            "{} sending response of size {} on stream {}",
            conn.trace_id(),
            body.len(),
            stream_id
        );

        let written = match conn.stream_send(stream_id, &body, true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        };

        if written < body.len() {
            let response = PartialResponse { body, written };
            client.partial_responses.insert(stream_id, response);
        }
    }
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    let written = match conn.stream_send(stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}
