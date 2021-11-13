use std::collections::HashMap;
use std::net;
use std::sync::Arc;

use crate::config::Config;
use crate::error::Error;
use crate::Connection;

use log::{debug, error, trace, warn};
use mio::Interest;

pub struct Server {
    cfg: Arc<Config>,
    clients: HashMap<quiche::ConnectionId<'static>, Connection>,
}

impl Server {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self {
            cfg,
            clients: HashMap::new(),
        }
    }

    pub async fn eventloop(&mut self) -> Result<(), Error> {
        let mut buf = [0; 65535];
        let mut out = [0; crate::MAX_DATAGRAM_SIZE];

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

        let rng = ring::rand::SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
            .map_err(|_| Error::RingUnspecified)?;

        loop {
            let timeout = self.clients.values().filter_map(|c| c.timeout()).min();
            poll.poll(&mut events, timeout)?;

            // Read incoming UDP packets from the socket and try initiating a connection,
            // until there are no more packets to read.
            'read: loop {
                // If event loop reports no events, the timeout must have expired,
                // handle it without attempting to read packets, then proceed with send loop.
                if events.is_empty() {
                    self.clients.values_mut().for_each(|c| c.on_timeout());
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

                        let len =
                            quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

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
                        Some(t) => t.clone(),
                        None => return Err(Error::MissingToken)
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
                        )
                        .unwrap();

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

                    let odcid = validate_token(&from, &token);

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

                    let client = Connection::accept(&scid, odcid.as_ref(), from, self.cfg.clone()).await?;

                    self.clients.insert(scid.clone(), client);

                    self.clients.get_mut(&scid).unwrap()
                } else {
                    match self.clients.get_mut(&hdr.dcid) {
                        Some(v) => v,

                        None => self.clients.get_mut(&conn_id).unwrap(),
                    }
                };
            }
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
