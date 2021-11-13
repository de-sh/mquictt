use std::net::SocketAddr;

use crate::{error::Error, quic::MAX_DATAGRAM_SIZE};

use bytes::{Bytes, BytesMut};
use log::{debug, error, info};
use mio::Interest;
use ring::rand::*;

const HTTP_REQ_STREAM_ID: u64 = 4;
struct QuicClient {}
impl QuicClient {
    fn connect(peer_addr: SocketAddr, out: &mut BytesMut) -> Result<(), Error> {
        let mut buf = [0; 65535];

        // Setup the event loop.
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let socket = std::net::UdpSocket::bind(bind_addr).unwrap();

        let mut socket = mio::net::UdpSocket::from_std(socket);
        poll.registry()
            .register(
                &mut socket,
                mio::Token(0),
                Interest::READABLE | Interest::WRITABLE,
            )
            .unwrap();

        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        config.verify_peer(true);
        config.set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")?;
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            Some(&format!("{}", peer_addr)),
            &scid,
            peer_addr,
            &mut config,
        )
        .unwrap();

        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(out).expect("initial send failed");

        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send() would block");
                continue;
            }

            panic!("send() failed: {:?}", e);
        }

        debug!("written {}", write);

        let req_start = std::time::Instant::now();
        let mut req_sent = false;

        loop {
            poll.poll(&mut events, conn.timeout()).unwrap();

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                // If the event loop reported no events, it means that the timeout
                // has expired, so handle it without attempting to read packets. We
                // will then proceed with the send loop.
                if events.is_empty() {
                    debug!("timed out");

                    conn.on_timeout();
                    break 'read;
                }

                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("recv() would block");
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    }
                };

                debug!("got {} bytes", len);

                let recv_info = quiche::RecvInfo { from };

                // Process potentially coalesced packets.
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("recv failed: {:?}", e);
                        continue 'read;
                    }
                };

                debug!("processed {} bytes", read);
            }

            debug!("done reading");

            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                return Ok(());
            }

            // Send an HTTP request as soon as the connection is established.
            if conn.is_established() && !req_sent {
                info!("sending HTTP request for {}", peer_addr);

                let req = format!("GET {}\r\n", peer_addr);
                conn.stream_send(HTTP_REQ_STREAM_ID, req.as_bytes(), true)
                    .unwrap();

                req_sent = true;
            }

            // Process all readable streams.
            for s in conn.readable() {
                while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                    debug!("received {} bytes", read);

                    let stream_buf = &buf[..read];

                    debug!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

                    print!("{}", unsafe { std::str::from_utf8_unchecked(stream_buf) });

                    // The server reported that it has no more data to send, which
                    // we got the full response. Close the connection.
                    if s == HTTP_REQ_STREAM_ID && fin {
                        info!("response received in {:?}, closing...", req_start.elapsed());

                        conn.close(true, 0x00, b"kthxbye").unwrap();
                    }
                }
            }

            // Generate outgoing QUIC packets and send them on the UDP socket, until
            // quiche reports that there are no more packets to be sent.
            loop {
                let (write, send_info) = match conn.send(out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("done writing");
                        break;
                    }

                    Err(e) => {
                        error!("send failed: {:?}", e);

                        conn.close(false, 0x1, b"fail").ok();
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

                debug!("written {}", write);
            }

            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                return Ok(());
            }
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
