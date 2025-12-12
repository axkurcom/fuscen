// Server side SCTP accept + UDP forwarding with sync and async modes
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use socket2::Socket;

use crate::async_io::AsyncIO;
use crate::constants::MAX_PACKET_SIZE;
use crate::crypto::TunnelCrypto;
use crate::network;
use crate::protocol::{
    decode_control, decode_frame, encode_control, encode_frame, ControlMessage, FrameType,
    STREAM_ID_CONTROL, STREAM_ID_DATA_DEFAULT, PROTOCOL_VERSION,
};
use crate::sctp::SctpAssociation;
use crate::stats::TrafficStats;
use crate::table;

/// Server runtime configuration
#[derive(Clone)]
pub struct ServerConfig {
    pub sctp_port: u16,
    pub ax_backend: SocketAddr,
    pub udp_buffer_size: usize,
    pub debug_level: Option<u8>,
    pub debug_frequency: u64,
    pub stats_interval: u64,
    pub table_width: usize,
    pub workers: usize,
    pub pool_enabled: bool,
    pub pool_size: usize,
    pub nonblocking: bool, // используется только для UDP в sync-режиме
    pub zero_copy: bool,
    pub use_async_io: bool,
}

// Token kind for AsyncIO demux
#[derive(Copy, Clone, Debug)]
enum FdKind {
    Sctp = 0,
    Udp = 1,
}

// Pack conn_id and fd kind into token
fn make_token(conn_id: u32, kind: FdKind) -> u64 {
    ((conn_id as u64) << 8) | (kind as u64)
}

// Unpack token into (conn_id, kind)
fn parse_token(token: u64) -> (u32, FdKind) {
    let kind = match (token & 0xFF) as u8 {
        0 => FdKind::Sctp,
        1 => FdKind::Udp,
        _ => FdKind::Sctp,
    };
    let conn_id = (token >> 8) as u32;
    (conn_id, kind)
}

/// Main server loop
pub fn run_server(config: ServerConfig, crypto: TunnelCrypto) {
    // SCTP blocking depends on async mode
    // UDP blocking depends on mode and flag

    let sctp_nonblocking = config.use_async_io;

    // Shared socket options template
    let socket_config = network::SocketConfig {
        send_buffer_size: config.udp_buffer_size,
        recv_buffer_size: config.udp_buffer_size,
        nonblocking: sctp_nonblocking,
        zero_copy: config.zero_copy,
        ..Default::default()
    };

    // Bind SCTP listener
    let listener = network::create_sctp_listener(config.sctp_port, &socket_config)
        .expect("[FATAL] Failed to create SCTP Listener");

    // Async backend availability
    let mut async_supported = false;
    if config.use_async_io {
        async_supported = crate::async_io::check_async_support();
        if async_supported {
            println!(
                "[✓] Async I/O ({} support enabled)",
                if cfg!(target_os = "linux") { "epoll" } else { "kqueue" }
            );
        } else {
            println!("[⚠] Async I/O not supported on this platform");
        }
    }

    // Startup info table rows
    let info_rows = vec![
        table::TableRow::simple(
            "SCTP Local on",
            &format!("0.0.0.0:{}", config.sctp_port),
        ),
        table::TableRow::simple("UDP Endpoint", &config.ax_backend.to_string()),
        table::TableRow::new(
            "UDP Buffer",
            format!("{:>6} MB", config.udp_buffer_size / 1024 / 1024),
        ),
        table::TableRow::new("Workers", format!("{:>6}", config.workers)),
        table::TableRow::new(
            "Connection Pool",
            format!("{:>6}", if config.pool_enabled { "Yes" } else { "No" }),
        ),
        table::TableRow::new(
            "Non-blocking",
            format!(
                "{:>6}",
                if config.nonblocking || (config.use_async_io && async_supported) {
                    "Yes"
                } else {
                    "No"
                }
            ),
        ),
        table::TableRow::new(
            "Zero-copy",
            format!("{:>6}", if config.zero_copy { "Yes" } else { "No" }),
        ),
        table::TableRow::new(
            "Async I/O",
            format!(
                "{:>6}",
                if config.use_async_io && async_supported { "Yes" } else { "No" }
            ),
        ),
        table::TableRow::new("Debug Level", format!("{:>6}", config.debug_level.unwrap_or(0))),
        table::TableRow::new(
            "Statistics",
            format!("every {:>2} sec", config.stats_interval),
        ),
    ];

    // Print banner table
    println!(
        "{}",
        table::create_table("Fuscen Stream 13 with Async I/O", info_rows, config.table_width)
    );

    // Optional CPU feature hint
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;
        unsafe {
            let cpuid = __cpuid(1);
            let has_aesni = (cpuid.ecx & (1 << 25)) != 0;
            println!("[ℹ] AES-NI Support: {}", if has_aesni { "Yes ✅" } else { "No ⚠" });
        }
    }

    // Shared server stats
    let server_stats = Arc::new(TrafficStats::new());

    // Stats printing thread
    {
        let stats_display = server_stats.clone();
        let stats_interval = config.stats_interval;
        let table_width = config.table_width;
        let crypto_stats = crypto.clone();
        let debug_level = config.debug_level;
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(stats_interval));
            stats_display.print_stats("STATISTICS - Stream", stats_interval, table_width);

            // Optional crypto telemetry
            let (enc_ops, dec_ops, processed) = crypto_stats.get_performance_stats();
            if debug_level.unwrap_or(0) >= 2 && processed > 0 {
                println!(
                    "[🔐] Crypto: EncryptOps={}, DecryptOps={}, Processed={} bytes",
                    enc_ops, dec_ops, processed
                );
            }
        });
    }

    // Accept queue to workers
    let (tx, rx) = std::sync::mpsc::channel::<(Socket, socket2::SockAddr)>();
    let rx = Arc::new(Mutex::new(rx));

    // Worker shared clones
    let worker_crypto = crypto.clone();
    let worker_config = config.clone();
    let worker_stats = server_stats.clone();
    let use_async = config.use_async_io && async_supported;

    // Spawn worker threads
    for worker_id in 0..config.workers {
        let crypto = worker_crypto.clone();
        let config = worker_config.clone();
        let stats = worker_stats.clone();
        let rx = rx.clone();
        let use_async = use_async;

        thread::spawn(move || {
            if use_async {
                async_worker_loop(worker_id, rx, crypto, config, stats);
            } else {
                worker_loop(worker_id, rx, crypto, config, stats);
            }
        });
    }

    // Drop local rx handle
    drop(rx);

    // Accept loop
    let mut connection_count = 0;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                connection_count += 1;

                // Debug accept log
                if config.debug_level.unwrap_or(0) >= 2 {
                    let peer_addr = match peer.as_socket_ipv4() {
                        Some(addr) => addr.to_string(),
                        None => format!("{:?}", peer),
                    };
                    println!("[INFO] Connection #{} from {}", connection_count, peer_addr);
                }

                // Dispatch to workers
                if tx.send((stream, peer)).is_err() {
                    if config.debug_level.unwrap_or(0) >= 1 {
                        eprintln!("[ERROR] Worker channel full, dropping connection");
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // Backoff for nonblocking accept
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                // Log and keep running
                if config.debug_level.unwrap_or(0) >= 1 {
                    eprintln!("[ERROR] Accept error: {}", e);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ---------------- SYNC worker ----------------

/// Per-connection sync worker dispatcher
fn worker_loop(
    worker_id: usize,
    rx: Arc<Mutex<Receiver<(Socket, socket2::SockAddr)>>>,
    crypto: TunnelCrypto,
    config: ServerConfig,
    stats: Arc<TrafficStats>,
) {
    // Each accepted SCTP goes to a pair of threads
    while let Ok((sctp_stream, peer)) = rx.lock().unwrap().recv() {
        let peer_addr = match peer.as_socket_ipv4() {
            Some(addr) => addr.to_string(),
            None => format!("{:?}", peer),
        };

        // Debug ownership
        if config.debug_level.unwrap_or(0) >= 2 {
            println!("[INFO] Worker {} handling {}", worker_id, peer_addr);
        }

        // UDP socket config for this connection
        let socket_config = network::SocketConfig {
            send_buffer_size: config.udp_buffer_size,
            recv_buffer_size: config.udp_buffer_size,
            nonblocking: config.nonblocking,
            zero_copy: config.zero_copy,
            ..Default::default()
        };

        // Bind ephemeral UDP local
        let udp_local: UdpSocket =
            network::create_udp_socket("127.0.0.1:0".parse().unwrap(), &socket_config)
                .unwrap_or_else(|_| {
                    UdpSocket::bind("127.0.0.1:0").expect("[FATAL] UDP Local Bind Failed")
                });

        // Remember local UDP port for logs
        let local_port = udp_local.local_addr().unwrap().port();

        // Split SCTP into RX and TX handles
        let sctp_rx = SctpAssociation::new(
            sctp_stream
                .try_clone()
                .expect("[FATAL] Failed to clone SCTP socket for RX"),
        );
        let sctp_tx = SctpAssociation::new(sctp_stream);

        // Split UDP into two handles
        let udp_for_sctp = udp_local
            .try_clone()
            .expect("[FATAL] UDP clone for SCTP failed");
        let udp_for_udp = udp_local;

        // Clone shared state for threads
        let crypto_rx = crypto.clone();
        let crypto_tx = crypto.clone();
        let stats_rx = stats.clone();
        let stats_tx = stats.clone();
        let debug_level = config.debug_level;
        let debug_frequency = config.debug_frequency;
        let ax_backend = config.ax_backend;

        let peer_addr_for_sctp = peer_addr.clone();
        let peer_addr_for_udp = peer_addr;

        // Thread SCTP -> UDP
        thread::spawn(move || {
            process_sctp_to_udp(
                sctp_rx,
                crypto_rx,
                udp_for_sctp,
                ax_backend,
                peer_addr_for_sctp,
                local_port,
                stats_rx,
                debug_level,
                debug_frequency,
                worker_id,
            );
        });

        // Thread UDP -> SCTP
        thread::spawn(move || {
            process_udp_to_sctp(
                sctp_tx,
                crypto_tx,
                udp_for_udp,
                peer_addr_for_udp,
                stats_tx,
                debug_level,
                debug_frequency,
                worker_id,
                config.nonblocking,
            );
        });
    }
}

// ---------------- ASYNC worker ----------------

/// Per-connection async state
struct ConnectionState {
    // Token id used by poller
    conn_id: u32,

    // I/O endpoints
    assoc: SctpAssociation,
    udp_socket: UdpSocket,

    // Crypto context
    crypto: TunnelCrypto,

    // Backend UDP target
    ax_backend: SocketAddr,

    // Client label for logs
    client_addr: String,

    // Per-connection UDP source port
    local_port: u16,

    // Shared stats
    stats: Arc<TrafficStats>,

    // Buffers to reduce alloc
    sctp_recv_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    frame_plain_buf: Vec<u8>,
    cipher_buf: Vec<u8>,
    udp_read_buf: Vec<u8>,

    // Pending SCTP writes
    out_queue: VecDeque<(u16, Vec<u8>)>,

    // Debug and error counters
    packet_counter: u64,
    error_counter: u64,

    // Nonce counters per direction
    tx_counter: u64,
    rx_counter: u64,

    // Unused legacy counters kept as-is
    tx_counter: u64,
    rx_counter: u64,
}

impl ConnectionState {
    /// Queue message for SCTP write
    fn enqueue_message(&mut self, stream_id: u16, data: Vec<u8>) {
        self.out_queue.push_back((stream_id, data));
    }

    /// Try drain write queue until WouldBlock
    fn try_flush_out_queue(&mut self) -> io::Result<()> {
        while let Some((sid, msg)) = self.out_queue.front() {
            match self.assoc.send(*sid, msg) {
                Ok(n) if n == msg.len() => {
                    self.out_queue.pop_front();
                }
                Ok(_) => {
                    // Detect partial sends
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "partial SCTP send"));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Backpressure
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Send server HELLO on control stream
    fn send_server_hello(&mut self) {
        let mut control_payload = Vec::with_capacity(32);
        let flags = if self.crypto.is_aes256() { 0x01 } else { 0x00 };
        let hello = ControlMessage::Hello {
            version: PROTOCOL_VERSION,
            flags,
        };
        encode_control(&hello, &mut control_payload);
        encode_frame(
            FrameType::Control,
            STREAM_ID_CONTROL,
            &control_payload,
            &mut self.frame_plain_buf,
        );

        // Encrypt framed payload
        let ct_len = self.crypto.encrypt(
            self.tx_counter,
            &self.frame_plain_buf[..],
            &mut self.cipher_buf,
        );
        self.tx_counter = self.tx_counter.wrapping_add(1);

        // Enqueue and best-effort flush
        let msg = self.cipher_buf[..ct_len].to_vec();
        self.enqueue_message(STREAM_ID_CONTROL, msg);
        let _ = self.try_flush_out_queue();
    }
}

/// Async worker event loop
fn async_worker_loop(
    worker_id: usize,
    rx: Arc<Mutex<Receiver<(Socket, socket2::SockAddr)>>>,
    crypto: TunnelCrypto,
    config: ServerConfig,
    stats: Arc<TrafficStats>,
) {
    // Create poller
    let async_io = AsyncIO::new().expect("[FATAL] Failed to create async I/O");

    // Active connections map
    let mut connections: HashMap<u32, ConnectionState> = HashMap::new();
    let mut next_conn_id: u32 = 1;

    loop {
        // Accept new connections from channel
        loop {
            let msg = {
                let lock = rx.lock().unwrap();
                match lock.try_recv() {
                    Ok(m) => Some(m),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => return,
                }
            };

            let (mut sctp_stream, peer) = match msg {
                Some(v) => v,
                None => break,
            };

            let peer_addr = match peer.as_socket_ipv4() {
                Some(addr) => addr.to_string(),
                None => format!("{:?}", peer),
            };

            if config.debug_level.unwrap_or(0) >= 2 {
                println!("[INFO] Async Worker {} handling {}", worker_id, peer_addr);
            }

            // Force SCTP nonblocking
            if let Err(e) = sctp_stream.set_nonblocking(true) {
                eprintln!(
                    "[ERROR] Async Worker {}: failed to make SCTP non-blocking: {}",
                    worker_id, e
                );
                continue;
            }

            // UDP always nonblocking in async mode
            let socket_config = network::SocketConfig {
                send_buffer_size: config.udp_buffer_size,
                recv_buffer_size: config.udp_buffer_size,
                nonblocking: true,
                zero_copy: config.zero_copy,
                ..Default::default()
            };

            // Bind per-connection UDP local
            let local_udp: UdpSocket =
                network::create_udp_socket("127.0.0.1:0".parse().unwrap(), &socket_config)
                    .unwrap_or_else(|_| {
                        UdpSocket::bind("127.0.0.1:0").expect("[FATAL] UDP Local Bind Failed")
                    });

            let local_port = local_udp.local_addr().unwrap().port();

            // Assign connection id
            let conn_id = next_conn_id;
            next_conn_id = next_conn_id.wrapping_add(1);

            // Build connection state
            let mut state = ConnectionState {
                conn_id,
                assoc: SctpAssociation::new(sctp_stream),
                udp_socket: local_udp,
                crypto: crypto.clone(),
                ax_backend: config.ax_backend,
                client_addr: peer_addr,
                local_port,
                stats: stats.clone(),

                sctp_recv_buf: vec![0u8; MAX_PACKET_SIZE + 32],
                plain_buf: Vec::with_capacity(MAX_PACKET_SIZE + 32),
                frame_plain_buf: Vec::with_capacity(MAX_PACKET_SIZE + 32),
                cipher_buf: Vec::with_capacity(MAX_PACKET_SIZE + 32),
                udp_read_buf: vec![0u8; MAX_PACKET_SIZE],

                out_queue: VecDeque::new(),

                packet_counter: 0,
                error_counter: 0,
                tx_counter: 0,
                rx_counter: 0,
            };

            // Initial HELLO
            state.send_server_hello();

            // Register fds in poller
            let sctp_fd = state.assoc.as_raw_fd();
            let udp_fd = state.udp_socket.as_raw_fd();

            let sctp_token = make_token(conn_id, FdKind::Sctp);
            let udp_token = make_token(conn_id, FdKind::Udp);

            async_io
                .add_fd(sctp_fd, sctp_token, true, true)
                .expect("Failed to add SCTP to async I/O");
            async_io
                .add_fd(udp_fd, udp_token, true, false)
                .expect("Failed to add UDP to async I/O");

            connections.insert(conn_id, state);
        }

        // Poll for readiness
        match async_io.wait(100) {
            Ok(events) => {
                for event in events {
                    // Find connection from token
                    let (conn_id, kind) = parse_token(event.token);
                    let conn = match connections.get_mut(&conn_id) {
                        Some(c) => c,
                        None => continue,
                    };

                    if event.error {
                        // Mark dead
                        conn.error_counter = u64::MAX;
                        continue;
                    }

                    // Handle reads
                    if event.readable {
                        match kind {
                            FdKind::Sctp => {
                                if let Err(e) = handle_sctp_read(conn, worker_id, &config) {
                                    if config.debug_level.unwrap_or(0) >= 1 {
                                        eprintln!(
                                            "[ERROR] Async Worker {} SCTP read error: {}",
                                            worker_id, e
                                        );
                                    }
                                    conn.error_counter = u64::MAX;
                                }
                            }
                            FdKind::Udp => {
                                if let Err(e) = handle_udp_read(conn, worker_id, &config) {
                                    if config.debug_level.unwrap_or(0) >= 1 {
                                        eprintln!(
                                            "[ERROR] Async Worker {} UDP read error: {}",
                                            worker_id, e
                                        );
                                    }
                                    conn.error_counter = u64::MAX;
                                }
                            }
                        }
                    }

                    // Handle SCTP writes
                    if event.writable {
                        if let FdKind::Sctp = kind {
                            if let Err(e) = conn.try_flush_out_queue() {
                                if config.debug_level.unwrap_or(0) >= 1 {
                                    eprintln!(
                                        "[ERROR] Async Worker {} SCTP write error: {}",
                                        worker_id, e
                                    );
                                }
                                conn.error_counter = u64::MAX;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Poll errors are not fatal
                if config.debug_level.unwrap_or(0) >= 2 {
                    println!("[INFO] Async Worker {} poll error: {}", worker_id, e);
                }
            }
        }

        // Drop unhealthy connections
        connections.retain(|_, conn| conn.error_counter < 10);
    }
}

/// Async SCTP read handler
fn handle_sctp_read(conn: &mut ConnectionState, worker_id: usize, config: &ServerConfig) -> io::Result<()> {
    loop {
        match conn.assoc.recv(&mut conn.sctp_recv_buf) {
            Ok((0, _)) => {
                // Peer closed
                conn.error_counter = u64::MAX;
                break;
            }
            Ok((n, _stream_id)) => {
                // Decrypt datagram
                if let Some(plain_len) = conn.crypto.decrypt(
                    conn.rx_counter,
                    &conn.sctp_recv_buf[..n],
                    &mut conn.plain_buf,
                ) {
                    conn.rx_counter = conn.rx_counter.wrapping_add(1);

                    // Require frame header
                    if plain_len < 3 {
                        conn.error_counter += 1;
                        conn.stats.increment_rx_errors();
                        continue;
                    }

                    // Parse frame
                    let (frame_type, _header_sid, payload) =
                        match decode_frame(&conn.plain_buf[..plain_len]) {
                            Ok(v) => v,
                            Err(e) => {
                                if config.debug_level.unwrap_or(0) >= 1 {
                                    eprintln!(
                                        "[ERROR] Async Worker {}: failed to decode frame header from {}: {}",
                                        worker_id, conn.client_addr, e
                                    );
                                }
                                conn.error_counter += 1;
                                conn.stats.increment_rx_errors();
                                continue;
                            }
                        };

                    match frame_type {
                        FrameType::Data => {
                            // Count RX payload
                            let payload_len = payload.len();
                            conn.stats.update_rx(payload_len);

                            // Optional debug sampling
                            conn.packet_counter += 1;
                            if config.debug_level.unwrap_or(0) >= 3
                                && conn.packet_counter % config.debug_frequency == 0
                            {
                                println!(
                                    "[INFO] Async Worker {}: {}:{} → Backend {}:{} ({} bytes)",
                                    worker_id,
                                    conn.client_addr,
                                    conn.local_port,
                                    conn.ax_backend.ip(),
                                    conn.ax_backend.port(),
                                    payload_len
                                );
                            }

                            // Forward to backend
                            if let Err(e) = conn.udp_socket.send_to(payload, conn.ax_backend) {
                                conn.error_counter += 1;
                                conn.stats.increment_rx_errors();
                                if config.debug_level.unwrap_or(0) >= 2 {
                                    eprintln!(
                                        "[ERROR] Async Worker {}: UDP send failed: {}",
                                        worker_id, e
                                    );
                                }
                            }
                        }
                        FrameType::Control => {
                            // Control plane decode
                            match decode_control(payload) {
                                Ok(ControlMessage::Hello { version, flags }) => {
                                    if config.debug_level.unwrap_or(0) >= 2 {
                                        println!(
                                            "[INFO] Async Worker {}: client HELLO from {}: version {}, flags 0x{:02X}",
                                            worker_id, conn.client_addr, version, flags
                                        );
                                    }
                                    if version != PROTOCOL_VERSION && config.debug_level.unwrap_or(0) >= 1 {
                                        eprintln!(
                                            "[WARN] Async Worker {}: protocol version mismatch: client={}, server={}",
                                            worker_id, version, PROTOCOL_VERSION
                                        );
                                    }
                                }
                                Ok(m) => {
                                    if config.debug_level.unwrap_or(0) >= 3 {
                                        println!(
                                            "[INFO] Async Worker {}: control frame from {}: {:?}",
                                            worker_id, conn.client_addr, m
                                        );
                                    }
                                }
                                Err(e) => {
                                    if config.debug_level.unwrap_or(0) >= 1 {
                                        eprintln!(
                                            "[WARN] Async Worker {}: malformed control frame from {}: {}",
                                            worker_id, conn.client_addr, e
                                        );
                                    }
                                    conn.error_counter += 1;
                                    conn.stats.increment_rx_errors();
                                }
                            }
                        }
                    }

                    // Reuse plaintext buffer
                    conn.plain_buf.clear();
                } else {
                    // Auth failure
                    conn.error_counter += 1;
                    conn.stats.increment_rx_errors();
                    if config.debug_level.unwrap_or(0) >= 2 {
                        eprintln!(
                            "[ERROR] Async Worker {}: Decryption error from {}",
                            worker_id, conn.client_addr
                        );
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => {
                // Propagate unexpected errors
                conn.error_counter += 1;
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Async UDP read handler
fn handle_udp_read(conn: &mut ConnectionState, worker_id: usize, config: &ServerConfig) -> io::Result<()> {
    loop {
        match conn.udp_socket.recv_from(&mut conn.udp_read_buf) {
            Ok((len, _src)) => {
                if len == 0 {
                    continue;
                }

                // Count TX payload
                conn.stats.update_tx(len);

                // Optional debug sampling
                conn.packet_counter += 1;
                if config.debug_level.unwrap_or(0) >= 3
                    && conn.packet_counter % config.debug_frequency == 0
                {
                    println!(
                        "[INFO] Async Worker {}: Backend → {} ({} bytes)",
                        worker_id, conn.client_addr, len
                    );
                }

                // Frame UDP payload
                encode_frame(
                    FrameType::Data,
                    STREAM_ID_DATA_DEFAULT,
                    &conn.udp_read_buf[..len],
                    &mut conn.frame_plain_buf,
                );

                // Encrypt framed payload
                let ct_len = conn.crypto.encrypt(
                    conn.tx_counter,
                    &conn.frame_plain_buf[..],
                    &mut conn.cipher_buf,
                );
                conn.tx_counter = conn.tx_counter.wrapping_add(1);

                // Enqueue to SCTP
                let msg = conn.cipher_buf[..ct_len].to_vec();
                conn.enqueue_message(STREAM_ID_DATA_DEFAULT, msg);

                // Best-effort flush
                if let Err(e) = conn.try_flush_out_queue() {
                    conn.error_counter += 1;
                    conn.stats.increment_tx_errors();
                    return Err(e);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => {
                // Count and log UDP errors
                conn.error_counter += 1;
                conn.stats.increment_tx_errors();
                if config.debug_level.unwrap_or(0) >= 2 {
                    eprintln!("[INFO] Async Worker {}: UDP recv error: {}", worker_id, e);
                }
                break;
            }
        }
    }

    Ok(())
}

// ---- SYNC обработчики ----

/// Sync path SCTP -> UDP forwarder
fn process_sctp_to_udp(
    assoc: SctpAssociation,
    crypto: TunnelCrypto,
    udp_socket: UdpSocket,
    ax_backend: SocketAddr,
    client_addr: String,
    local_port: u16,
    stats: Arc<TrafficStats>,
    debug_level: Option<u8>,
    debug_frequency: u64,
    worker_id: usize,
) {
    // Buffers and counters
    let mut ct_buf = vec![0u8; MAX_PACKET_SIZE + 32];
    let mut plain_buf = Vec::with_capacity(MAX_PACKET_SIZE + 32);
    let mut packet_counter = 0u64;
    let mut error_counter = 0u64;
    let mut rx_counter: u64 = 0;

    loop {
        match assoc.recv(&mut ct_buf) {
            Ok((0, _)) => {
                // Client disconnected
                if debug_level.unwrap_or(0) >= 1 {
                    println!("[INFO] Worker {}: Client {} disconnected", worker_id, client_addr);
                }
                break;
            }
            Ok((n, _stream_id)) => {
                // Decrypt datagram
                if let Some(plain_len) = crypto.decrypt(rx_counter, &ct_buf[..n], &mut plain_buf) {
                    rx_counter = rx_counter.wrapping_add(1);

                    // Require header
                    if plain_len < 3 {
                        stats.increment_rx_errors();
                        error_counter += 1;
                        if error_counter > 10 {
                            break;
                        }
                        continue;
                    }

                    // Parse frame
                    let (frame_type, _header_sid, payload) =
                        match decode_frame(&plain_buf[..plain_len]) {
                            Ok(v) => v,
                            Err(e) => {
                                if debug_level.unwrap_or(0) >= 1 {
                                    eprintln!(
                                        "[ERROR] Worker {}: failed to decode frame header from {}: {}",
                                        worker_id, client_addr, e
                                    );
                                }
                                stats.increment_rx_errors();
                                error_counter += 1;
                                if error_counter > 10 {
                                    break;
                                }
                                continue;
                            }
                        };

                    match frame_type {
                        FrameType::Data => {
                            // Count RX payload
                            let payload_len = payload.len();
                            stats.update_rx(payload_len);

                            // Optional debug sampling
                            packet_counter += 1;
                            if debug_level.unwrap_or(0) >= 3 && packet_counter % debug_frequency == 0 {
                                println!(
                                    "[INFO] Worker {}: {}:{} → Backend {}:{} ({} bytes, packet {})",
                                    worker_id,
                                    client_addr,
                                    local_port,
                                    ax_backend.ip(),
                                    ax_backend.port(),
                                    payload_len,
                                    packet_counter
                                );
                            }

                            // Forward to backend
                            if let Err(e) = udp_socket.send_to(payload, ax_backend) {
                                if debug_level.unwrap_or(0) >= 2 {
                                    eprintln!("[ERROR] Worker {}: UDP send failed: {}", worker_id, e);
                                }
                                stats.increment_rx_errors();
                                error_counter += 1;
                                if error_counter > 100 {
                                    break;
                                }
                            }
                        }
                        FrameType::Control => {
                            // Control decode
                            match decode_control(payload) {
                                Ok(ControlMessage::Hello { version, flags }) => {
                                    if debug_level.unwrap_or(0) >= 2 {
                                        println!(
                                            "[INFO] Worker {}: client HELLO from {}: version {}, flags 0x{:02X}",
                                            worker_id, client_addr, version, flags
                                        );
                                    }
                                    if version != PROTOCOL_VERSION && debug_level.unwrap_or(0) >= 1 {
                                        eprintln!(
                                            "[WARN] Worker {}: protocol version mismatch: client={}, server={}",
                                            worker_id, version, PROTOCOL_VERSION
                                        );
                                    }
                                }
                                Ok(m) => {
                                    if debug_level.unwrap_or(0) >= 3 {
                                        println!(
                                            "[INFO] Worker {}: control frame from {}: {:?}",
                                            worker_id, client_addr, m
                                        );
                                    }
                                }
                                Err(e) => {
                                    if debug_level.unwrap_or(0) >= 1 {
                                        eprintln!(
                                            "[WARN] Worker {}: malformed control frame from {}: {}",
                                            worker_id, client_addr, e
                                        );
                                    }
                                    stats.increment_rx_errors();
                                    error_counter += 1;
                                    if error_counter > 10 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Auth failure
                    if debug_level.unwrap_or(0) >= 2 {
                        eprintln!("[ERROR] Worker {}: Decryption error from {}", worker_id, client_addr);
                    }
                    stats.increment_rx_errors();
                    error_counter += 1;
                    if error_counter > 10 {
                        break;
                    }
                }
            }
            Err(e) => {
                // Receive error
                if debug_level.unwrap_or(0) >= 1 {
                    eprintln!("[ERROR] Worker {}: SCTP recv error: {}", worker_id, e);
                }
                stats.increment_rx_errors();
                break;
            }
        }
    }
}

/// Sync path UDP -> SCTP forwarder
fn process_udp_to_sctp(
    assoc: SctpAssociation,
    crypto: TunnelCrypto,
    udp_socket: UdpSocket,
    client_addr: String,
    stats: Arc<TrafficStats>,
    debug_level: Option<u8>,
    debug_frequency: u64,
    worker_id: usize,
    nonblocking: bool,
) {
    // Buffers and counters
    let mut udp_payload_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut frame_plain_buf = Vec::with_capacity(MAX_PACKET_SIZE + 32);
    let mut control_payload = Vec::with_capacity(32);
    let mut ciphertext_buf = Vec::with_capacity(MAX_PACKET_SIZE + 32);
    let mut packet_counter = 0u64;
    let mut error_counter = 0u64;
    let mut tx_counter: u64 = 0;

    // Server HELLO on control stream
    {
        let flags = if crypto.is_aes256() { 0x01 } else { 0x00 };
        let hello = ControlMessage::Hello {
            version: PROTOCOL_VERSION,
            flags,
        };
        encode_control(&hello, &mut control_payload);
        encode_frame(
            FrameType::Control,
            STREAM_ID_CONTROL,
            &control_payload,
            &mut frame_plain_buf,
        );

        let ct_len = crypto.encrypt(tx_counter, &frame_plain_buf[..], &mut ciphertext_buf);
        tx_counter = tx_counter.wrapping_add(1);

        if let Err(e) = assoc.send(STREAM_ID_CONTROL, &ciphertext_buf[..ct_len]) {
            if debug_level.unwrap_or(0) >= 1 {
                eprintln!(
                    "[ERROR] Worker {}: failed to send server HELLO to {}: {}",
                    worker_id, client_addr, e
                );
            }
            stats.increment_tx_errors();
            return;
        }
    }

    loop {
        match udp_socket.recv(&mut udp_payload_buf) {
            Ok(len) => {
                if len == 0 {
                    if debug_level.unwrap_or(0) >= 2 {
                        println!("[INFO] Worker {}: UDP received 0 bytes", worker_id);
                    }
                    continue;
                }

                // Count TX payload
                stats.update_tx(len);

                // Optional debug sampling
                packet_counter += 1;
                if debug_level.unwrap_or(0) >= 3 && packet_counter % debug_frequency == 0 {
                    println!(
                        "[INFO] Worker {}: Backend → {} ({} bytes, packet {})",
                        worker_id, client_addr, len, packet_counter
                    );
                }

                // Frame UDP payload
                encode_frame(
                    FrameType::Data,
                    STREAM_ID_DATA_DEFAULT,
                    &udp_payload_buf[..len],
                    &mut frame_plain_buf,
                );

                // Encrypt framed payload
                let ct_len = crypto.encrypt(tx_counter, &frame_plain_buf[..], &mut ciphertext_buf);
                tx_counter = tx_counter.wrapping_add(1);

                // Send over SCTP
                if let Err(e) = assoc.send(STREAM_ID_DATA_DEFAULT, &ciphertext_buf[..ct_len]) {
                    if debug_level.unwrap_or(0) >= 2 {
                        eprintln!(
                            "[ERROR] Worker {}: SCTP send failed to {}: {}",
                            worker_id, client_addr, e
                        );
                    }
                    stats.increment_tx_errors();
                    error_counter += 1;
                    if error_counter > 10 {
                        break;
                    }

                    // Nonblocking backoff
                    if nonblocking {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    } else {
                        break;
                    }
                }
            }
            Err(e) => {
                // UDP recv error
                if debug_level.unwrap_or(0) >= 2 {
                    eprintln!("[INFO] Worker {}: UDP recv error: {}", worker_id, e);
                }
                stats.increment_tx_errors();
                error_counter += 1;
                if error_counter > 10 {
                    break;
                }

                // Nonblocking backoff
                if nonblocking {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                } else {
                    break;
                }
            }
        }
    }
}