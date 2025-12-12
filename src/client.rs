// Client side UDP capture + SCTP tunnel with sync and async modes
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
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

/// Client runtime configuration
#[derive(Clone)]
pub struct ClientConfig {
    pub local_port: SocketAddr,
    pub server_sctp: SocketAddr,
    pub udp_buffer_size: usize,
    pub debug_level: Option<u8>,
    pub debug_frequency: u64,
    pub stats_interval: u64,
    pub table_width: usize,
    pub batch_enabled: bool,
    pub batch_size: usize,
    pub nonblocking: bool, // используется только для UDP в sync-режиме
    pub zero_copy: bool,
    pub use_async_io: bool,
}

/// Shared client state across threads
pub struct ClientState {
    // Last UDP source for return path
    pub last_ax_src: Arc<Mutex<Option<SocketAddr>>>,
    // Shared traffic stats
    pub stats: Arc<TrafficStats>,
    // Optional batch accumulator
    pub batch_buffer: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ClientState {
    /// Create shared client state
    pub fn new() -> Self {
        Self {
            last_ax_src: Arc::new(Mutex::new(None)),
            stats: Arc::new(TrafficStats::new()),
            batch_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }
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

/// Main client entrypoint
pub fn run_client(config: ClientConfig, crypto: TunnelCrypto) {
    // UDP nonblocking depends on mode and flag
    let udp_nonblocking = config.nonblocking || config.use_async_io;

    // Shared socket options template
    let socket_config = network::SocketConfig {
        send_buffer_size: config.udp_buffer_size,
        recv_buffer_size: config.udp_buffer_size,
        nonblocking: udp_nonblocking,
        zero_copy: config.zero_copy,
        ..Default::default()
    };

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
        table::TableRow::simple("UDP Local on", &config.local_port.to_string()),
        table::TableRow::simple("SCTP Endpoint", &config.server_sctp.to_string()),
        table::TableRow::new(
            "UDP Buffer",
            format!("{:>6} MB", config.udp_buffer_size / 1024 / 1024),
        ),
        table::TableRow::new(
            "Batch Mode",
            format!("{:>6}", if config.batch_enabled { "Yes" } else { "No" }),
        ),
        table::TableRow::new("Batch Size", format!("{:>6}", config.batch_size)),
        table::TableRow::new(
            "Non-blocking",
            format!(
                "{:>6}",
                if udp_nonblocking || (config.use_async_io && async_supported) {
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
        table::create_table("Fuscen Connect 13 with Async I/O", info_rows, config.table_width)
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

    // Bind UDP socket
    let udp_socket = network::create_udp_socket(config.local_port, &socket_config).unwrap_or_else(
        |_| UdpSocket::bind(config.local_port).expect("[FATAL] bind UDP socket"),
    );

    // Best-effort buffer tuning
    network::optimize_socket_buffers(&udp_socket).ok();

    // Create shared state
    let client_state = ClientState::new();

    // Stats printing thread
    {
        let stats_display = client_state.stats.clone();
        let stats_interval = config.stats_interval;
        let table_width = config.table_width;
        let crypto_stats = crypto.clone();
        let debug_level = config.debug_level;
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(stats_interval));
            stats_display.print_stats("STATISTICS - Connect", stats_interval, table_width);

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

    // Choose async vs sync implementation
    if config.use_async_io && async_supported {
        run_client_async(config, crypto, udp_socket, client_state);
    } else {
        run_client_sync(config, crypto, udp_socket, client_state);
    }
}

// ---------------- SYNC client ----------------

/// Blocking client with reconnect loop
fn run_client_sync(config: ClientConfig, crypto: TunnelCrypto, udp_socket: UdpSocket, client_state: ClientState) {
    let mut reconnect_attempt = 0;

    loop {
        // Blocking connect for sync mode
        match network::create_sctp_client(
            config.server_sctp,
            &network::SocketConfig {
                send_buffer_size: config.udp_buffer_size,
                recv_buffer_size: config.udp_buffer_size,
                nonblocking: false,
                zero_copy: config.zero_copy,
                ..Default::default()
            },
        ) {
            Ok(sctp_sock) => {
                reconnect_attempt = 0;

                // Connect log
                if config.debug_level.unwrap_or(0) >= 1 {
                    println!(
                        "[✓] Tunnel Established! Endpoint {}:{}",
                        config.server_sctp.ip(),
                        config.server_sctp.port()
                    );
                }

                // Reset crypto perf counters
                let crypto = crypto.clone();
                crypto.reset_counters();

                // Run until broken
                handle_connection_sync(sctp_sock, crypto, &udp_socket, &client_state, &config);

                // Reconnect notice
                if config.debug_level.unwrap_or(0) >= 1 {
                    println!("[INFO] Tunnel broken — reconnecting in 3 seconds...");
                }
            }
            Err(e) => {
                reconnect_attempt += 1;
                let delay = std::cmp::min(reconnect_attempt * 2, 30);

                // Backoff log
                if config.debug_level.unwrap_or(0) >= 1 {
                    eprintln!(
                        "[ERROR] Connection failed (attempt {}): {} — waiting {} seconds",
                        reconnect_attempt, e, delay
                    );
                }
                thread::sleep(Duration::from_secs(delay as u64));
            }
        }

        // Extra reconnect delay
        thread::sleep(Duration::from_secs(3));
    }
}

/// Handle one connected SCTP session in sync mode
fn handle_connection_sync(
    sctp_sock: Socket,
    crypto: TunnelCrypto,
    udp_socket: &UdpSocket,
    client_state: &ClientState,
    config: &ClientConfig,
) {
    // Split SCTP into RX and TX handles
    let sctp_rx = SctpAssociation::new(
        sctp_sock
            .try_clone()
            .expect("[FATAL] Failed to clone SCTP socket for RX"),
    );
    let sctp_tx = SctpAssociation::new(sctp_sock);

    // Clone UDP for threads
    let udp_for_sctp = udp_socket
        .try_clone()
        .expect("[ERROR] Clone UDP for SCTP Thread");
    let udp_for_udp = udp_socket
        .try_clone()
        .expect("[ERROR] Clone UDP for UDP Thread");

    // Share destination memory
    let last_ax_src = client_state.last_ax_src.clone();

    // Share stats
    let stats_rx = client_state.stats.clone();
    let stats_tx = client_state.stats.clone();

    // Share batch buffer
    let batch_buffer = client_state.batch_buffer.clone();

    let server_sctp = config.server_sctp;
    let crypto_rx = crypto.clone();
    let debug_level = config.debug_level;
    let debug_frequency = config.debug_frequency;

    // RX thread SCTP -> UDP
    thread::spawn(move || {
        process_client_sctp_to_udp_sync(
            sctp_rx,
            crypto_rx,
            udp_for_sctp,
            last_ax_src,
            server_sctp,
            stats_rx,
            debug_level,
            debug_frequency,
        );
    });

    // TX loop UDP -> SCTP
    let mut udp_payload_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut frame_plain_buf = Vec::with_capacity(MAX_PACKET_SIZE + 32);
    let mut control_payload = Vec::with_capacity(32);
    let mut ciphertext_buf = Vec::with_capacity(MAX_PACKET_SIZE + 32);
    let mut packet_counter = 0u64;
    let mut batch_counter = 0usize;
    let mut tx_counter: u64 = 0;

    // Client HELLO on control stream
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

        if let Err(e) = sctp_tx.send(STREAM_ID_CONTROL, &ciphertext_buf[..ct_len]) {
            eprintln!("[ERROR] Failed to send ClientHello: {}", e);
            return;
        }
    }

    loop {
        match udp_for_udp.recv_from(&mut udp_payload_buf) {
            Ok((len, src)) => {
                if len == 0 {
                    continue;
                }

                // Remember return address
                *client_state.last_ax_src.lock().unwrap() = Some(src);

                // Count TX payload
                stats_tx.update_tx(len);

                // Optional debug sampling
                packet_counter += 1;
                if config.debug_level.unwrap_or(0) >= 3
                    && packet_counter % config.debug_frequency == 0
                {
                    println!(
                        "[INFO] TX {} bytes from {}:{} → Server {}:{} (packet {})",
                        len,
                        src.ip(),
                        src.port(),
                        config.server_sctp.ip(),
                        config.server_sctp.port(),
                        packet_counter
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

                if config.batch_enabled {
                    // Append to batch
                    let mut batch = batch_buffer.lock().unwrap();
                    batch.push(ciphertext_buf[..ct_len].to_vec());
                    batch_counter += 1;

                    // Flush when full
                    if batch_counter >= config.batch_size {
                        for msg in batch.iter() {
                            if let Err(e) = sctp_tx.send(STREAM_ID_DATA_DEFAULT, msg) {
                                eprintln!("[ERROR] SCTP batch send failed: {}", e);
                                return;
                            }
                        }
                        batch.clear();
                        batch_counter = 0;
                    }
                } else if let Err(e) = sctp_tx.send(STREAM_ID_DATA_DEFAULT, &ciphertext_buf[..ct_len]) {
                    // Stop on SCTP send error
                    if config.debug_level.unwrap_or(0) >= 1 {
                        eprintln!("[ERROR] SCTP send error: {}", e);
                    }
                    break;
                }
            }
            Err(e) => {
                // UDP recv error
                if config.debug_level.unwrap_or(0) >= 2 {
                    println!("[INFO] UDP recv error: {}", e);
                }

                // Nonblocking backoff
                if config.nonblocking {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    // Flush leftover batch on exit
    if config.batch_enabled && batch_counter > 0 {
        let batch = batch_buffer.lock().unwrap();
        for msg in batch.iter() {
            let _ = sctp_tx.send(STREAM_ID_DATA_DEFAULT, msg);
        }
    }
}

/// RX thread SCTP -> UDP for sync mode
fn process_client_sctp_to_udp_sync(
    assoc: SctpAssociation,
    crypto: TunnelCrypto,
    udp_socket: UdpSocket,
    last_ax_src: Arc<Mutex<Option<SocketAddr>>>,
    server_sctp: SocketAddr,
    stats: Arc<TrafficStats>,
    debug_level: Option<u8>,
    debug_frequency: u64,
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
                // Server closed
                if debug_level.unwrap_or(0) >= 1 {
                    println!("[INFO] Server closed SCTP association");
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
                                    eprintln!("[ERROR] Client: failed to decode frame header: {}", e);
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
                                    "[INFO] RX {} bytes from Server {}:{} (packet {})",
                                    payload_len,
                                    server_sctp.ip(),
                                    server_sctp.port(),
                                    packet_counter
                                );
                            }

                            // Send back to last UDP source
                            let ax_addr = last_ax_src.lock().unwrap();
                            if let Some(addr) = *ax_addr {
                                if let Err(e) = udp_socket.send_to(payload, addr) {
                                    if debug_level.unwrap_or(0) >= 2 {
                                        eprintln!("[WARN] UDP send failed: {}", e);
                                    }
                                    stats.increment_rx_errors();
                                    error_counter += 1;
                                }
                            } else if debug_level.unwrap_or(0) >= 2 {
                                // Unknown destination until first TX
                                println!("[WARN] Destination address not known yet");
                            }
                        }
                        FrameType::Control => {
                            // Control plane decode
                            match decode_control(payload) {
                                Ok(ControlMessage::Hello { version, flags }) => {
                                    if debug_level.unwrap_or(0) >= 2 {
                                        println!(
                                            "[INFO] Client: server HELLO: version {}, flags 0x{:02X}",
                                            version, flags
                                        );
                                    }
                                }
                                Ok(m) => {
                                    if debug_level.unwrap_or(0) >= 3 {
                                        println!("[INFO] Client: control frame from server: {:?}", m);
                                    }
                                }
                                Err(e) => {
                                    if debug_level.unwrap_or(0) >= 1 {
                                        eprintln!("[WARN] Client: malformed control frame: {}", e);
                                    }
                                    stats.increment_rx_errors();
                                    error_counter += 1;
                                }
                            }
                        }
                    }

                    // Exit on too many errors
                    if error_counter > 10 {
                        break;
                    }
                } else {
                    // Auth failure
                    if debug_level.unwrap_or(0) >= 1 {
                        eprintln!("[ERROR] Decryption error from server");
                    }
                    stats.increment_rx_errors();
                    error_counter += 1;
                    if error_counter > 10 {
                        break;
                    }
                }
            }
            Err(e) => {
                // SCTP recv error
                if debug_level.unwrap_or(0) >= 1 {
                    eprintln!("[ERROR] SCTP recv error: {}", e);
                }
                stats.increment_rx_errors();
                break;
            }
        }
    }
}

// ---------------- ASYNC client ----------------

use std::collections::VecDeque;

/// Async client connection state
struct AsyncClientConnection {
    // Token id used by poller
    conn_id: u32,

    // I/O endpoints
    assoc: SctpAssociation,
    udp_socket: UdpSocket,

    // Crypto context
    crypto: TunnelCrypto,

    // Server address for logs
    server_sctp: SocketAddr,

    // Last UDP source for return path
    last_ax_src: Arc<Mutex<Option<SocketAddr>>>,

    // Shared stats
    stats: Arc<TrafficStats>,

    // Shared batch buffer
    batch_buffer: Arc<Mutex<Vec<Vec<u8>>>>,

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

    // Copy of config for logs and behavior
    config: ClientConfig,
}

impl AsyncClientConnection {
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
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Send client HELLO on control stream
    fn send_client_hello(&mut self) {
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

/// Async client loop with reconnect
fn run_client_async(config: ClientConfig, crypto: TunnelCrypto, udp_socket: UdpSocket, client_state: ClientState) {
    let mut reconnect_attempt = 0;

    loop {
        // Create poller per session
        match AsyncIO::new() {
            Ok(async_io) => {
                // Nonblocking connect for async mode
                match network::create_sctp_client(
                    config.server_sctp,
                    &network::SocketConfig {
                        send_buffer_size: config.udp_buffer_size,
                        recv_buffer_size: config.udp_buffer_size,
                        nonblocking: true,
                        zero_copy: config.zero_copy,
                        ..Default::default()
                    },
                ) {
                    Ok(sctp_sock) => {
                        reconnect_attempt = 0;

                        // Connect log
                        if config.debug_level.unwrap_or(0) >= 1 {
                            println!(
                                "[✓] Async Tunnel Established! Endpoint {}:{}",
                                config.server_sctp.ip(),
                                config.server_sctp.port()
                            );
                        }

                        // Reset crypto perf counters
                        let crypto = crypto.clone();
                        crypto.reset_counters();

                        // Clone UDP for async ownership
                        let udp = udp_socket.try_clone().expect("[ERROR] Failed to clone UDP socket");

                        // Build connection state
                        let mut client_conn = AsyncClientConnection {
                            conn_id: 1,
                            assoc: SctpAssociation::new(sctp_sock),
                            udp_socket: udp,
                            crypto,
                            server_sctp: config.server_sctp,
                            last_ax_src: client_state.last_ax_src.clone(),
                            stats: client_state.stats.clone(),
                            batch_buffer: client_state.batch_buffer.clone(),

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
                            config: config.clone(),
                        };

                        // Initial HELLO
                        client_conn.send_client_hello();

                        // Register fds in poller
                        let sctp_fd = client_conn.assoc.as_raw_fd();
                        let udp_fd = client_conn.udp_socket.as_raw_fd();

                        let sctp_token = make_token(client_conn.conn_id, FdKind::Sctp);
                        let udp_token = make_token(client_conn.conn_id, FdKind::Udp);

                        if let Err(e) = async_io.add_fd(sctp_fd, sctp_token, true, true) {
                            eprintln!("[ERROR] Failed to add SCTP to async I/O: {}", e);
                            thread::sleep(Duration::from_secs(3));
                            continue;
                        }

                        if let Err(e) = async_io.add_fd(udp_fd, udp_token, true, false) {
                            eprintln!("[ERROR] Failed to add UDP to async I/O: {}", e);
                            thread::sleep(Duration::from_secs(3));
                            continue;
                        }

                        // Main poll loop
                        'outer: while client_conn.error_counter < 10 {
                            match async_io.wait(100) {
                                Ok(events) => {
                                    for event in events {
                                        // Filter by conn id
                                        let (conn_id, kind) = parse_token(event.token);
                                        if conn_id != client_conn.conn_id {
                                            continue;
                                        }

                                        if event.error {
                                            // Error event from poller
                                            if client_conn.config.debug_level.unwrap_or(0) >= 1 {
                                                println!("[ERROR] Async I/O error event");
                                            }
                                            client_conn.error_counter = u64::MAX;
                                            break 'outer;
                                        }

                                        // Handle reads
                                        if event.readable {
                                            match kind {
                                                FdKind::Sctp => {
                                                    if let Err(e) = handle_async_client_sctp_read(&mut client_conn) {
                                                        if client_conn.config.debug_level.unwrap_or(0) >= 1 {
                                                            println!("[ERROR] Async SCTP read error: {}", e);
                                                        }
                                                        client_conn.error_counter = u64::MAX;
                                                        break 'outer;
                                                    }
                                                }
                                                FdKind::Udp => {
                                                    if let Err(e) = handle_async_client_udp_read(&mut client_conn) {
                                                        if client_conn.config.debug_level.unwrap_or(0) >= 1 {
                                                            println!("[ERROR] Async UDP read error: {}", e);
                                                        }
                                                        client_conn.error_counter = u64::MAX;
                                                        break 'outer;
                                                    }
                                                }
                                            }
                                        }

                                        // Handle SCTP writes
                                        if event.writable {
                                            if let FdKind::Sctp = kind {
                                                if let Err(e) = client_conn.try_flush_out_queue() {
                                                    if client_conn.config.debug_level.unwrap_or(0) >= 1 {
                                                        println!("[ERROR] Async SCTP write error: {}", e);
                                                    }
                                                    client_conn.error_counter = u64::MAX;
                                                    break 'outer;
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Poll error
                                    if client_conn.config.debug_level.unwrap_or(0) >= 2 {
                                        println!("[INFO] Async client poll error: {}", e);
                                    }
                                    break 'outer;
                                }
                            }

                            // Batch flush hook
                            if client_conn.config.batch_enabled {
                                handle_async_batch_write(&mut client_conn);
                            }

                            // Optional micro backoff
                            if client_conn.config.nonblocking {
                                thread::sleep(Duration::from_micros(100));
                            }
                        }

                        // Reconnect notice
                        if client_conn.config.debug_level.unwrap_or(0) >= 1 {
                            println!("[INFO] Async tunnel broken — reconnecting...");
                        }

                        // Cleanup registrations
                        let _ = async_io.remove_fd(sctp_fd);
                        let _ = async_io.remove_fd(udp_fd);
                    }
                    Err(e) => {
                        // Connect backoff
                        reconnect_attempt += 1;
                        let delay = std::cmp::min(reconnect_attempt * 2, 30);

                        if config.debug_level.unwrap_or(0) >= 1 {
                            eprintln!(
                                "[ERROR] Async connection failed (attempt {}): {} — waiting {} seconds",
                                reconnect_attempt, e, delay
                            );
                        }
                        thread::sleep(Duration::from_secs(delay as u64));
                        continue;
                    }
                }
            }
            Err(e) => {
                // Poller creation failure
                eprintln!("[ERROR] Failed to create async I/O: {}", e);
                thread::sleep(Duration::from_secs(3));
                continue;
            }
        }

        // Extra reconnect delay
        thread::sleep(Duration::from_secs(3));
    }
}

/// Async SCTP read handler
fn handle_async_client_sctp_read(conn: &mut AsyncClientConnection) -> io::Result<()> {
    use std::io::ErrorKind;

    loop {
        match conn.assoc.recv(&mut conn.sctp_recv_buf) {
            Ok((0, _)) => {
                // Server closed
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

                    // Require header
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
                                if conn.config.debug_level.unwrap_or(0) >= 1 {
                                    println!(
                                        "[ERROR] Async Client: failed to decode frame header: {}",
                                        e
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
                            if conn.config.debug_level.unwrap_or(0) >= 3
                                && conn.packet_counter % conn.config.debug_frequency == 0
                            {
                                println!(
                                    "[INFO] Async Client: RX {} bytes from Server {}:{} (packet {})",
                                    payload_len,
                                    conn.server_sctp.ip(),
                                    conn.server_sctp.port(),
                                    conn.packet_counter
                                );
                            }

                            // Send back to last UDP source
                            let ax_addr = conn.last_ax_src.lock().unwrap();
                            if let Some(addr) = *ax_addr {
                                if let Err(e) = conn.udp_socket.send_to(payload, addr) {
                                    if conn.config.debug_level.unwrap_or(0) >= 2 {
                                        println!("[WARN] UDP send failed: {}", e);
                                    }
                                    conn.error_counter += 1;
                                    conn.stats.increment_rx_errors();
                                }
                            } else if conn.config.debug_level.unwrap_or(0) >= 2 {
                                // Unknown destination until first TX
                                println!("[WARN] Destination address not known yet, dropping packet");
                            }
                        }
                        FrameType::Control => {
                            // Control plane decode
                            match decode_control(payload) {
                                Ok(ControlMessage::Hello { version, flags }) => {
                                    if conn.config.debug_level.unwrap_or(0) >= 2 {
                                        println!(
                                            "[INFO] Async Client: server HELLO: version {}, flags 0x{:02X}",
                                            version, flags
                                        );
                                    }
                                }
                                Ok(m) => {
                                    if conn.config.debug_level.unwrap_or(0) >= 3 {
                                        println!(
                                            "[INFO] Async Client: control frame from server: {:?}",
                                            m
                                        );
                                    }
                                }
                                Err(e) => {
                                    if conn.config.debug_level.unwrap_or(0) >= 1 {
                                        println!(
                                            "[WARN] Async Client: malformed control frame: {}",
                                            e
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
                    if conn.config.debug_level.unwrap_or(0) >= 1 {
                        println!("[ERROR] Decryption error from server");
                    }
                    conn.error_counter += 1;
                    conn.stats.increment_rx_errors();
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
fn handle_async_client_udp_read(conn: &mut AsyncClientConnection) -> io::Result<()> {
    use std::io::ErrorKind;

    loop {
        match conn.udp_socket.recv_from(&mut conn.udp_read_buf) {
            Ok((len, src)) => {
                if len == 0 {
                    continue;
                }

                // Remember return address
                *conn.last_ax_src.lock().unwrap() = Some(src);

                // Count TX payload
                conn.stats.update_tx(len);

                // Optional debug sampling
                conn.packet_counter += 1;
                if conn.config.debug_level.unwrap_or(0) >= 3
                    && conn.packet_counter % conn.config.debug_frequency == 0
                {
                    println!(
                        "[INFO] Async Client: TX {} bytes from {}:{} → Server {}:{} (packet {})",
                        len,
                        src.ip(),
                        src.port(),
                        conn.server_sctp.ip(),
                        conn.server_sctp.port(),
                        conn.packet_counter
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

                let msg = conn.cipher_buf[..ct_len].to_vec();

                if conn.config.batch_enabled {
                    // Append to batch buffer
                    let mut batch = conn.batch_buffer.lock().unwrap();
                    batch.push(msg);
                } else {
                    // Enqueue to SCTP
                    conn.enqueue_message(STREAM_ID_DATA_DEFAULT, msg);
                    if let Err(e) = conn.try_flush_out_queue() {
                        conn.error_counter += 1;
                        conn.stats.increment_tx_errors();
                        return Err(e);
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => {
                // UDP recv error
                if conn.config.debug_level.unwrap_or(0) >= 2 {
                    println!("[INFO] UDP recv error: {}", e);
                }
                conn.error_counter += 1;
                conn.stats.increment_tx_errors();
                break;
            }
        }
    }

    Ok(())
}

/// Flush batched messages into SCTP queue
fn handle_async_batch_write(conn: &mut AsyncClientConnection) {
    // Drain batch buffer without holding lock
    let mut batch_vec = {
        let mut guard = conn.batch_buffer.lock().unwrap();
        std::mem::take(&mut *guard)
    };

    if batch_vec.is_empty() {
        return;
    }

    // Enqueue drained messages
    for msg in batch_vec.drain(..) {
        conn.enqueue_message(STREAM_ID_DATA_DEFAULT, msg);
    }

    // Best-effort flush
    if let Err(e) = conn.try_flush_out_queue() {
        if conn.config.debug_level.unwrap_or(0) >= 1 {
            println!("[ERROR] Async batch write failed: {}", e);
        }
        conn.error_counter += 1;
        conn.stats.increment_tx_errors();
    }
}