// src/main.rs — fuscen 12 — Fast UDP-over-SCTP Encapsulation and Encryption
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use aes_gcm::aead::generic_array::typenum::U12;
use clap::{Parser, Subcommand};
use sha2::Digest;
use socket2::{Domain, Protocol, Socket, Type};

type Nonce12 = Nonce<U12>;
const IPPROTO_SCTP: i32 = 132;

// ====================== TABLE MODULE ======================

mod table {
    use std::cmp::max;
    use unicode_width::UnicodeWidthStr;
    
    /// Table row: label and value
    #[derive(Clone)]
    pub struct TableRow {
        pub label: String,
        pub value: String,
    }
    
    impl TableRow {
        pub fn new(label: &str, value: String) -> Self {
            Self {
                label: label.to_string(),
                value,
            }
        }
        
        pub fn simple(label: &str, value: &str) -> Self {
            Self {
                label: label.to_string(),
                value: value.to_string(),
            }
        }
    }
    
    /// Calculate visual width of string considering Unicode
    fn visual_width(s: &str) -> usize {
        UnicodeWidthStr::width(s)
    }
    
    /// Create adaptive table with proper Unicode support
    pub fn create_table(title: &str, rows: Vec<TableRow>, min_width: usize) -> String {
        // Calculate maximum visual width
        let mut max_len = min_width;
        max_len = max(max_len, visual_width(title) + 4);
        
        for row in &rows {
            let row_len = visual_width(&format!("{}: {}", row.label, row.value)) + 4;
            max_len = max(max_len, row_len);
        }
        
        // Add margin
        max_len += 2;
        
        let mut result = String::new();
        
        // Top border
        result.push_str(&format!("╔{}╗\n", "═".repeat(max_len - 2)));
        
        // Header - center considering visual width
        let title_width = visual_width(title);
        let title_padding = max_len - title_width - 4;
        let title_left = title_padding / 2;
        let title_right = title_padding - title_left;
        result.push_str(&format!("║ {}{}{} ║\n", 
            " ".repeat(title_left), title, " ".repeat(title_right)));
        
        // Separator
        result.push_str(&format!("╠{}╣\n", "═".repeat(max_len - 2)));
        
        // Rows
        for (i, row) in rows.iter().enumerate() {
            let row_text = format!("{}: {}", row.label, row.value);
            let row_width = visual_width(&row_text);
            let row_padding = max_len - row_width - 4;
            let row_left = 1;
            let row_right = row_padding - row_left;
            result.push_str(&format!("║ {}{}{} ║\n", 
                row_text, " ".repeat(row_right), " ".repeat(row_left)));
            
            // Separator between groups
            if i == rows.len() / 2 - 1 && rows.len() > 4 {
                result.push_str(&format!("╠{}╣\n", "─".repeat(max_len - 2)));
            }
        }
        
        // Bottom border
        result.push_str(&format!("╚{}╝", "═".repeat(max_len - 2)));
        
        result
    }
    
    /// Format statistics into a table
    pub fn create_stats_table(
        title: &str,
        interval_secs: u64,
        rx_bytes: u64,
        tx_bytes: u64,
        rx_packets: u64,
        tx_packets: u64,
        elapsed_secs: f64,
        min_width: usize,
    ) -> String {
        // Calculate metrics
        let rx_mbps = (rx_bytes as f64 * 8.0 / elapsed_secs) / 1_000_000.0;
        let tx_mbps = (tx_bytes as f64 * 8.0 / elapsed_secs) / 1_000_000.0;
        let rx_pps = rx_packets as f64 / elapsed_secs;
        let tx_pps = tx_packets as f64 / elapsed_secs;
        let rx_mb = rx_bytes as f64 / 1024.0 / 1024.0;
        let tx_mb = tx_bytes as f64 / 1024.0 / 1024.0;
        
        let mut rows = Vec::new();
        
        // Reception
        rows.push(TableRow::simple("📥 Recieved - RX", ""));
        rows.push(TableRow::new("  Speed", format!("{:7.2} Mbps", rx_mbps)));
        rows.push(TableRow::new("  Packets", format!("{:7} ({:.0}/s)", rx_packets, rx_pps)));
        rows.push(TableRow::new("  Data", format!("{:7.2} MB", rx_mb)));
        
        // Transmission
        rows.push(TableRow::simple("📤 transmitted - TX", ""));
        rows.push(TableRow::new("  Speed", format!("{:7.2} Mbps", tx_mbps)));
        rows.push(TableRow::new("  Packets", format!("{:7} ({:.0}/s)", tx_packets, tx_pps)));
        rows.push(TableRow::new("  Data", format!("{:7.2} MB", tx_mb)));
        
        create_table(
            &format!("{} ({} sec)", title, interval_secs),
            rows,
            min_width,
        )
    }
}

// ====================== STATISTICS MODULE ======================

mod stats {
    use super::*;
    
    #[derive(Debug, Clone)]
    pub struct TrafficStats {
        rx_bytes: Arc<AtomicU64>,
        tx_bytes: Arc<AtomicU64>,
        rx_packets: Arc<AtomicU64>,
        tx_packets: Arc<AtomicU64>,
        last_update: Arc<Mutex<Instant>>,
    }
    
    impl TrafficStats {
        pub fn new() -> Self {
            Self {
                rx_bytes: Arc::new(AtomicU64::new(0)),
                tx_bytes: Arc::new(AtomicU64::new(0)),
                rx_packets: Arc::new(AtomicU64::new(0)),
                tx_packets: Arc::new(AtomicU64::new(0)),
                last_update: Arc::new(Mutex::new(Instant::now())),
            }
        }
        
        pub fn update_rx(&self, bytes: usize) {
            self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            self.rx_packets.fetch_add(1, Ordering::Relaxed);
        }
        
        pub fn update_tx(&self, bytes: usize) {
            self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
        }
        
        pub fn get_and_reset(&self) -> (u64, u64, u64, u64, f64) {
            let rx_bytes = self.rx_bytes.swap(0, Ordering::AcqRel);
            let tx_bytes = self.tx_bytes.swap(0, Ordering::AcqRel);
            let rx_packets = self.rx_packets.swap(0, Ordering::AcqRel);
            let tx_packets = self.tx_packets.swap(0, Ordering::AcqRel);
            
            let now = Instant::now();
            let elapsed = {
                let mut last_update = self.last_update.lock().unwrap();
                let elapsed = now.duration_since(*last_update).as_secs_f64();
                *last_update = now;
                elapsed.max(0.001)
            };
            
            (rx_bytes, tx_bytes, rx_packets, tx_packets, elapsed)
        }
        
        pub fn print_stats(&self, title: &str, interval_secs: u64, table_width: usize) -> bool {
            let (rx_bytes, tx_bytes, rx_packets, tx_packets, elapsed) = self.get_and_reset();
            
            if rx_bytes == 0 && tx_bytes == 0 {
                return false;
            }
            
            let stats_table = table::create_stats_table(
                title,
                interval_secs,
                rx_bytes,
                tx_bytes,
                rx_packets,
                tx_packets,
                elapsed,
                table_width,
            );
            
            println!("\n{}", stats_table);
            true
        }
    }
}

// ====================== CRYPTOGRAPHY MODULE ======================

mod crypto {
    use super::*;
    
    #[derive(Clone)]
    pub struct TunnelCrypto {
        cipher: Aes128Gcm,
        send_counter: Arc<Mutex<u64>>,
        recv_counter: Arc<Mutex<u64>>,
    }
    
    impl TunnelCrypto {
        pub fn new(password: &str) -> Self {
            let hash = sha2::Sha256::digest(password.as_bytes());
            let key = &hash[..16];
            Self {
                cipher: Aes128Gcm::new_from_slice(key).expect("[FATAL] Key Must be 16 bytes"),
                send_counter: Arc::new(Mutex::new(0)),
                recv_counter: Arc::new(Mutex::new(0)),
            }
        }
        
        fn next_nonce(&self, send: bool) -> Nonce12 {
            let counter = if send { &self.send_counter } else { &self.recv_counter };
            let mut c = counter.lock().unwrap();
            *c += 1;
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&c.to_be_bytes());
            Nonce12::from(nonce)
        }
        
        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let nonce = self.next_nonce(true);
            self.cipher.encrypt(&nonce, plaintext).expect("[ERROR] Encryption Failed")
        }
        
        pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
            let nonce = self.next_nonce(false);
            self.cipher.decrypt(&nonce, ciphertext).ok()
        }
        
        pub fn reset_counters(&self) {
            *self.send_counter.lock().unwrap() = 0;
            *self.recv_counter.lock().unwrap() = 0;
        }
    }
}

// ====================== NETWORK MODULE ======================

mod network {
    use super::*;
    
    pub fn create_udp_socket(addr: SocketAddr, buffer_size: usize) -> std::io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_recv_buffer_size(buffer_size)?;
        socket.set_send_buffer_size(buffer_size)?;
        socket.bind(&addr.into())?;
        Ok(socket.into())
    }
    
    pub fn create_sctp_listener(port: u16) -> std::io::Result<Socket> {
        let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        listener.bind(&bind_addr.into())?;
        listener.listen(1024)?;
        Ok(listener)
    }
    
    pub fn create_sctp_client(server_addr: SocketAddr, buffer_size: usize) -> std::io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;
        socket.set_send_buffer_size(buffer_size).ok();
        socket.set_recv_buffer_size(buffer_size).ok();
        socket.connect(&server_addr.into())?;
        Ok(socket)
    }
}

// ====================== COMMAND LINE ======================

#[derive(Parser)]
#[command(name = "fuscen", version = "11.9", about = "UDP-over-SCTP tunnel — Fixed tables")]
struct Args {
    #[arg(long, help = "Password for AES-128-GCM (≥16 characters)")]
    key: String,

    #[arg(long, help = "Selective debug log (1=minimal, 2=detailed, 3=full)")]
    debug: Option<u8>,

    #[arg(long, default_value = "33554432", help = "UDP buffer size in bytes")]
    udp_buffer_size: usize,

    #[arg(long, default_value = "10", help = "Statistics output interval in seconds")]
    stats_interval: u64,

    #[arg(long, default_value = "100", help = "Debug message output frequency")]
    debug_frequency: u64,

    #[arg(long, default_value = "70", help = "Table width in characters")]
    table_width: usize,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Client {
        #[arg(long, default_value = "127.0.0.1:55553")]
        local_port: SocketAddr,

        #[arg(long)]
        server_sctp: SocketAddr,
    },
    Server {
        #[arg(long, default_value_t = 55551)]
        sctp_port: u16,

        #[arg(long, default_value = "127.0.0.1:55552")]
        ax_backend: SocketAddr,
    },
}

// ====================== SERVER ======================

mod server {
    use super::*;
    
    #[derive(Clone)]
    pub struct ServerConfig {
        pub sctp_port: u16,
        pub ax_backend: SocketAddr,
        pub udp_buffer_size: usize,
        pub debug_level: Option<u8>,
        pub debug_frequency: u64,
        pub stats_interval: u64,
        pub table_width: usize,
    }
    
    pub fn run_server(config: ServerConfig, crypto: crypto::TunnelCrypto) {
        // Create SCTP listener
        let listener = network::create_sctp_listener(config.sctp_port)
            .expect("[FATAL] Failed to create SCTP Listener");
        
        // Create table with server information
        let info_rows = vec![
            table::TableRow::simple("SCTP Local on", &config.sctp_port.to_string()),
            table::TableRow::simple("UDP Endpoint is", &config.ax_backend.to_string()),
            table::TableRow::new("UDP Buffer", format!("{:>6} MB", config.udp_buffer_size / 1024 / 1024)),
            table::TableRow::new("Debug Level", format!("{:>6}", config.debug_level.unwrap_or(0))),
            table::TableRow::new("Debug Frequency", format!("1/{:<5} packets", config.debug_frequency)),
            table::TableRow::new("Statistics", format!("every {:>2} sec", config.stats_interval)),
        ];
        
        println!("{}", table::create_table("Fuscen Stream 12", info_rows, config.table_width));
        
        // Create statistics
        let server_stats = Arc::new(stats::TrafficStats::new());
        
        // Start statistics thread
        let stats_display = server_stats.clone();
        let stats_interval = config.stats_interval;
        let table_width = config.table_width;
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(stats_interval));
                stats_display.print_stats("STATISTICS - Stream", stats_interval, table_width);
            }
        });
        
        // Main accept loop
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let peer_addr = match peer.as_socket_ipv4() {
                        Some(addr) => addr.to_string(),
                        None => format!("{:?}", peer),
                    };
                    
                    if config.debug_level.unwrap_or(0) >= 2 {
                        println!("[INFO] Connection from {}", peer_addr);
                    }
                    
                    let crypto_clone = crypto.clone();
                    let stats_clone = server_stats.clone();
                    let config_clone = config.clone();
                    
                    thread::spawn(move || {
                        handle_client_connection(
                            stream,
                            crypto_clone,
                            config_clone,
                            stats_clone,
                            peer_addr,
                        );
                    });
                }
                Err(e) => {
                    if config.debug_level.unwrap_or(0) >= 1 {
                        eprintln!("[ERROR] Error on RX: {}", e);
                    }
                }
            }
        }
    }
    
    fn handle_client_connection(
        sctp_stream: Socket,
        crypto: crypto::TunnelCrypto,
        config: ServerConfig,
        stats: Arc<stats::TrafficStats>,
        client_addr: String,
    ) {
        
        crypto.reset_counters();
        
        // Create local UDP socket for this client
        let local_udp = network::create_udp_socket("127.0.0.1:0".parse().unwrap(), config.udp_buffer_size)
            .unwrap_or_else(|_| {
                UdpSocket::bind("127.0.0.1:0").expect("[FATAL] UDP Local Bind Failed")
            });
        
        let local_port = local_udp.local_addr().unwrap().port();
        
        if config.debug_level.unwrap_or(0) >= 2 {
            println!("[INFO] TX Port {} for Client {}", local_port, client_addr);
        }
		
		if config.debug_level.unwrap_or(0) >= 1 {
            println!("[✔] New Client! {}!", client_addr);
        }
        
        let sctp_stream = Arc::new(sctp_stream);
        let udp_read = local_udp.try_clone().expect("[ERROR] Сlone UDP for Reading");
        let udp_write = local_udp;
        
        // Clone variables for threads
        let client_addr_sctp = client_addr.clone();
        let client_addr_udp = client_addr.clone();
        let ax_backend = config.ax_backend;
        let stats_sctp = stats.clone();
        let stats_udp = stats.clone();
        let debug_level = config.debug_level;
        let debug_frequency = config.debug_frequency;
        
        // Thread SCTP → UDP
        let sctp_r = sctp_stream.clone();
        let crypto_rx = crypto.clone();
        thread::spawn(move || {
            process_sctp_to_udp(
                sctp_r,
                crypto_rx,
                udp_write,
                ax_backend,
                client_addr_sctp,
                local_port,
                stats_sctp,
                debug_level,
                debug_frequency,
            );
        });
        
        // Thread UDP → SCTP
        let sctp_w = sctp_stream.clone();
        let crypto_tx = crypto.clone();
        thread::spawn(move || {
            process_udp_to_sctp(
                sctp_w,
                crypto_tx,
                udp_read,
                client_addr_udp,
                stats_udp,
                debug_level,
                debug_frequency,
            );
        });
    }
    
    fn process_sctp_to_udp(
        sctp: Arc<Socket>,
        crypto: crypto::TunnelCrypto,
        udp_socket: UdpSocket,
        ax_backend: SocketAddr,
        client_addr: String,
        local_port: u16,
        stats: Arc<stats::TrafficStats>,
        debug_level: Option<u8>,
        debug_frequency: u64,
    ) {
        let mut reader = BufReader::new(&*sctp);
        let mut len_buf = [0u8; 4];
        let mut payload = vec![0u8; 65536];
        let mut packet_counter = 0u64;
        
        loop {
            if reader.read_exact(&mut len_buf).is_err() {
                if debug_level.unwrap_or(0) >= 1 {
                    println!("[INFO] Client {} disconnected", client_addr);
                }
                break;
            }
            
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 65536 {
                if debug_level.unwrap_or(0) >= 1 {
                    eprintln!("[ERROR] Invalid Length from Client {}: {}", client_addr, len);
                }
                break;
            }
            
            if reader.read_exact(&mut payload[..len]).is_err() {
                break;
            }
            
            if let Some(plain) = crypto.decrypt(&payload[..len]) {
                stats.update_rx(plain.len());
                
                packet_counter += 1;
                if debug_level.unwrap_or(0) >= 3 && packet_counter % debug_frequency == 0 {
                    println!("[INFO] Client {}:{} → Backend {} ({} bytes, packet {})", 
                            client_addr, local_port, ax_backend.port(), 
                            plain.len(), packet_counter);
                }
                
                let _ = udp_socket.send_to(&plain, ax_backend);
            } else if debug_level.unwrap_or(0) >= 1 {
                eprintln!("[ERROR] Decryption Error from Client {}", client_addr);
            }
        }
    }
    
    fn process_udp_to_sctp(
        sctp: Arc<Socket>,
        crypto: crypto::TunnelCrypto,
        udp_socket: UdpSocket,
        client_addr: String,
        stats: Arc<stats::TrafficStats>,
        debug_level: Option<u8>,
        debug_frequency: u64,
    ) {
        let mut writer = BufWriter::new(&*sctp);
        let mut buf = vec![0u8; 65536];
        let mut packet_counter = 0u64;
        
        loop {
            match udp_socket.recv(&mut buf) {
                Ok(len) => {
                    stats.update_tx(len);
                    
                    packet_counter += 1;
                    if debug_level.unwrap_or(0) >= 3 && packet_counter % debug_frequency == 0 {
                        println!("[INFO] Backend → {}:{} ({} bytes, packet {})", 
                                client_addr,
                                sctp.peer_addr()
                                    .ok()
                                    .and_then(|sa| sa.as_socket())
                                    .map(|s| s.port())
                                    .unwrap_or(0),
                                len, packet_counter);
                    }
                    
                    let ct = crypto.encrypt(&buf[..len]);
                    let framing = (ct.len() as u32).to_be_bytes();
                    
                    if writer.write_all(&framing).is_err() || 
                       writer.write_all(&ct).is_err() ||
                       writer.flush().is_err() {
                        break;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
    }
}

// ====================== CLIENT ======================

mod client {
    use super::*;
    
    #[derive(Clone)]
    pub struct ClientConfig {
        pub local_port: SocketAddr,
        pub server_sctp: SocketAddr,
        pub udp_buffer_size: usize,
        pub debug_level: Option<u8>,
        pub debug_frequency: u64,
        pub stats_interval: u64,
        pub table_width: usize,
    }
    
    pub struct ClientState {
        pub last_ax_src: Arc<Mutex<Option<SocketAddr>>>,
        pub stats: Arc<stats::TrafficStats>,
    }
    
    impl ClientState {
        pub fn new() -> Self {
            Self {
                last_ax_src: Arc::new(Mutex::new(None)),
                stats: Arc::new(stats::TrafficStats::new()),
            }
        }
    }
    
    pub fn run_client(config: ClientConfig, crypto: crypto::TunnelCrypto) {
        // Create table with client information
        let info_rows = vec![
            table::TableRow::simple("UDP Local on", &config.local_port.to_string()),
            table::TableRow::simple("SCTP Endpoint is", &config.server_sctp.to_string()),
            table::TableRow::new("UDP Buffer", format!("{:>6} MB", config.udp_buffer_size / 1024 / 1024)),
            table::TableRow::new("Debug Level", format!("{:>6}", config.debug_level.unwrap_or(0))),
            table::TableRow::new("Debug Frequency", format!("1/{:<5} packets", config.debug_frequency)),
            table::TableRow::new("Statistics", format!("every {:>2} sec", config.stats_interval)),
        ];
        
        println!("{}", table::create_table("Fuscen Connect 12", info_rows, config.table_width));
        
        // Create UDP socket
        let udp_socket = network::create_udp_socket(config.local_port, config.udp_buffer_size)
            .unwrap_or_else(|_| {
                UdpSocket::bind(config.local_port).expect("[FATAL] bind UDP socket")
            });
        
        // Create client state
        let client_state = ClientState::new();
        
        // Start statistics thread
        let stats_display = client_state.stats.clone();
        let stats_interval = config.stats_interval;
        let table_width = config.table_width;
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(stats_interval));
                stats_display.print_stats("STATISTICS - Connect", stats_interval, table_width);
            }
        });
        
        // Main reconnection loop
        loop {
            match network::create_sctp_client(config.server_sctp, config.udp_buffer_size) {
                Ok(sctp) => {
                    if config.debug_level.unwrap_or(0) >= 1 {
                        println!("[✔] Tunnel Established! With Endpoint {}:{}", 
                                config.server_sctp.ip(), config.server_sctp.port());
                    }
                    
                    crypto.reset_counters();
                    
                    // Handle connection
                    handle_connection(
                        sctp,
                        crypto.clone(),
                        &udp_socket,
                        &client_state,
                        &config,
                    );
                    
                    if config.debug_level.unwrap_or(0) >= 1 {
                        println!("[INFO] Tunnel Broken — reconnecting on 3 seconds...");
                    }
                }
                Err(e) => {
                    if config.debug_level.unwrap_or(0) >= 1 {
                        eprintln!("[ERROR] Connection Failed: {} — waiting 3 seconds", e);
                    }
                }
            }
            
            thread::sleep(Duration::from_secs(3));
        }
    }
    
    fn handle_connection(
        sctp: Socket,
        crypto: crypto::TunnelCrypto,
        udp_socket: &UdpSocket,
        client_state: &ClientState,
        config: &ClientConfig,
    ) {
        let sctp_arc = Arc::new(sctp);
        
        // Clone UDP sockets
        let udp_for_sctp = udp_socket.try_clone().expect("[ERROR] Clone UDP for SCTP Thread");
        let udp_for_udp = udp_socket.try_clone().expect("[ERROR] Clone UDP for UDP Thread");
        
        // Clone state
        let last_ax_src = client_state.last_ax_src.clone();
        let stats_rx = client_state.stats.clone();
        let stats_tx = client_state.stats.clone();
        
        // Thread SCTP → UDP
        let sctp_r = sctp_arc.clone();
        let last_ax_src_sctp = last_ax_src.clone();
        let server_sctp = config.server_sctp;
        let crypto_rx = crypto.clone();
        let debug_level = config.debug_level;
        let debug_frequency = config.debug_frequency;
        
        thread::spawn(move || {
            process_client_sctp_to_udp(
                sctp_r,
                crypto_rx,
                udp_for_sctp,
                last_ax_src_sctp,
                server_sctp,
                stats_rx,
                debug_level,
                debug_frequency,
            );
        });
        
        // Thread UDP → SCTP
        let mut writer = BufWriter::new(&*sctp_arc);
        let mut buf = vec![0u8; 65536];
        let mut packet_counter = 0u64;
        
        loop {
            match udp_for_udp.recv_from(&mut buf) {
                Ok((len, src)) => {
                    *last_ax_src.lock().unwrap() = Some(src);
                    stats_tx.update_tx(len);
                    
                    packet_counter += 1;
                    if config.debug_level.unwrap_or(0) >= 3 && packet_counter % config.debug_frequency == 0 {
                        println!("[INFO] TX {} bytes from {}:{} → Server {}:{} (packet {})", 
                                len,
                                src.ip(), src.port(),
                                config.server_sctp.ip(), config.server_sctp.port(),
                                packet_counter);
                    }
                    
                    let ct = crypto.encrypt(&buf[..len]);
                    let framing = (ct.len() as u32).to_be_bytes();
                    
                    if writer.write_all(&framing).is_err() || 
                       writer.write_all(&ct).is_err() || 
                       writer.flush().is_err() {
                        if config.debug_level.unwrap_or(0) >= 1 {
                            eprintln!("[ERROR] SCTP Error on Write");
                        }
                        break;
                    }
                }
                Err(e) => {
                    if config.debug_level.unwrap_or(0) >= 2 {
                        println!("[INFO] UDP Error on RX: {}", e);
                    }
                    break;
                }
            }
        }
    }
    
    fn process_client_sctp_to_udp(
        sctp: Arc<Socket>,
        crypto: crypto::TunnelCrypto,
        udp_socket: UdpSocket,
        last_ax_src: Arc<Mutex<Option<SocketAddr>>>,
        server_sctp: SocketAddr,
        stats: Arc<stats::TrafficStats>,
        debug_level: Option<u8>,
        debug_frequency: u64,
    ) {
        let mut reader = BufReader::new(&*sctp);
        let mut len_buf = [0u8; 4];
        let mut payload = vec![0u8; 65536];
        let mut packet_counter = 0u64;
        
        loop {
            if reader.read_exact(&mut len_buf).is_err() { 
                if debug_level.unwrap_or(0) >= 1 {
                    println!("[INFO] No Connection to Server");
                }
                break; 
            }
            
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 65536 { 
                if debug_level.unwrap_or(0) >= 1 {
                    eprintln!("[ERROR] Invalid Length from Server - {}", len);
                }
                break; 
            }
            
            if reader.read_exact(&mut payload[..len]).is_err() { 
                break; 
            }
            
            if let Some(plain) = crypto.decrypt(&payload[..len]) {
                stats.update_rx(plain.len());
                
                packet_counter += 1;
                if debug_level.unwrap_or(0) >= 3 && packet_counter % debug_frequency == 0 {
                    println!("[INFO] RX: {} bytes from Server {}:{} (packet {})", 
                            plain.len(),
                            server_sctp.ip(),
                            server_sctp.port(),
                            packet_counter);
                }
                
                let ax_addr = last_ax_src.lock().unwrap();
                if let Some(addr) = *ax_addr {
                    let _ = udp_socket.send_to(&plain, addr);
                } else if debug_level.unwrap_or(0) >= 2 {
                    println!("[WARN] Service Address not known yet");
                }
            } else if debug_level.unwrap_or(0) >= 1 {
                eprintln!("[ERROR] Decryption Error from Server");
            }
        }
    }
}

// ====================== MAIN FUNCTION ======================

fn main() {
    let args = Args::parse();
    
    if args.key.len() < 16 {
        eprintln!("[FATAL] Password Must be ≥ 16 Characters");
        std::process::exit(1);
    }
    
    let crypto = crypto::TunnelCrypto::new(&args.key);
    
    match args.command {
        Command::Client {
            local_port,
            server_sctp,
        } => {
            let config = client::ClientConfig {
                local_port,
                server_sctp,
                udp_buffer_size: args.udp_buffer_size,
                debug_level: args.debug,
                debug_frequency: args.debug_frequency,
                stats_interval: args.stats_interval,
                table_width: args.table_width,
            };
            
            client::run_client(config, crypto);
        }
        Command::Server {
            sctp_port,
            ax_backend,
        } => {
            let config = server::ServerConfig {
                sctp_port,
                ax_backend,
                udp_buffer_size: args.udp_buffer_size,
                debug_level: args.debug,
                debug_frequency: args.debug_frequency,
                stats_interval: args.stats_interval,
                table_width: args.table_width,
            };
            
            server::run_server(config, crypto);
        }
    }
}