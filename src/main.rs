// CLI entrypoint wiring client/server modes
mod constants;
mod table;
mod stats;
mod crypto;
mod network;
mod server;
mod client;
mod async_io;
mod framing;
mod protocol;
mod sctp;

use clap::{Parser, Subcommand};
use num_cpus;

use crate::constants::{MAX_PACKET_SIZE, OPTIMAL_BUFFER_SIZE};
use crate::crypto::TunnelCrypto;
use crate::server::{run_server, ServerConfig};
use crate::client::{run_client, ClientConfig};

/// CLI args
#[derive(Parser)]
#[command(
    name = "fuscen",
    version = "13.0",
    about = "UDP-over-SCTP tunnel with AES-NI optimization and zero-copy"
)]
struct Args {
    // Password for key derivation
    #[arg(long, help = "Password for AES-128-GCM (≥16 characters)")]
    key: String,

    // Debug verbosity
    #[arg(long, help = "Selective debug log (0=none, 1=minimal, 2=detailed, 3=full)")]
    debug: Option<u8>,

    // UDP socket buffers
    #[arg(long, default_value = "33554432", help = "UDP buffer size in bytes")]
    udp_buffer_size: usize,

    // Stats interval
    #[arg(long, default_value = "10", help = "Statistics output interval in seconds")]
    stats_interval: u64,

    // Debug sampling
    #[arg(long, default_value = "100", help = "Debug message output frequency")]
    debug_frequency: u64,

    // UI table width
    #[arg(long, default_value = "70", help = "Table width in characters")]
    table_width: usize,

    // Cipher selection
    #[arg(long, default_value = "false", help = "Enable AES-256 instead of AES-128")]
    aes256: bool,

    // Nonblocking flag
    #[arg(long, default_value = "false", help = "Enable non-blocking I/O")]
    nonblocking: bool,

    // Zero-copy request
    #[arg(long, default_value = "false", help = "Enable zero-copy when available")]
    zero_copy: bool,

    // Async poller request
    #[arg(long, default_value = "false", help = "Enable async I/O (epoll/kqueue)")]
    async_io: bool,

    // Server workers
    #[arg(long, default_value = "4", help = "Worker threads for server")]
    workers: usize,

    // Subcommand
    #[command(subcommand)]
    command: Command,
}

/// Client vs server mode
#[derive(Subcommand)]
enum Command {
    // Run as client
    Client {
        // Local UDP bind
        #[arg(long, default_value = "127.0.0.1:55553")]
        local_port: std::net::SocketAddr,

        // Server SCTP endpoint
        #[arg(long)]
        server_sctp: std::net::SocketAddr,

        // Enable batching
        #[arg(long, default_value = "false", help = "Enable packet batching")]
        batch: bool,

        // Batch size
        #[arg(long, default_value = "32", help = "Batch size")]
        batch_size: usize,

        // Extra zero-copy flag
        #[arg(long, default_value = "false", help = "Enable zero-copy buffers")]
        zero_copy_buffers: bool,
    },
    // Run as server
    Server {
        // Local SCTP port
        #[arg(long, default_value_t = 55551)]
        sctp_port: u16,

        // Backend UDP destination
        #[arg(long, default_value = "127.0.0.1:55552")]
        ax_backend: std::net::SocketAddr,

        // Connection pool flag
        #[arg(long, default_value = "false", help = "Enable connection pooling")]
        pool: bool,

        // Pool size placeholder
        #[arg(long, default_value = "100", help = "Connection pool size")]
        pool_size: usize,

        // Extra zero-copy flag
        #[arg(long, default_value = "false", help = "Enable zero-copy mode")]
        zero_copy_mode: bool,
    },
}

/// Linux kernel check for hints
fn check_kernel_compatibility() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(kernel_version) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            let version = kernel_version.trim();
            println!("[ℹ] Kernel: {}", version);
            return version.starts_with("4.") || version.starts_with("5.") || version.starts_with("6.");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("[ℹ] Kernel: non-Linux (some optimizations disabled)");
    }

    true
}

/// Startup checks and environment hints
fn perform_pretests() {
    println!("[🔍] Running logical pretests...");

    // AES-NI check
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;
        unsafe {
            let cpuid = __cpuid(1);
            let has_aesni = (cpuid.ecx & (1 << 25)) != 0;
            println!(
                "[1/6] AES-NI Support: {}",
                if has_aesni { "PASS ✅" } else { "WARN ⚠ (software fallback)" }
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        println!("[1/6] AES-NI: N/A (not x86_64)");
    }

    // Zero-copy support check
    println!(
        "[2/6] Zero-copy support: {}",
        if network::supports_zero_copy() { "PASS ✅" } else { "WARN ⚠ (disabled)" }
    );

    // Async poller support check
    println!(
        "[3/6] Async I/O (epoll/kqueue): {}",
        if async_io::check_async_support() { "PASS ✅" } else { "WARN ⚠ (disabled)" }
    );

    // Buffer sanity
    let optimal_buffer = OPTIMAL_BUFFER_SIZE;
    let max_packet = MAX_PACKET_SIZE;
    println!(
        "[4/6] Buffer Sizes: Optimal={}B, Max Packet={}B {}",
        optimal_buffer,
        max_packet,
        if optimal_buffer >= max_packet * 2 { "✅" } else { "⚠" }
    );

    // Kernel hint
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(kernel_version) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            println!(
                "[5/6] Linux Kernel: {} {}",
                kernel_version.trim(),
                if kernel_version.contains("4.14") || kernel_version.contains("5.") {
                    "✅"
                } else {
                    "⚠ (consider upgrade for zero-copy)"
                }
            );
        } else {
            println!("[5/6] Kernel: Unable to read version");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("[5/6] Kernel: Not Linux (some optimizations disabled)");
    }

    // CPU core count
    let cores = num_cpus::get();
    println!(
        "[6/6] CPU Cores: {} {}",
        cores,
        if cores >= 4 { "✅" } else { "⚠ (performance may be limited)" }
    );

    println!("[✓] Pretests completed");
}

fn main() {
    // Banner
    println!("=== Fuscen v13.0 (Zero-copy Enhanced with Async I/O) ===");

    // Env hint
    if !check_kernel_compatibility() {
        println!("[⚠] Running on older kernel - some optimizations disabled");
    }

    // Preflight
    perform_pretests();

    // Parse CLI
    let args = Args::parse();

    // Password length gate
    if args.key.len() < 16 {
        eprintln!("[FATAL] Password must be ≥ 16 characters");
        std::process::exit(1);
    }

    // Build crypto
    let crypto = if args.aes256 {
        TunnelCrypto::new_aes256(&args.key)
    } else {
        TunnelCrypto::new(&args.key)
    };

    // Mode info
    println!(
        "[🔐] Crypto: AES-{} with zero-copy: {}, async I/O: {}",
        if args.aes256 { "256" } else { "128" },
        if args.zero_copy { "requested" } else { "standard mode" },
        if args.async_io { "enabled" } else { "disabled" }
    );

    // Dispatch
    match args.command {
        Command::Client {
            local_port,
            server_sctp,
            batch,
            batch_size,
            zero_copy_buffers,
        } => {
            let config = ClientConfig {
                local_port,
                server_sctp,
                udp_buffer_size: args.udp_buffer_size,
                debug_level: args.debug,
                debug_frequency: args.debug_frequency,
                stats_interval: args.stats_interval,
                table_width: args.table_width,
                batch_enabled: batch,
                batch_size,
                nonblocking: args.nonblocking,
                zero_copy: args.zero_copy || zero_copy_buffers,
                use_async_io: args.async_io,
            };

            run_client(config, crypto);
        }
        Command::Server {
            sctp_port,
            ax_backend,
            pool,
            pool_size: _,
            zero_copy_mode,
        } => {
            let config = ServerConfig {
                sctp_port,
                ax_backend,
                udp_buffer_size: args.udp_buffer_size,
                debug_level: args.debug,
                debug_frequency: args.debug_frequency,
                stats_interval: args.stats_interval,
                table_width: args.table_width,
                workers: args.workers,
                pool_enabled: pool,
                pool_size: 0,
                nonblocking: args.nonblocking,
                zero_copy: args.zero_copy || zero_copy_mode,
                use_async_io: args.async_io,
            };

            run_server(config, crypto);
        }
    }
}