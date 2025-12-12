// Shared traffic counters with interval reset
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::table;

/// RX/TX counters and periodic printing
#[derive(Debug, Clone)]
pub struct TrafficStats {
    // Total counters
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    rx_packets: Arc<AtomicU64>,
    tx_packets: Arc<AtomicU64>,
    rx_errors: Arc<AtomicU64>,
    tx_errors: Arc<AtomicU64>,

    // Interval counters
    interval_rx_bytes: Arc<AtomicU64>,
    interval_tx_bytes: Arc<AtomicU64>,
    interval_rx_packets: Arc<AtomicU64>,
    interval_tx_packets: Arc<AtomicU64>,
    interval_rx_errors: Arc<AtomicU64>,
    interval_tx_errors: Arc<AtomicU64>,

    // Timing state
    last_update: Arc<Mutex<Instant>>,
    start_time: Instant,
}

impl TrafficStats {
    /// New zeroed counters
    pub fn new() -> Self {
        Self {
            rx_bytes: Arc::new(AtomicU64::new(0)),
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_packets: Arc::new(AtomicU64::new(0)),
            tx_packets: Arc::new(AtomicU64::new(0)),
            rx_errors: Arc::new(AtomicU64::new(0)),
            tx_errors: Arc::new(AtomicU64::new(0)),

            interval_rx_bytes: Arc::new(AtomicU64::new(0)),
            interval_tx_bytes: Arc::new(AtomicU64::new(0)),
            interval_rx_packets: Arc::new(AtomicU64::new(0)),
            interval_tx_packets: Arc::new(AtomicU64::new(0)),
            interval_rx_errors: Arc::new(AtomicU64::new(0)),
            interval_tx_errors: Arc::new(AtomicU64::new(0)),

            last_update: Arc::new(Mutex::new(Instant::now())),
            start_time: Instant::now(),
        }
    }

    /// Count RX bytes and packet
    pub fn update_rx(&self, bytes: usize) {
        let b = bytes as u64;
        self.rx_bytes.fetch_add(b, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.interval_rx_bytes.fetch_add(b, Ordering::Relaxed);
        self.interval_rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Count TX bytes and packet
    pub fn update_tx(&self, bytes: usize) {
        let b = bytes as u64;
        self.tx_bytes.fetch_add(b, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.interval_tx_bytes.fetch_add(b, Ordering::Relaxed);
        self.interval_tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Count RX error
    pub fn increment_rx_errors(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
        self.interval_rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Count TX error
    pub fn increment_tx_errors(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
        self.interval_tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Read interval counters and reset them
    #[allow(clippy::type_complexity)]
    pub fn get_and_reset(&self) -> (u64, u64, u64, u64, u64, u64, f64, f64) {
        // Swap interval counters to zero
        let rx_bytes = self.interval_rx_bytes.swap(0, Ordering::AcqRel);
        let tx_bytes = self.interval_tx_bytes.swap(0, Ordering::AcqRel);
        let rx_packets = self.interval_rx_packets.swap(0, Ordering::AcqRel);
        let tx_packets = self.interval_tx_packets.swap(0, Ordering::AcqRel);
        let rx_errors = self.interval_rx_errors.swap(0, Ordering::AcqRel);
        let tx_errors = self.interval_tx_errors.swap(0, Ordering::AcqRel);

        // Compute elapsed times
        let now = Instant::now();
        let (elapsed, total_elapsed) = {
            let mut last_update = self.last_update.lock().unwrap();
            let elapsed = now.duration_since(*last_update).as_secs_f64();
            let total_elapsed = now.duration_since(self.start_time).as_secs_f64();
            *last_update = now;
            // Avoid division by zero
            (elapsed.max(0.001), total_elapsed.max(0.001))
        };

        (rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, elapsed, total_elapsed)
    }

    /// Print stats table if any activity
    pub fn print_stats(&self, title: &str, interval_secs: u64, table_width: usize) -> bool {
        let (
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            elapsed,
            total_elapsed,
        ) = self.get_and_reset();

        // Skip empty interval
        if rx_bytes == 0 && tx_bytes == 0 && rx_errors == 0 && tx_errors == 0 {
            return false;
        }

        // Render interval table
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

        // Print errors line
        if rx_errors > 0 || tx_errors > 0 {
            println!("[⚠] Errors - RX: {}, TX: {}", rx_errors, tx_errors);
        }

        // Periodic totals
        static GLOBAL_COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = GLOBAL_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

        if count % 10 == 0 {
            let total_rx = self.rx_bytes.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
            let total_tx = self.tx_bytes.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
            println!(
                "[📊] Total: RX {:.2} MB, TX {:.2} MB, Uptime: {:.0}s",
                total_rx, total_tx, total_elapsed
            );
        }

        true
    }
}