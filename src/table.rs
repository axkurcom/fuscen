// Pretty unicode table rendering with width-aware alignment
use std::cmp::max;
use unicode_width::UnicodeWidthStr;

/// One row entry
#[derive(Clone)]
pub struct TableRow {
    // Left label
    pub label: String,
    // Right value
    pub value: String,
}

impl TableRow {
    /// Label + owned value
    pub fn new(label: &str, value: String) -> Self {
        Self {
            label: label.to_string(),
            value,
        }
    }

    /// Label + borrowed value
    pub fn simple(label: &str, value: &str) -> Self {
        Self {
            label: label.to_string(),
            value: value.to_string(),
        }
    }
}

/// Display width for unicode strings
fn visual_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Render a boxed table
pub fn create_table(title: &str, rows: Vec<TableRow>, min_width: usize) -> String {
    // Compute max line width
    let mut max_len = min_width;
    max_len = max(max_len, visual_width(title) + 4);

    for row in &rows {
        let row_len = visual_width(&format!("{}: {}", row.label, row.value)) + 4;
        max_len = max(max_len, row_len);
    }

    // Extra padding
    max_len += 2;

    let mut result = String::new();

    // Top border
    result.push_str(&format!("╔{}╗\n", "═".repeat(max_len - 2)));

    // Centered title
    let title_width = visual_width(title);
    let title_padding = max_len - title_width - 4;
    let title_left = title_padding / 2;
    let title_right = title_padding - title_left;
    result.push_str(&format!(
        "║ {}{}{} ║\n",
        " ".repeat(title_left),
        title,
        " ".repeat(title_right)
    ));

    // Header separator
    result.push_str(&format!("╠{}╣\n", "═".repeat(max_len - 2)));

    // Rows
    for (i, row) in rows.iter().enumerate() {
        let row_text = format!("{}: {}", row.label, row.value);
        let row_width = visual_width(&row_text);
        let row_padding = max_len - row_width - 4;
        // Slight asymmetry kept as-is
        let row_left = 1;
        let row_right = row_padding - row_left;
        result.push_str(&format!(
            "║ {}{}{} ║\n",
            row_text,
            " ".repeat(row_right),
            " ".repeat(row_left)
        ));

        // Mid separator for long tables
        if i == rows.len() / 2 - 1 && rows.len() > 4 {
            result.push_str(&format!("╠{}╣\n", "─".repeat(max_len - 2)));
        }
    }

    // Bottom border
    result.push_str(&format!("╚{}╝", "═".repeat(max_len - 2)));

    result
}

/// Build and render traffic stats table
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
    // Rates
    let rx_mbps = (rx_bytes as f64 * 8.0 / elapsed_secs) / 1_000_000.0;
    let tx_mbps = (tx_bytes as f64 * 8.0 / elapsed_secs) / 1_000_000.0;
    let rx_pps = rx_packets as f64 / elapsed_secs;
    let tx_pps = tx_packets as f64 / elapsed_secs;
    let rx_mb = rx_bytes as f64 / 1024.0 / 1024.0;
    let tx_mb = tx_bytes as f64 / 1024.0 / 1024.0;

    // Simple ratio metric
    let efficiency = if tx_bytes > 0 {
        (rx_bytes as f64 / tx_bytes as f64) * 100.0
    } else {
        0.0
    };

    let mut rows = Vec::new();

    // RX block
    rows.push(TableRow::simple("📥 Received - RX", ""));
    rows.push(TableRow::new("  Speed", format!("{:7.2} Mbps", rx_mbps)));
    rows.push(TableRow::new(
        "  Packets",
        format!("{:7} ({:.0}/s)", rx_packets, rx_pps),
    ));
    rows.push(TableRow::new("  Data", format!("{:7.2} MB", rx_mb)));

    // TX block
    rows.push(TableRow::simple("📤 Transmitted - TX", ""));
    rows.push(TableRow::new("  Speed", format!("{:7.2} Mbps", tx_mbps)));
    rows.push(TableRow::new(
        "  Packets",
        format!("{:7} ({:.0}/s)", tx_packets, tx_pps),
    ));
    rows.push(TableRow::new("  Data", format!("{:7.2} MB", tx_mb)));

    // Extra metric
    rows.push(TableRow::new("  Efficiency", format!("{:6.2}%", efficiency)));

    create_table(&format!("{} ({} sec)", title, interval_secs), rows, min_width)
}