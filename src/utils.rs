use std::{
    net::IpAddr,
    time::Duration,
};

// Simplified network range for checking if an IP is local
#[derive(Debug, Clone)]
pub struct IpRange {
    base: [u8; 4],
    mask: [u8; 4],
}

impl IpRange {
    pub fn new(base: [u8; 4], prefix: u8) -> Self {
        let mut mask = [0; 4];
        for i in 0..4 {
            let i_usize = i as usize;
            if (i_usize * 8) < prefix as usize {
                if (i_usize + 1) * 8 <= prefix as usize {
                    // Full byte is masked
                    mask[i_usize] = 0xFF;
                } else {
                    // Partial byte
                    let bits = prefix as usize - (i_usize * 8);
                    mask[i_usize] = 0xFF << (8 - bits);
                }
            }
        }
        
        IpRange { base, mask }
    }
    
    pub fn contains(&self, ip: &IpAddr) -> bool {
        if let IpAddr::V4(ipv4) = ip {
            let octets = ipv4.octets();
            for i in 0..4 {
                let i_usize = i as usize;
                if (octets[i_usize] & self.mask[i_usize]) != (self.base[i_usize] & self.mask[i_usize]) {
                    return false;
                }
            }
            true
        } else {
            false // Only supporting IPv4 for simplicity
        }
    }
}

// Helper function to check if an IP is in any local network
pub fn is_local_ip(ip: IpAddr, local_networks: &[IpRange]) -> bool {
    local_networks.iter().any(|net| net.contains(&ip))
}

// Simple check if IP is private (simpler than using std function which may not be available)
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            (octets[0] == 10) ||
            // 172.16.0.0/12
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            // 192.168.0.0/16
            (octets[0] == 192 && octets[1] == 168) ||
            // 169.254.0.0/16
            (octets[0] == 169 && octets[1] == 254)
        },
        IpAddr::V6(_) => false  // Simplified for the example
    }
}

// Simple check if IP is loopback
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 127.0.0.0/8
            octets[0] == 127
        },
        IpAddr::V6(_) => false  // Simplified for the example
    }
}

// Helper function to format bytes
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// Helper function to format bytes per second
pub fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    
    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.2} B/s", bytes_per_sec)
    }
}

// Helper function to format time duration
pub fn format_duration(duration: Duration) -> String {
    if duration.as_secs() < 60 {
        format!("{}s", duration.as_secs())
    } else if duration.as_secs() < 3600 {
        format!("{}m {}s", duration.as_secs() / 60, duration.as_secs() % 60)
    } else {
        format!("{}h {}m", duration.as_secs() / 3600, (duration.as_secs() % 3600) / 60)
    }
}

// Helper to create centered rect
pub fn centered_rect(percent_x: u16, percent_y: u16, r: ratatui::prelude::Rect) -> ratatui::prelude::Rect {
    use ratatui::prelude::*;
    
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}