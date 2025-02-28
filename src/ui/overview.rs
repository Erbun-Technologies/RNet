use chrono::Local;
use ratatui::{
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;
use crate::network::types::{BasicProtocolType, get_basic_type};
use crate::utils::{format_bytes, format_bytes_per_sec};

pub fn draw_network_overview(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);
    
    // Interface name
    let interface_text = format!("Interface: {}", app.network_stats.interface_name);
    let interface = Paragraph::new(interface_text)
        .block(Block::default().borders(Borders::ALL).title("Interface"));
    f.render_widget(interface, chunks[0]);
    
    // Total traffic
    let total_rx = format_bytes(app.network_stats.rx_bytes);
    let total_tx = format_bytes(app.network_stats.tx_bytes);
    let total_text = format!("Total RX: {}\nTotal TX: {}", total_rx, total_tx);
    let total = Paragraph::new(total_text)
        .block(Block::default().borders(Borders::ALL).title("Traffic Totals"));
    f.render_widget(total, chunks[1]);
    
    // Current speeds
    let rx_speed = format_bytes_per_sec(app.network_stats.rx_speed);
    let tx_speed = format_bytes_per_sec(app.network_stats.tx_speed);
    let speed_text = format!("RX: {}\nTX: {}", rx_speed, tx_speed);
    let speeds = Paragraph::new(speed_text)
        .block(Block::default().borders(Borders::ALL).title("Current Speed"));
    f.render_widget(speeds, chunks[2]);
    
    // Packet counts
    if let Ok(stats) = app.packet_stats.try_lock() {
        let packet_text = match app.protocol_grouping {
            crate::network::types::ProtocolGrouping::Basic => {
                // Group by basic categories
                let tcp_count: u64 = stats.counts.iter()
                    .filter(|(k, _)| matches!(get_basic_type(**k), BasicProtocolType::TCP))
                    .map(|(_, v)| *v)
                    .sum();
                
                let udp_count: u64 = stats.counts.iter()
                    .filter(|(k, _)| matches!(get_basic_type(**k), BasicProtocolType::UDP))
                    .map(|(_, v)| *v)
                    .sum();
                
                let icmp_count = *stats.counts.get(&crate::network::types::PacketType::ICMP).unwrap_or(&0);
                let other_count = *stats.counts.get(&crate::network::types::PacketType::Other).unwrap_or(&0);
                
                format!(
                    "TCP: {} | UDP: {} | ICMP: {} | Other: {}", 
                    tcp_count, udp_count, icmp_count, other_count
                )
            },
            crate::network::types::ProtocolGrouping::Detailed => {
                // Show detailed breakdown
                let http_count = *stats.counts.get(&crate::network::types::PacketType::TCP_HTTP).unwrap_or(&0);
                let https_count = *stats.counts.get(&crate::network::types::PacketType::TCP_HTTPS).unwrap_or(&0);
                let ssh_count = *stats.counts.get(&crate::network::types::PacketType::TCP_SSH).unwrap_or(&0);
                let tcp_dns_count = *stats.counts.get(&crate::network::types::PacketType::TCP_DNS).unwrap_or(&0);
                let tcp_other_count = *stats.counts.get(&crate::network::types::PacketType::TCP_Other).unwrap_or(&0);
                
                let udp_dns_count = *stats.counts.get(&crate::network::types::PacketType::UDP_DNS).unwrap_or(&0);
                let dhcp_count = *stats.counts.get(&crate::network::types::PacketType::UDP_DHCP).unwrap_or(&0);
                let udp_other_count = *stats.counts.get(&crate::network::types::PacketType::UDP_Other).unwrap_or(&0);
                
                let tcp_total = http_count + https_count + ssh_count + tcp_dns_count + tcp_other_count;
                let udp_total = udp_dns_count + dhcp_count + udp_other_count;
                
                format!(
                    "TCP({}) HTTP:{} HTTPS:{} SSH:{} DNS:{} Other:{} | UDP({}) DNS:{} DHCP:{} Other:{} | ICMP:{} | Other:{}", 
                    tcp_total, http_count, https_count, ssh_count, tcp_dns_count, tcp_other_count,
                    udp_total, udp_dns_count, dhcp_count, udp_other_count,
                    *stats.counts.get(&crate::network::types::PacketType::ICMP).unwrap_or(&0),
                    *stats.counts.get(&crate::network::types::PacketType::Other).unwrap_or(&0)
                )
            }
        };
        
        let packets = Paragraph::new(packet_text)
            .block(Block::default().borders(Borders::ALL).title("Packet Counts"));
        f.render_widget(packets, chunks[3]);
    }
    
    // Date and time
    let now = Local::now();
    let date_time = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let date_widget = Paragraph::new(date_time)
        .block(Block::default().borders(Borders::ALL).title("Date & Time"))
        .alignment(Alignment::Center);
    f.render_widget(date_widget, chunks[4]);
}