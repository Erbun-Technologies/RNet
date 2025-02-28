use ratatui::{
    prelude::*,
    style::{Color, Style},
    widgets::{BarChart, Block, Borders, Paragraph},
};

use crate::app::App;
use crate::network::types::{BasicProtocolType, PacketType, ProtocolGrouping, get_basic_type};

pub fn draw_packet_bar_chart(f: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Packet Distribution");
    
    let inner_area = block.inner(area);
    f.render_widget(block, area);
    
    if let Ok(stats) = app.packet_stats.try_lock() {
        // Check if we have any data
        let total: u64 = stats.counts.values().sum();
        
        // Avoid division by zero
        if total == 0 {
            let message = Paragraph::new("No packets captured yet...")
                .alignment(Alignment::Center);
            f.render_widget(message, inner_area);
            return;
        }
        
        // Prepare data for barchart based on grouping mode
        let data = match app.protocol_grouping {
            ProtocolGrouping::Basic => {
                // Group by basic protocol type
                let tcp_count: u64 = stats.counts.iter()
                    .filter(|(k, _)| matches!(get_basic_type(**k), BasicProtocolType::TCP))
                    .map(|(_, v)| *v)
                    .sum();
                
                let udp_count: u64 = stats.counts.iter()
                    .filter(|(k, _)| matches!(get_basic_type(**k), BasicProtocolType::UDP))
                    .map(|(_, v)| *v)
                    .sum();
                
                let icmp_count = *stats.counts.get(&PacketType::ICMP).unwrap_or(&0);
                let other_count = *stats.counts.get(&PacketType::Other).unwrap_or(&0);
                
                vec![
                    ("TCP", tcp_count),
                    ("UDP", udp_count),
                    ("ICMP", icmp_count),
                    ("Other", other_count),
                ]
            },
            ProtocolGrouping::Detailed => {
                // Show detailed breakdown
                let mut data = vec![
                    ("HTTP", *stats.counts.get(&PacketType::TCP_HTTP).unwrap_or(&0)),
                    ("HTTPS", *stats.counts.get(&PacketType::TCP_HTTPS).unwrap_or(&0)),
                    ("SSH", *stats.counts.get(&PacketType::TCP_SSH).unwrap_or(&0)),
                    ("TCP_DNS", *stats.counts.get(&PacketType::TCP_DNS).unwrap_or(&0)),
                    ("TCP_Other", *stats.counts.get(&PacketType::TCP_Other).unwrap_or(&0)),
                    ("UDP_DNS", *stats.counts.get(&PacketType::UDP_DNS).unwrap_or(&0)),
                    ("DHCP", *stats.counts.get(&PacketType::UDP_DHCP).unwrap_or(&0)),
                    ("UDP_Other", *stats.counts.get(&PacketType::UDP_Other).unwrap_or(&0)),
                    ("ICMP", *stats.counts.get(&PacketType::ICMP).unwrap_or(&0)),
                    ("Other", *stats.counts.get(&PacketType::Other).unwrap_or(&0)),
                ];
                
                // Sort by count (descending) for better visualization
                data.sort_by(|a, b| b.1.cmp(&a.1));
                
                // Limit to top 8 for better display
                if data.len() > 8 {
                    data.truncate(8);
                }
                
                data
            }
        };
        
        // Update block title to show grouping mode
        let title = match app.protocol_grouping {
            ProtocolGrouping::Basic => "Basic Protocol Distribution",
            ProtocolGrouping::Detailed => "Detailed Protocol Distribution (Top 8)",
        };
        
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title);
        
        f.render_widget(block, area);
        
        // Convert data for BarChart (which expects array slices)
        let labels: Vec<&str> = data.iter().map(|(name, _)| *name).collect();
        let values: Vec<u64> = data.iter().map(|(_, count)| *count).collect();
        
        // Create data array slices for BarChart
        let chart_data: Vec<(&str, u64)> = labels.iter()
            .zip(values.iter())
            .map(|(label, value)| (*label, *value))
            .collect();
        
        let barchart = BarChart::default()
            .block(Block::default())
            .data(&chart_data)
            .bar_width(10)
            .bar_gap(3)
            .bar_style(Style::default().fg(Color::Green))
            .value_style(Style::default().bg(Color::Green).fg(Color::Black));
        
        f.render_widget(barchart, inner_area);
    }
}