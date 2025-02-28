use ratatui::{
    prelude::*,
    style::{Color, Style},
    widgets::{Axis, Block, Borders, Dataset, Paragraph},
    symbols,
};

use crate::app::App;
use crate::network::types::{BasicProtocolType, GraphScale, PacketType, ProtocolGrouping, get_basic_type};

pub fn draw_packet_graph(f: &mut Frame, app: &mut App, area: Rect) {
    // Create title with scale and grouping info
    let scale_text = match app.graph_scale {
        GraphScale::Linear => "Linear Scale",
        GraphScale::Logarithmic => "Log Scale",
    };
    
    let group_text = match app.protocol_grouping {
        ProtocolGrouping::Basic => "Basic Groups",
        ProtocolGrouping::Detailed => "Detailed View",
    };
    
    let title = format!("Network Traffic ({}, {})", group_text, scale_text);
    
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title);
    
    let inner_area = block.inner(area);
    f.render_widget(block, area);
    
    if let Ok(stats) = app.packet_stats.try_lock() {
        if stats.history.len() < 2 {
            // Not enough data yet
            let message = Paragraph::new("Collecting data...")
                .alignment(Alignment::Center);
            f.render_widget(message, inner_area);
            return;
        }
        
        // Get data for the graph
        let max_points = inner_area.width as usize - 2;
        let history_len = stats.history.len();
        let start_idx = if history_len <= max_points {
            0
        } else {
            history_len - max_points
        };
        let data_len = if history_len <= max_points {
            history_len
        } else {
            max_points
        };
        
        // Prepare datasets based on the chosen protocol grouping
        let datasets_data: Vec<(String, Color, Vec<(f64, f64)>)> = match app.protocol_grouping {
            ProtocolGrouping::Basic => {
                // Basic grouping - combine by protocol type
                let mut tcp_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_len];
                let mut udp_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_len];
                let mut icmp_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_len];
                let mut other_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_len];
                
                // Combine data from all TCP, UDP, etc.
                for i in 0..data_len {
                    let idx = start_idx + i;
                    
                    // Initialize with x-coordinate
                    tcp_data[i].0 = i as f64;
                    udp_data[i].0 = i as f64;
                    icmp_data[i].0 = i as f64;
                    other_data[i].0 = i as f64;
                    
                    // Aggregate counts by basic type
                    for (packet_type, count) in stats.history[idx].iter() {
                        match get_basic_type(*packet_type) {
                            BasicProtocolType::TCP => tcp_data[i].1 += *count as f64,
                            BasicProtocolType::UDP => udp_data[i].1 += *count as f64,
                            BasicProtocolType::ICMP => icmp_data[i].1 += *count as f64,
                            BasicProtocolType::Other => other_data[i].1 += *count as f64,
                        }
                    }
                }
                
                // Apply logarithmic scale if selected
                if matches!(app.graph_scale, GraphScale::Logarithmic) {
                    for i in 0..data_len {
                        // Add 1 to avoid ln(0) which is undefined
                        tcp_data[i].1 = (tcp_data[i].1 + 1.0).ln();
                        udp_data[i].1 = (udp_data[i].1 + 1.0).ln();
                        icmp_data[i].1 = (icmp_data[i].1 + 1.0).ln();
                        other_data[i].1 = (other_data[i].1 + 1.0).ln();
                    }
                }
                
                vec![
                    ("TCP".to_string(), Color::LightRed, tcp_data),
                    ("UDP".to_string(), Color::LightGreen, udp_data),
                    ("ICMP".to_string(), Color::LightBlue, icmp_data),
                    ("Other".to_string(), Color::LightYellow, other_data),
                ]
            },
            ProtocolGrouping::Detailed => {
                // Detailed view - show all protocol types
                let packet_types = [
                    (PacketType::TCP_HTTP, "HTTP", Color::Red),
                    (PacketType::TCP_HTTPS, "HTTPS", Color::LightRed),
                    (PacketType::TCP_SSH, "SSH", Color::LightMagenta),
                    (PacketType::TCP_DNS, "TCP-DNS", Color::LightCyan),
                    (PacketType::TCP_Other, "TCP-Other", Color::DarkGray),
                    (PacketType::UDP_DNS, "UDP-DNS", Color::Green),
                    (PacketType::UDP_DHCP, "DHCP", Color::LightGreen),
                    (PacketType::UDP_Other, "UDP-Other", Color::Cyan),
                    (PacketType::ICMP, "ICMP", Color::Blue),
                    (PacketType::Other, "Other", Color::Yellow),
                ];
                
                let mut result = Vec::new();
                
                for (packet_type, name, color) in packet_types.iter() {
                    let mut data: Vec<(f64, f64)> = (0..data_len)
                        .map(|i| {
                            let idx = start_idx + i;
                            let count = stats.history[idx].get(packet_type).unwrap_or(&0);
                            (i as f64, *count as f64)
                        })
                        .collect();
                        
                    // Apply logarithmic scale if selected
                    if matches!(app.graph_scale, GraphScale::Logarithmic) {
                        for point in data.iter_mut() {
                            // Add 1 to avoid ln(0) which is undefined
                            point.1 = (point.1 + 1.0).ln();
                        }
                    }
                    
                    result.push((name.to_string(), *color, data));
                }
                
                result
            }
        };
        
        // Find max Y value for scaling
        let max_y = datasets_data.iter()
            .flat_map(|(_, _, data)| data.iter().map(|(_, y)| *y))
            .fold(1.0, |max, y| if y > max { y } else { max });
        
        // Create the datasets
        let datasets: Vec<Dataset> = datasets_data.iter()
            .map(|(name, color, data)| {
                Dataset::default()
                    .name(name.as_str()) // Use &str instead of &String
                    .marker(symbols::Marker::Braille)
                    .graph_type(ratatui::widgets::GraphType::Line)
                    .style(Style::default().fg(*color))
                    .data(data)
            })
            .collect();
        
        // Y-axis title based on scale
        let y_title = match app.graph_scale {
            GraphScale::Linear => "Packets",
            GraphScale::Logarithmic => "Packets (ln)",
        };
        
        // Create the chart with legend
        let chart = ratatui::widgets::Chart::new(datasets)
            .x_axis(
                Axis::default()
                    .title("Time (s)")
                    .style(Style::default().fg(Color::Gray))
                    .bounds([0.0, data_len as f64])
                    .labels(vec![Span::from("0"), Span::from(data_len.to_string())])
            )
            .y_axis(
                Axis::default()
                    .title(y_title)
                    .style(Style::default().fg(Color::Gray))
                    .bounds([0.0, max_y])
                    .labels(vec![Span::from("0"), Span::from(format!("{:.1}", max_y))])
            )
            // Add a prominent legend
            .legend_position(Some(ratatui::widgets::LegendPosition::Top));
        
        f.render_widget(chart, inner_area);
    }
}