use std::time::Instant;

use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

use crate::app::App;
use crate::network::types::{ConnectionFilter, ConnectionDirection, PacketType};
use crate::utils::{format_bytes, format_duration, centered_rect};
use crate::network::capture::get_connection_direction;

pub fn draw_connections(f: &mut Frame, app: &mut App, area: Rect) {
    // Create a layout with header and body
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header with controls
            Constraint::Min(0),    // Connections list
        ])
        .split(area);
    
    // Create header showing current sort and filter
    let header_text = format!(
        "Sort: {} | Filter: {} | Use s/f to change | Arrow keys to navigate",
        app.connection_sort.to_string(),
        app.connection_filter.to_string()
    );
    
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title("Connection Controls"))
        .alignment(Alignment::Center);
    
    f.render_widget(header, chunks[0]);
    
    // Get the connections
    if let Ok(conns) = app.connections.try_lock() {
        // Create a copy for sorting and filtering
        let mut connections: Vec<(&crate::network::types::ConnectionId, &crate::network::types::ConnectionStats)> = conns.iter().collect();
        
        // Filter connections
        connections = match app.connection_filter {
            ConnectionFilter::All => connections,
            ConnectionFilter::Outbound => connections.into_iter()
                .filter(|(id, _)| {
                    get_connection_direction(id.src_ip, id.dst_ip, &app.local_networks) == ConnectionDirection::Outbound
                })
                .collect(),
            ConnectionFilter::Inbound => connections.into_iter()
                .filter(|(id, _)| {
                    get_connection_direction(id.src_ip, id.dst_ip, &app.local_networks) == ConnectionDirection::Inbound
                })
                .collect(),
            ConnectionFilter::HTTP => connections.into_iter()
                .filter(|(id, _)| id.protocol == PacketType::TCP_HTTP)
                .collect(),
            ConnectionFilter::HTTPS => connections.into_iter()
                .filter(|(id, _)| id.protocol == PacketType::TCP_HTTPS)
                .collect(),
            ConnectionFilter::DNS => connections.into_iter()
                .filter(|(id, _)| id.protocol == PacketType::UDP_DNS || id.protocol == PacketType::TCP_DNS)
                .collect(),
        };
        
        // Sort connections
        match app.connection_sort {
            crate::network::types::ConnectionSort::PacketCount => {
                connections.sort_by(|(_, a), (_, b)| b.packet_count.cmp(&a.packet_count));
            },
            crate::network::types::ConnectionSort::ByteCount => {
                connections.sort_by(|(_, a), (_, b)| b.byte_count.cmp(&a.byte_count));
            },
            crate::network::types::ConnectionSort::LastSeen => {
                connections.sort_by(|(_, a), (_, b)| b.last_seen.cmp(&a.last_seen));
            },
            crate::network::types::ConnectionSort::FirstSeen => {
                connections.sort_by(|(_, a), (_, b)| a.first_seen.cmp(&b.first_seen));
            },
        }
        
        // Create connection table
        let table_state = TableState::default().with_selected(Some(app.connection_scroll.min(connections.len().saturating_sub(1))));
        
        // Prepare connection rows
        let now = Instant::now();
        let rows = connections.iter().map(|(id, stats)| {
            let direction = match get_connection_direction(id.src_ip, id.dst_ip, &app.local_networks) {
                ConnectionDirection::Outbound => "OUT",
                ConnectionDirection::Inbound => "IN",
            };
            
            let proto = match id.protocol {
                PacketType::TCP_HTTP => "HTTP",
                PacketType::TCP_HTTPS => "HTTPS",
                PacketType::TCP_SSH => "SSH",
                PacketType::TCP_DNS => "TCP-DNS",
                PacketType::TCP_Other => "TCP",
                PacketType::UDP_DNS => "UDP-DNS",
                PacketType::UDP_DHCP => "DHCP",
                PacketType::UDP_Other => "UDP",
                PacketType::ICMP => "ICMP",
                PacketType::Other => "OTHER",
            };
            
            let age = format_duration(now.duration_since(stats.first_seen));
            let last_seen = format_duration(now.duration_since(stats.last_seen));
            let bytes = format_bytes(stats.byte_count);
            
            Row::new(vec![
                Cell::from(direction),
                Cell::from(proto),
                Cell::from(id.src_ip.to_string()),
                Cell::from(id.dst_ip.to_string()),
                Cell::from(format!("{}:{}", id.src_port, id.dst_port)),
                Cell::from(format!("{}", stats.packet_count)),
                Cell::from(bytes),
                Cell::from(age),
                Cell::from(last_seen),
            ])
        }).collect::<Vec<_>>();
        
        // Define the column widths
        let widths = [
            Constraint::Length(4),  // Direction
            Constraint::Length(8),  // Protocol
            Constraint::Length(15), // Source IP
            Constraint::Length(15), // Dest IP
            Constraint::Length(11), // Ports
            Constraint::Length(8),  // Packets
            Constraint::Length(10), // Bytes
            Constraint::Length(8),  // Age
            Constraint::Length(10), // Last Seen
        ];

        // Create the table
        let table = Table::new(rows, widths)
            .header(Row::new(vec![
                Cell::from("Dir"),
                Cell::from("Proto"),
                Cell::from("Source IP"),
                Cell::from("Dest IP"),
                Cell::from("Ports"),
                Cell::from("Packets"),
                Cell::from("Bytes"),
                Cell::from("Age"),
                Cell::from("Last Seen"),
            ]).style(Style::default().fg(Color::Yellow)))
            .block(Block::default().borders(Borders::ALL).title(format!("Connections ({})", connections.len())))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        
        f.render_stateful_widget(table, chunks[1], &mut table_state.clone());
        
        // Show message if no connections
        if connections.is_empty() {
            let message = Paragraph::new("No connections matching current filter...")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));
                
            let message_area = centered_rect(60, 20, chunks[1]);
            f.render_widget(message, message_area);
        }
    } else {
        // Could not get lock on connections
        let message = Paragraph::new("Could not access connection data...")
            .alignment(Alignment::Center);
        f.render_widget(message, chunks[1]);
    }
}