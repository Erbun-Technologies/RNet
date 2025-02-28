use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::Local;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Device, Capture};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{
        Axis, BarChart, Block, Borders, Cell, Dataset, Paragraph, Row, Table, TableState, Tabs,
    },
};
use sysinfo::{System, Networks};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PacketType {
    TCP_HTTP,    // Port 80
    TCP_HTTPS,   // Port 443
    TCP_SSH,     // Port 22
    TCP_DNS,     // Port 53
    TCP_Other,   // Other TCP ports
    UDP_DNS,     // Port 53
    UDP_DHCP,    // Ports 67, 68
    UDP_Other,   // Other UDP ports
    ICMP,
    Other,
}

// Connection identifier for tracking network flows
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionId {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: PacketType,
}

// Connection statistics
#[derive(Debug, Clone)]
struct ConnectionStats {
    first_seen: Instant,
    last_seen: Instant,
    packet_count: u64,
    byte_count: u64,
}

// Direction of traffic for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionDirection {
    Outbound,
    Inbound,
}

// Options for sorting connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionSort {
    PacketCount,
    ByteCount,
    LastSeen,
    FirstSeen,
}

impl ConnectionSort {
    fn to_string(&self) -> &str {
        match self {
            ConnectionSort::PacketCount => "Packet Count",
            ConnectionSort::ByteCount => "Byte Count",
            ConnectionSort::LastSeen => "Last Seen",
            ConnectionSort::FirstSeen => "First Seen",
        }
    }
    
    fn next(&self) -> Self {
        match self {
            ConnectionSort::PacketCount => ConnectionSort::ByteCount,
            ConnectionSort::ByteCount => ConnectionSort::LastSeen,
            ConnectionSort::LastSeen => ConnectionSort::FirstSeen,
            ConnectionSort::FirstSeen => ConnectionSort::PacketCount,
        }
    }
}

// Options for filtering connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionFilter {
    All,
    Outbound,
    Inbound,
    HTTP,
    HTTPS,
    DNS,
}

impl ConnectionFilter {
    fn to_string(&self) -> &str {
        match self {
            ConnectionFilter::All => "All",
            ConnectionFilter::Outbound => "Outbound",
            ConnectionFilter::Inbound => "Inbound",
            ConnectionFilter::HTTP => "HTTP",
            ConnectionFilter::HTTPS => "HTTPS",
            ConnectionFilter::DNS => "DNS",
        }
    }
    
    fn next(&self) -> Self {
        match self {
            ConnectionFilter::All => ConnectionFilter::Outbound,
            ConnectionFilter::Outbound => ConnectionFilter::Inbound,
            ConnectionFilter::Inbound => ConnectionFilter::HTTP,
            ConnectionFilter::HTTP => ConnectionFilter::HTTPS,
            ConnectionFilter::HTTPS => ConnectionFilter::DNS,
            ConnectionFilter::DNS => ConnectionFilter::All,
        }
    }
}

#[derive(Debug, Clone)]
struct NetworkStats {
    interface_name: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_speed: f64, // bytes per second
    tx_speed: f64, // bytes per second
    last_update: Instant,
}

#[derive(Debug, Clone)]
struct PacketStats {
    counts: HashMap<PacketType, u64>,
    history: Vec<HashMap<PacketType, u64>>,
    last_update: Instant,
}

impl PacketStats {
    fn new() -> Self {
        let mut counts = HashMap::new();
        // TCP categories
        counts.insert(PacketType::TCP_HTTP, 0);
        counts.insert(PacketType::TCP_HTTPS, 0);
        counts.insert(PacketType::TCP_SSH, 0);
        counts.insert(PacketType::TCP_DNS, 0);
        counts.insert(PacketType::TCP_Other, 0);
        // UDP categories
        counts.insert(PacketType::UDP_DNS, 0);
        counts.insert(PacketType::UDP_DHCP, 0);
        counts.insert(PacketType::UDP_Other, 0);
        // Other protocols
        counts.insert(PacketType::ICMP, 0);
        counts.insert(PacketType::Other, 0);

        PacketStats {
            counts,
            history: Vec::new(),
            last_update: Instant::now(),
        }
    }

    fn update_history(&mut self) {
        // Keep last 60 datapoints for a minute of history
        if self.history.len() >= 60 {
            self.history.remove(0);
        }
        self.history.push(self.counts.clone());
        self.last_update = Instant::now();
    }
}

// Display modes for packet graph
enum GraphScale {
    Linear,
    Logarithmic,
}

// Display grouping for protocol types
enum ProtocolGrouping {
    Detailed,   // Show all subcategories
    Basic,      // Show TCP/UDP/ICMP/Other
}

// Basic protocol types for simplified display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BasicProtocolType {
    TCP,
    UDP,
    ICMP,
    Other,
}

// Tab enum for better organization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    PacketGraph,
    PacketDistribution,
    Connections,
}

impl Tab {
    fn to_string(&self) -> &str {
        match self {
            Tab::Overview => "Overview",
            Tab::PacketGraph => "Packet Graph",
            Tab::PacketDistribution => "Packet Distribution",
            Tab::Connections => "Connections",
        }
    }
    
    fn next(&self) -> Self {
        match self {
            Tab::Overview => Tab::PacketGraph,
            Tab::PacketGraph => Tab::PacketDistribution,
            Tab::PacketDistribution => Tab::Connections,
            Tab::Connections => Tab::Overview,
        }
    }
    
    fn prev(&self) -> Self {
        match self {
            Tab::Overview => Tab::Connections,
            Tab::PacketGraph => Tab::Overview,
            Tab::PacketDistribution => Tab::PacketGraph,
            Tab::Connections => Tab::PacketDistribution,
        }
    }
}

struct App {
    system: System,
    networks: Networks,
    network_stats: NetworkStats,
    packet_stats: Arc<Mutex<PacketStats>>,
    connections: Arc<Mutex<HashMap<ConnectionId, ConnectionStats>>>,
    local_networks: Vec<IpRange>,
    running: Arc<AtomicBool>,
    current_tab: Tab,
    // Visualization options
    graph_scale: GraphScale,
    protocol_grouping: ProtocolGrouping,
    show_help: bool,
    connection_sort: ConnectionSort,
    connection_filter: ConnectionFilter,
    connection_scroll: usize,
}

// Helper function to convert detailed packet type to basic category
fn get_basic_type(packet_type: PacketType) -> BasicProtocolType {
    match packet_type {
        // All TCP variants
        PacketType::TCP_HTTP | 
        PacketType::TCP_HTTPS | 
        PacketType::TCP_SSH | 
        PacketType::TCP_DNS | 
        PacketType::TCP_Other => BasicProtocolType::TCP,
        
        // All UDP variants
        PacketType::UDP_DNS | 
        PacketType::UDP_DHCP | 
        PacketType::UDP_Other => BasicProtocolType::UDP,
        
        // Other protocols
        PacketType::ICMP => BasicProtocolType::ICMP,
        PacketType::Other => BasicProtocolType::Other,
    }
}

impl App {
    fn new() -> Result<Self> {
        let system = System::new();
        let networks = Networks::new_with_refreshed_list();
        
        // Default to a common interface name, will be overridden in main
        let interface_name = String::from("en0");
        
        // Get network stats for default interface (this will be updated later)
        let (rx_bytes, tx_bytes) = (0, 0);
        
        let network_stats = NetworkStats {
            interface_name,
            rx_bytes,
            tx_bytes,
            rx_packets: 0,
            tx_packets: 0,
            rx_speed: 0.0,
            tx_speed: 0.0,
            last_update: Instant::now(),
        };

        let packet_stats = Arc::new(Mutex::new(PacketStats::new()));
        let running = Arc::new(AtomicBool::new(true));

        // Initialize with common local network ranges for connection direction detection
        let local_networks = vec![
            IpRange::new([10, 0, 0, 0], 8),    // 10.0.0.0/8
            IpRange::new([172, 16, 0, 0], 12), // 172.16.0.0/12
            IpRange::new([192, 168, 0, 0], 16), // 192.168.0.0/16
            IpRange::new([127, 0, 0, 0], 8),   // 127.0.0.0/8
            IpRange::new([169, 254, 0, 0], 16), // 169.254.0.0/16
        ];
        
        // Create the connections hashmap
        let connections = Arc::new(Mutex::new(HashMap::new()));
        
        Ok(App {
            system,
            networks,
            network_stats,
            packet_stats,
            connections,
            local_networks,
            running,
            current_tab: Tab::Overview,
            // Default visualization options
            graph_scale: GraphScale::Linear,
            protocol_grouping: ProtocolGrouping::Detailed,
            show_help: false,
            connection_sort: ConnectionSort::PacketCount,
            connection_filter: ConnectionFilter::All,
            connection_scroll: 0,
        })
    }

    fn update(&mut self) -> Result<()> {
        self.networks.refresh_list();
        
        let interface_name = &self.network_stats.interface_name;
        
        if let Some(network) = self.networks.get(interface_name) {
            let now = Instant::now();
            let elapsed = now.duration_since(self.network_stats.last_update).as_secs_f64();
            
            let rx_bytes = network.received();
            let tx_bytes = network.transmitted();
            
            // Calculate speeds
            if elapsed > 0.0 {
                if rx_bytes >= self.network_stats.rx_bytes {
                    // Normal case - counter increased
                    self.network_stats.rx_speed = (rx_bytes - self.network_stats.rx_bytes) as f64 / elapsed;
                } else {
                    // Counter reset or wrapped around - use the new value as-is
                    // This assumes the reset value represents the data transferred since reset
                    self.network_stats.rx_speed = rx_bytes as f64 / elapsed;
                    // Don't print debug messages to not interfere with TUI
                }
                
                if tx_bytes >= self.network_stats.tx_bytes {
                    // Normal case - counter increased
                    self.network_stats.tx_speed = (tx_bytes - self.network_stats.tx_bytes) as f64 / elapsed;
                } else {
                    // Counter reset or wrapped around - use the new value as-is
                    // This assumes the reset value represents the data transferred since reset
                    self.network_stats.tx_speed = tx_bytes as f64 / elapsed;
                    // Don't print debug messages to not interfere with TUI
                }
            }
            
            // Update stats
            self.network_stats.rx_bytes = rx_bytes;
            self.network_stats.tx_bytes = tx_bytes;
            self.network_stats.last_update = now;
        }
        
        // Update packet stats history every second
        if let Ok(mut stats) = self.packet_stats.try_lock() {
            let now = Instant::now();
            if now.duration_since(stats.last_update).as_secs() >= 1 {
                stats.update_history();
            }
        }
        
        Ok(())
    }
}

fn start_packet_capture(
    interface_name: String, 
    packet_stats: Arc<Mutex<PacketStats>>,
    connections: Arc<Mutex<HashMap<ConnectionId, ConnectionStats>>>,
    local_networks: Vec<IpRange>,
    running: Arc<AtomicBool>
) -> Result<()> {
    // Find the device with the matching name
    let devices = Device::list()?;
    let device = devices.into_iter()
        .find(|d| d.name == interface_name)
        .context(format!("Failed to find device {}", interface_name))?;
    
    // Create a new capture instance
    let capture_device = Capture::from_device(device)?;
    let capture_device = capture_device.immediate_mode(true);
    let capture_device = capture_device.snaplen(65535);
    
    let mut cap = match capture_device.open() {
        Ok(cap) => cap,
        Err(e) => {
            // Log error but don't stop the app - we'll just run with no packet capture
            eprintln!("Error opening capture device: {}", e);
            return Ok(());
        }
    };
    
    // Start capture thread
    thread::spawn(move || {
        // Track errors so we don't spam the console
        let mut consecutive_errors = 0;
        
        while running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    // Reset error counter on success
                    consecutive_errors = 0;
                    
                    if let Some(ethernet) = EthernetPacket::new(packet.data) {
                        let mut packet_type = PacketType::Other;
                        
                        match ethernet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                    match ipv4.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                                // Classify TCP traffic by port
                                                let src_port = tcp.get_source();
                                                let dst_port = tcp.get_destination();
                                                let src_ip = IpAddr::V4(ipv4.get_source());
                                                let dst_ip = IpAddr::V4(ipv4.get_destination());
                                                
                                                // Check for common services on either source or destination port
                                                if src_port == 80 || dst_port == 80 {
                                                    packet_type = PacketType::TCP_HTTP;
                                                } else if src_port == 443 || dst_port == 443 {
                                                    packet_type = PacketType::TCP_HTTPS;
                                                } else if src_port == 22 || dst_port == 22 {
                                                    packet_type = PacketType::TCP_SSH;
                                                } else if src_port == 53 || dst_port == 53 {
                                                    packet_type = PacketType::TCP_DNS;
                                                } else {
                                                    packet_type = PacketType::TCP_Other;
                                                }
                                                
                                                // Track this connection
                                                if let Ok(mut conns) = connections.try_lock() {
                                                    let now = Instant::now();
                                                    let packet_len = packet.header.len + packet.header.caplen;
                                                    
                                                    // Create connection identifier
                                                    let conn_id = ConnectionId {
                                                        src_ip,
                                                        dst_ip,
                                                        src_port,
                                                        dst_port,
                                                        protocol: packet_type,
                                                    };
                                                    
                                                    // Update or create connection stats
                                                    conns.entry(conn_id)
                                                        .and_modify(|stats| {
                                                            stats.last_seen = now;
                                                            stats.packet_count += 1;
                                                            stats.byte_count += packet_len as u64;
                                                        })
                                                        .or_insert_with(|| ConnectionStats {
                                                            first_seen: now,
                                                            last_seen: now,
                                                            packet_count: 1,
                                                            byte_count: packet_len as u64,
                                                        });
                                                }
                                            }
                                        },
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                // Classify UDP traffic by port
                                                let src_port = udp.get_source();
                                                let dst_port = udp.get_destination();
                                                let src_ip = IpAddr::V4(ipv4.get_source());
                                                let dst_ip = IpAddr::V4(ipv4.get_destination());
                                                
                                                // Check for common services
                                                if src_port == 53 || dst_port == 53 {
                                                    packet_type = PacketType::UDP_DNS;
                                                } else if src_port == 67 || dst_port == 67 || 
                                                          src_port == 68 || dst_port == 68 {
                                                    packet_type = PacketType::UDP_DHCP;
                                                } else {
                                                    packet_type = PacketType::UDP_Other;
                                                }
                                                
                                                // Track this connection
                                                if let Ok(mut conns) = connections.try_lock() {
                                                    let now = Instant::now();
                                                    let packet_len = packet.header.len + packet.header.caplen;
                                                    
                                                    // Create connection identifier
                                                    let conn_id = ConnectionId {
                                                        src_ip,
                                                        dst_ip,
                                                        src_port,
                                                        dst_port,
                                                        protocol: packet_type,
                                                    };
                                                    
                                                    // Update or create connection stats
                                                    conns.entry(conn_id)
                                                        .and_modify(|stats| {
                                                            stats.last_seen = now;
                                                            stats.packet_count += 1;
                                                            stats.byte_count += packet_len as u64;
                                                        })
                                                        .or_insert_with(|| ConnectionStats {
                                                            first_seen: now,
                                                            last_seen: now,
                                                            packet_count: 1,
                                                            byte_count: packet_len as u64,
                                                        });
                                                }
                                            }
                                        },
                                        IpNextHeaderProtocols::Icmp => {
                                            packet_type = PacketType::ICMP;
                                        },
                                        _ => {},
                                    }
                                }
                            },
                            EtherTypes::Ipv6 => {
                                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                                    match ipv6.get_next_header() {
                                        IpNextHeaderProtocols::Tcp => {
                                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                                // Classify TCP traffic by port
                                                let src_port = tcp.get_source();
                                                let dst_port = tcp.get_destination();
                                                
                                                // Check for common services on either source or destination port
                                                if src_port == 80 || dst_port == 80 {
                                                    packet_type = PacketType::TCP_HTTP;
                                                } else if src_port == 443 || dst_port == 443 {
                                                    packet_type = PacketType::TCP_HTTPS;
                                                } else if src_port == 22 || dst_port == 22 {
                                                    packet_type = PacketType::TCP_SSH;
                                                } else if src_port == 53 || dst_port == 53 {
                                                    packet_type = PacketType::TCP_DNS;
                                                } else {
                                                    packet_type = PacketType::TCP_Other;
                                                }
                                            }
                                        },
                                        IpNextHeaderProtocols::Udp => {
                                            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                                // Classify UDP traffic by port
                                                let src_port = udp.get_source();
                                                let dst_port = udp.get_destination();
                                                
                                                // Check for common services
                                                if src_port == 53 || dst_port == 53 {
                                                    packet_type = PacketType::UDP_DNS;
                                                } else if src_port == 67 || dst_port == 67 || 
                                                          src_port == 68 || dst_port == 68 {
                                                    packet_type = PacketType::UDP_DHCP;
                                                } else {
                                                    packet_type = PacketType::UDP_Other;
                                                }
                                            }
                                        },
                                        IpNextHeaderProtocols::Icmpv6 => {
                                            packet_type = PacketType::ICMP;
                                        },
                                        _ => {},
                                    }
                                }
                            },
                            _ => {},
                        }
                        
                        // Update packet counts - use try_lock to avoid blocking UI
                        if let Ok(mut stats) = packet_stats.try_lock() {
                            *stats.counts.entry(packet_type).or_insert(0) += 1;
                        }
                    }
                },
                Err(_) => {
                    consecutive_errors += 1;
                    
                    // Only log every 100th error to avoid flooding
                    if consecutive_errors == 1 || consecutive_errors % 100 == 0 {
                        // Don't use println in a TUI app - errors will mess up the display
                        // Just sleep and continue
                    }
                    
                    // Sleep to avoid spinning CPU on repeated errors
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });
    
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
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

fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
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

fn draw_network_overview(f: &mut Frame, app: &App, area: Rect) {
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
            ProtocolGrouping::Basic => {
                // Group by basic categories
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
                
                format!(
                    "TCP: {} | UDP: {} | ICMP: {} | Other: {}", 
                    tcp_count, udp_count, icmp_count, other_count
                )
            },
            ProtocolGrouping::Detailed => {
                // Show detailed breakdown
                let http_count = *stats.counts.get(&PacketType::TCP_HTTP).unwrap_or(&0);
                let https_count = *stats.counts.get(&PacketType::TCP_HTTPS).unwrap_or(&0);
                let ssh_count = *stats.counts.get(&PacketType::TCP_SSH).unwrap_or(&0);
                let tcp_dns_count = *stats.counts.get(&PacketType::TCP_DNS).unwrap_or(&0);
                let tcp_other_count = *stats.counts.get(&PacketType::TCP_Other).unwrap_or(&0);
                
                let udp_dns_count = *stats.counts.get(&PacketType::UDP_DNS).unwrap_or(&0);
                let dhcp_count = *stats.counts.get(&PacketType::UDP_DHCP).unwrap_or(&0);
                let udp_other_count = *stats.counts.get(&PacketType::UDP_Other).unwrap_or(&0);
                
                let tcp_total = http_count + https_count + ssh_count + tcp_dns_count + tcp_other_count;
                let udp_total = udp_dns_count + dhcp_count + udp_other_count;
                
                format!(
                    "TCP({}) HTTP:{} HTTPS:{} SSH:{} DNS:{} Other:{} | UDP({}) DNS:{} DHCP:{} Other:{} | ICMP:{} | Other:{}", 
                    tcp_total, http_count, https_count, ssh_count, tcp_dns_count, tcp_other_count,
                    udp_total, udp_dns_count, dhcp_count, udp_other_count,
                    *stats.counts.get(&PacketType::ICMP).unwrap_or(&0),
                    *stats.counts.get(&PacketType::Other).unwrap_or(&0)
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

fn draw_packet_graph(f: &mut Frame, app: &App, area: Rect) {
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

fn draw_packet_bar_chart(f: &mut Frame, app: &App, area: Rect) {
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

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    // Create a centered box for the help
    let help_area = centered_rect(60, 60, area);
    
    // Clear the area first
    f.render_widget(
        ratatui::widgets::Clear,
        help_area
    );
    
    // Create help content
    let help_text = "
Keyboard Shortcuts

q: Quit the application
←/→: Navigate between tabs
l: Toggle between Linear and Logarithmic scale
g: Toggle between Basic and Detailed protocol view
h: Show/hide this help

----- Connections Tab Shortcuts -----
s: Change sorting (Packets, Bytes, Age, First Seen)
f: Filter connections (All, Outbound, Inbound, HTTP, HTTPS, DNS)
↑/↓: Navigate connections list
PgUp/PgDn: Page up/down in connections list

Press any key to close this help
";
    
    // Create help paragraph
    let help = Paragraph::new(help_text)
        .block(Block::default().title("Help").borders(Borders::ALL))
        .alignment(Alignment::Center)
        .wrap(ratatui::widgets::Wrap { trim: true });
    
    // Render help
    f.render_widget(help, help_area);
}

// Simplified network range for checking if an IP is local
#[derive(Debug, Clone)]
struct IpRange {
    base: [u8; 4],
    mask: [u8; 4],
}

impl IpRange {
    fn new(base: [u8; 4], prefix: u8) -> Self {
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
    
    fn contains(&self, ip: &IpAddr) -> bool {
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
fn is_local_ip(ip: IpAddr, local_networks: &[IpRange]) -> bool {
    local_networks.iter().any(|net| net.contains(&ip))
}

// Helper function to determine the direction of a connection
fn get_connection_direction(src_ip: IpAddr, dst_ip: IpAddr, local_networks: &[IpRange]) -> ConnectionDirection {
    let src_is_local = is_local_ip(src_ip, local_networks);
    let dst_is_local = is_local_ip(dst_ip, local_networks);
    
    // If source is local and destination is not, it's outbound
    if src_is_local && !dst_is_local {
        ConnectionDirection::Outbound
    } else {
        // Otherwise consider it inbound (includes local to local)
        ConnectionDirection::Inbound
    }
}

// Helper function to format time duration
fn format_duration(duration: Duration) -> String {
    if duration.as_secs() < 60 {
        format!("{}s", duration.as_secs())
    } else if duration.as_secs() < 3600 {
        format!("{}m {}s", duration.as_secs() / 60, duration.as_secs() % 60)
    } else {
        format!("{}h {}m", duration.as_secs() / 3600, (duration.as_secs() % 3600) / 60)
    }
}

// Function to draw the connections tab
fn draw_connections(f: &mut Frame, app: &App, area: Rect) {
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
        let mut connections: Vec<(&ConnectionId, &ConnectionStats)> = conns.iter().collect();
        
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
            ConnectionSort::PacketCount => {
                connections.sort_by(|(_, a), (_, b)| b.packet_count.cmp(&a.packet_count));
            },
            ConnectionSort::ByteCount => {
                connections.sort_by(|(_, a), (_, b)| b.byte_count.cmp(&a.byte_count));
            },
            ConnectionSort::LastSeen => {
                connections.sort_by(|(_, a), (_, b)| b.last_seen.cmp(&a.last_seen));
            },
            ConnectionSort::FirstSeen => {
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

// Helper to create centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

fn draw_ui(f: &mut Frame, app: &App) {
    // Clear the entire frame first to prevent artifacts
    f.render_widget(
        ratatui::widgets::Clear,
        f.size()
    );
    
    // Create the layout
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(f.size());
    
    // Tabs
    let titles = vec![
        Tab::Overview.to_string(),
        Tab::PacketGraph.to_string(),
        Tab::PacketDistribution.to_string(),
        Tab::Connections.to_string(),
    ];
    
    let selected_index = match app.current_tab {
        Tab::Overview => 0,
        Tab::PacketGraph => 1,
        Tab::PacketDistribution => 2,
        Tab::Connections => 3,
    };
    
    let tabs = Tabs::new(titles)
        .block(Block::default().title("Network Dashboard").borders(Borders::ALL))
        .select(selected_index)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow));
    f.render_widget(tabs, main_chunks[0]);
    
    // Clear the content area to prevent artifacts when switching tabs
    f.render_widget(
        ratatui::widgets::Clear,
        main_chunks[1]
    );
    
    // Content based on selected tab
    match app.current_tab {
        Tab::Overview => draw_network_overview(f, app, main_chunks[1]),
        Tab::PacketGraph => draw_packet_graph(f, app, main_chunks[1]),
        Tab::PacketDistribution => draw_packet_bar_chart(f, app, main_chunks[1]),
        Tab::Connections => draw_connections(f, app, main_chunks[1]),
    }
    
    // Draw help overlay if enabled
    if app.show_help {
        draw_help_overlay(f, f.size());
    }
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()> {
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();
    
    loop {
        terminal.draw(|f| draw_ui(f, &app))?;
        
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // If help is showing, any key closes it
                if app.show_help {
                    app.show_help = false;
                } else {
                    match key.code {
                        KeyCode::Char('q') => {
                            app.running.store(false, Ordering::Relaxed);
                            return Ok(());
                        },
                        KeyCode::Left => {
                            app.current_tab = app.current_tab.prev();
                        },
                        KeyCode::Right => {
                            app.current_tab = app.current_tab.next();
                        },
                        // Toggle logarithmic scale with 'l'
                        KeyCode::Char('l') => {
                            app.graph_scale = match app.graph_scale {
                                GraphScale::Linear => GraphScale::Logarithmic,
                                GraphScale::Logarithmic => GraphScale::Linear,
                            };
                        },
                        // Toggle protocol grouping with 'g'
                        KeyCode::Char('g') => {
                            app.protocol_grouping = match app.protocol_grouping {
                                ProtocolGrouping::Basic => ProtocolGrouping::Detailed,
                                ProtocolGrouping::Detailed => ProtocolGrouping::Basic,
                            };
                        },
                        // Display help with 'h'
                        KeyCode::Char('h') => {
                            app.show_help = true;
                        },
                        // Sort connections with 's' (when on Connections tab)
                        KeyCode::Char('s') => {
                            if app.current_tab == Tab::Connections {
                                app.connection_sort = app.connection_sort.next();
                            }
                        },
                        // Filter connections with 'f' (when on Connections tab)
                        KeyCode::Char('f') => {
                            if app.current_tab == Tab::Connections {
                                app.connection_filter = app.connection_filter.next();
                            }
                        },
                        // Scroll through connections list
                        KeyCode::Up => {
                            if app.current_tab == Tab::Connections && app.connection_scroll > 0 {
                                app.connection_scroll -= 1;
                            }
                        },
                        KeyCode::Down => {
                            if app.current_tab == Tab::Connections {
                                app.connection_scroll += 1;
                            }
                        },
                        KeyCode::PageUp => {
                            if app.current_tab == Tab::Connections && app.connection_scroll >= 10 {
                                app.connection_scroll -= 10;
                            } else if app.current_tab == Tab::Connections {
                                app.connection_scroll = 0;
                            }
                        },
                        KeyCode::PageDown => {
                            if app.current_tab == Tab::Connections {
                                app.connection_scroll += 10;
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
        
        if last_tick.elapsed() >= tick_rate {
            app.update().unwrap_or_else(|err| eprintln!("Error updating app: {}", err));
            last_tick = Instant::now();
        }
    }
}

// Function to get user-selected network interface
fn select_network_interface() -> Result<String> {
    let networks = Networks::new_with_refreshed_list();
    
    // Collect available interfaces
    let mut interface_names: Vec<String> = networks.iter()
        .map(|(name, _)| name.clone())
        .collect();
    
    // Sort by name for easier selection
    interface_names.sort();
    
    // Display the menu of available interfaces
    println!("Available network interfaces:");
    for (idx, name) in interface_names.iter().enumerate() {
        if let Some(network) = networks.get(name) {
            println!("  [{}] {} - RX: {}, TX: {}", 
                idx, name, network.received(), network.transmitted());
        } else {
            println!("  [{}] {}", idx, name);
        }
    }
    
    // Prompt for user selection
    println!("\nEnter the number of the interface to monitor:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    // Parse the input
    let selected_idx = match input.trim().parse::<usize>() {
        Ok(idx) if idx < interface_names.len() => idx,
        _ => {
            println!("Invalid selection, using first interface");
            0
        }
    };
    
    let interface_name = interface_names[selected_idx].clone();
    println!("Selected network interface: {}", interface_name);
    
    // Wait a moment for user to see the selection
    thread::sleep(Duration::from_millis(1000));
    
    Ok(interface_name)
}

fn main() -> Result<()> {
    // Select the network interface first, before setting up the UI
    let selected_interface = select_network_interface()?;
    
    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create app with the selected interface
    let mut app = App::new()?;
    
    // Set up the network stats with the selected interface
    let networks = Networks::new_with_refreshed_list();
    app.network_stats.interface_name = selected_interface;
    
    // Update initial stats for the selected interface
    if let Some(network) = networks.get(&app.network_stats.interface_name) {
        app.network_stats.rx_bytes = network.received();
        app.network_stats.tx_bytes = network.transmitted();
    } else {
        eprintln!("Warning: Could not get initial stats for selected interface");
    }
    
    // Start packet capture
    let interface_name = app.network_stats.interface_name.clone();
    let packet_stats = app.packet_stats.clone();
    let connections = app.connections.clone();
    let local_networks = app.local_networks.clone();
    let running = app.running.clone();
    start_packet_capture(interface_name, packet_stats, connections, local_networks, running)?;
    
    // Run the app
    let res = run_app(&mut terminal, app);
    
    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    
    if let Err(err) = res {
        println!("Error: {:?}", err);
    }
    
    Ok(())
}