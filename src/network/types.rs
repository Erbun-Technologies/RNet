use std::{
    net::IpAddr,
    time::Instant,
    collections::HashMap
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
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
pub struct ConnectionId {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: PacketType,
}

// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub packet_count: u64,
    pub byte_count: u64,
}

// Direction of traffic for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Outbound,
    Inbound,
}

// Options for sorting connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSort {
    PacketCount,
    ByteCount,
    LastSeen,
    FirstSeen,
}

impl ConnectionSort {
    pub fn to_string(&self) -> &str {
        match self {
            ConnectionSort::PacketCount => "Packet Count",
            ConnectionSort::ByteCount => "Byte Count",
            ConnectionSort::LastSeen => "Last Seen",
            ConnectionSort::FirstSeen => "First Seen",
        }
    }
    
    pub fn next(&self) -> Self {
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
pub enum ConnectionFilter {
    All,
    Outbound,
    Inbound,
    HTTP,
    HTTPS,
    DNS,
}

impl ConnectionFilter {
    pub fn to_string(&self) -> &str {
        match self {
            ConnectionFilter::All => "All",
            ConnectionFilter::Outbound => "Outbound",
            ConnectionFilter::Inbound => "Inbound",
            ConnectionFilter::HTTP => "HTTP",
            ConnectionFilter::HTTPS => "HTTPS",
            ConnectionFilter::DNS => "DNS",
        }
    }
    
    pub fn next(&self) -> Self {
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

// Options for displaying geographical data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoMode {
    CountryList,   // List of countries with traffic counts
    WorldMap,      // Text-based world map approximation
}

impl GeoMode {
    pub fn to_string(&self) -> &str {
        match self {
            GeoMode::CountryList => "Country List",
            GeoMode::WorldMap => "World Map",
        }
    }
    
    pub fn next(&self) -> Self {
        match self {
            GeoMode::CountryList => GeoMode::WorldMap,
            GeoMode::WorldMap => GeoMode::CountryList,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub interface_name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_speed: f64, // bytes per second
    pub tx_speed: f64, // bytes per second
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct PacketStats {
    pub counts: HashMap<PacketType, u64>,
    pub history: Vec<HashMap<PacketType, u64>>,
    pub last_update: Instant,
}

impl PacketStats {
    pub fn new() -> Self {
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

    pub fn update_history(&mut self) {
        // Keep last 60 datapoints for a minute of history
        if self.history.len() >= 60 {
            self.history.remove(0);
        }
        self.history.push(self.counts.clone());
        self.last_update = Instant::now();
    }
}

// Display modes for packet graph
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphScale {
    Linear,
    Logarithmic,
}

// Display grouping for protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolGrouping {
    Detailed,   // Show all subcategories
    Basic,      // Show TCP/UDP/ICMP/Other
}

// Basic protocol types for simplified display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BasicProtocolType {
    TCP,
    UDP,
    ICMP,
    Other,
}

// Tab enum for better organization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    PacketGraph,
    PacketDistribution,
    Connections,
    GeoMap,
}

impl Tab {
    pub fn to_string(&self) -> &str {
        match self {
            Tab::Overview => "Overview",
            Tab::PacketGraph => "Packet Graph",
            Tab::PacketDistribution => "Packet Distribution",
            Tab::Connections => "Connections",
            Tab::GeoMap => "Geo Map",
        }
    }
    
    pub fn next(&self) -> Self {
        match self {
            Tab::Overview => Tab::PacketGraph,
            Tab::PacketGraph => Tab::PacketDistribution,
            Tab::PacketDistribution => Tab::Connections,
            Tab::Connections => Tab::GeoMap,
            Tab::GeoMap => Tab::Overview,
        }
    }
    
    pub fn prev(&self) -> Self {
        match self {
            Tab::Overview => Tab::GeoMap,
            Tab::PacketGraph => Tab::Overview,
            Tab::PacketDistribution => Tab::PacketGraph,
            Tab::Connections => Tab::PacketDistribution,
            Tab::GeoMap => Tab::Connections,
        }
    }
}

// Simple structure to store geographic location info
#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country: String,
    pub region: String,
    pub latitude: f64,
    pub longitude: f64,
}

// Structure to store location visualization stats
#[derive(Debug, Clone)]
pub struct GeoStats {
    pub locations: HashMap<String, (GeoLocation, u64)>, // Country code -> (location, packet count)
    pub total_countries: usize,
    pub top_country: Option<String>,
    pub timestamp: Instant,
}

impl GeoStats {
    pub fn new() -> Self {
        GeoStats {
            locations: HashMap::new(),
            total_countries: 0,
            top_country: None,
            timestamp: Instant::now(),
        }
    }
    
    pub fn update_top_country(&mut self) {
        self.top_country = self.locations.iter()
            .max_by_key(|(_, (_, count))| *count)
            .map(|(country, _)| country.clone());
            
        self.total_countries = self.locations.len();
    }
}

// Helper function to convert detailed packet type to basic category
pub fn get_basic_type(packet_type: PacketType) -> BasicProtocolType {
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