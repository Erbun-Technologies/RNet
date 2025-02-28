use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use anyhow::Result;
use sysinfo::{System, Networks};

use crate::network::types::*;
use crate::utils::IpRange;

pub struct App {
    pub system: System,
    pub networks: Networks,
    pub network_stats: NetworkStats,
    pub packet_stats: Arc<Mutex<PacketStats>>,
    pub connections: Arc<Mutex<HashMap<ConnectionId, ConnectionStats>>>,
    pub geo_stats: Arc<Mutex<GeoStats>>,
    pub local_networks: Vec<IpRange>,
    pub running: Arc<AtomicBool>,
    pub current_tab: Tab,
    // Visualization options
    pub graph_scale: GraphScale,
    pub protocol_grouping: ProtocolGrouping,
    pub show_help: bool,
    pub connection_sort: ConnectionSort,
    pub connection_filter: ConnectionFilter,
    pub connection_scroll: usize,
    pub geo_mode: GeoMode,
    pub geo_country_selection: usize,
}

impl App {
    pub fn new() -> Result<Self> {
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
        
        // Create geo stats
        let geo_stats = Arc::new(Mutex::new(GeoStats::new()));
        
        Ok(App {
            system,
            networks,
            network_stats,
            packet_stats,
            connections,
            geo_stats,
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
            geo_mode: GeoMode::CountryList,
            geo_country_selection: 0,
        })
    }

    pub fn update(&mut self) -> Result<()> {
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