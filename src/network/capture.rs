use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
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

use crate::utils::is_local_ip;
use super::types::*;

// Simple IP to geo lookup that returns country code and coordinates
// In a real application, this would use a GeoIP database
pub fn lookup_ip_location(ip: IpAddr) -> Option<GeoLocation> {
    // If it's a local IP, don't attempt geolocation
    if crate::utils::is_loopback_ip(ip) || crate::utils::is_private_ip(ip) {
        return None;
    }
    
    // For demonstration, we'll use a simplistic approach:
    // Assign locations based on IP range
    // This is for simulation only!
    let octets = match ip {
        IpAddr::V4(ipv4) => ipv4.octets(),
        IpAddr::V6(_) => return None, // Skip IPv6 for simplicity
    };
    
    // Extremely simplified classification based on first octet
    // This is NOT accurate, just for demonstration!
    match octets[0] {
        0..=49 => Some(GeoLocation {
            country: "US".to_string(),
            region: "North America".to_string(),
            latitude: 37.0902,
            longitude: -95.7129,
        }),
        50..=99 => Some(GeoLocation {
            country: "EU".to_string(),
            region: "Europe".to_string(),
            latitude: 54.5260,
            longitude: 15.2551,
        }),
        100..=149 => Some(GeoLocation {
            country: "CN".to_string(),
            region: "Asia".to_string(),
            latitude: 35.8617,
            longitude: 104.1954,
        }),
        150..=199 => Some(GeoLocation {
            country: "AU".to_string(),
            region: "Oceania".to_string(),
            latitude: -25.2744,
            longitude: 133.7751,
        }),
        _ => Some(GeoLocation {
            country: "BR".to_string(),
            region: "South America".to_string(),
            latitude: -14.2350,
            longitude: -51.9253,
        }),
    }
}

// Helper function to determine the direction of a connection
pub fn get_connection_direction(src_ip: IpAddr, dst_ip: IpAddr, local_networks: &[crate::utils::IpRange]) -> ConnectionDirection {
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

pub fn start_packet_capture(
    interface_name: String, 
    packet_stats: Arc<Mutex<PacketStats>>,
    connections: Arc<Mutex<HashMap<ConnectionId, ConnectionStats>>>,
    geo_stats: Arc<Mutex<GeoStats>>,
    local_networks: Vec<crate::utils::IpRange>,
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
                                                
                                                // Track geographic location
                                                if let Ok(mut geo) = geo_stats.try_lock() {
                                                    // For outbound connections, track the destination
                                                    let target_ip = if is_local_ip(src_ip, &local_networks) {
                                                        dst_ip
                                                    } else {
                                                        src_ip
                                                    };
                                                    
                                                    // Try to get location
                                                    if let Some(location) = lookup_ip_location(target_ip) {
                                                        // Update country stats
                                                        geo.locations.entry(location.country.clone())
                                                            .and_modify(|(_, count)| {
                                                                *count += 1;
                                                            })
                                                            .or_insert_with(|| (location, 1));
                                                            
                                                        // Update top country
                                                        geo.update_top_country();
                                                    }
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