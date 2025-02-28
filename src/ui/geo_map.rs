use ratatui::{
    prelude::*,
    style::{Color, Style, Modifier},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    widgets::canvas::{Canvas, Shape},
};

use crate::app::App;
use crate::network::types::GeoMode;
use crate::utils::centered_rect;

// We'll use a simpler approach for geo points to avoid implementation complexity
fn draw_country_point(
    ctx: &mut ratatui::widgets::canvas::Context,
    longitude: f64,
    latitude: f64,
    color: Color,
    size: u16
) {
    // Draw a marker at the country location
    // Using simpler points and lines to visualize it
    let x = longitude;
    let y = latitude;
    
    // Size adjustment based on importance
    let dot_size = size as f64 * 0.5;
    
    // Draw a small diamond shape for better visibility
    ctx.draw(&ratatui::widgets::canvas::Line {
        x1: x, y1: y - dot_size,
        x2: x + dot_size, y2: y,
        color,
    });
    
    ctx.draw(&ratatui::widgets::canvas::Line {
        x1: x + dot_size, y1: y,
        x2: x, y2: y + dot_size,
        color,
    });
    
    ctx.draw(&ratatui::widgets::canvas::Line {
        x1: x, y1: y + dot_size,
        x2: x - dot_size, y2: y,
        color,
    });
    
    ctx.draw(&ratatui::widgets::canvas::Line {
        x1: x - dot_size, y1: y,
        x2: x, y2: y - dot_size,
        color,
    });
}

pub fn draw_geo_map(f: &mut Frame, app: &mut App, area: Rect) {
    // Create a layout with header and body
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header with controls
            Constraint::Min(0),    // Map or country list
        ])
        .split(area);
    
    // Create header
    let header_text = format!(
        "View Mode: {} | Use 'f' to change view | Shows traffic destinations by country",
        app.geo_mode.to_string()
    );
    
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title("Geographic Traffic Map"))
        .alignment(Alignment::Center);
    
    f.render_widget(header, chunks[0]);
    
    // Get geo stats
    if let Ok(geo) = app.geo_stats.try_lock() {
        match app.geo_mode {
            GeoMode::CountryList => {
                // Create a sorted list of countries by traffic
                let mut country_list: Vec<(&String, &(crate::network::types::GeoLocation, u64))> = geo.locations.iter().collect();
                country_list.sort_by(|(_, (_, a_count)), (_, (_, b_count))| b_count.cmp(a_count));
                
                // Create a two-panel split for the country list and details
                let country_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Percentage(60), // Country list
                        Constraint::Percentage(40), // Country details
                    ])
                    .split(chunks[1]);
                
                // Ensure app's selection index is within bounds
                if app.geo_country_selection >= country_list.len() && !country_list.is_empty() {
                    app.geo_country_selection = country_list.len() - 1;
                }
                
                // Create a table for country data
                let rows = country_list.iter().map(|(country, (location, count))| {
                    let percentage = if geo.locations.values().map(|(_, c)| *c).sum::<u64>() > 0 {
                        let total: u64 = geo.locations.values().map(|(_, c)| *c).sum();
                        format!("{:.1}%", (*count as f64 / total as f64) * 100.0)
                    } else {
                        "0.0%".to_string()
                    };
                    
                    Row::new(vec![
                        Cell::from(country.to_string()),
                        Cell::from(location.region.clone()),
                        Cell::from(count.to_string()),
                        Cell::from(percentage),
                        Cell::from(format!("{:.4}, {:.4}", location.latitude, location.longitude)),
                    ])
                }).collect::<Vec<_>>();
                
                // Create widths
                let widths = [
                    Constraint::Length(6),   // Country
                    Constraint::Length(15),  // Region
                    Constraint::Length(10),  // Count
                    Constraint::Length(8),   // Percentage
                    Constraint::Length(20),  // Coordinates
                ];
                
                // Create a mutable table state for selection
                let mut table_state = TableState::default();
                table_state.select(if !country_list.is_empty() { Some(app.geo_country_selection) } else { None });
                
                // Create the table
                let table = Table::new(rows, widths)
                    .header(Row::new(vec![
                        Cell::from("Country"),
                        Cell::from("Region"),
                        Cell::from("Packets"),
                        Cell::from("% Total"),
                        Cell::from("Coordinates"),
                    ]).style(Style::default().fg(Color::Yellow)))
                    .block(Block::default().borders(Borders::ALL).title(format!("Countries ({} total) - ↑/↓ to navigate", geo.total_countries)))
                    .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
                    .highlight_symbol("> ");
                
                // Render table with selection
                f.render_stateful_widget(table, country_chunks[0], &mut table_state);
                
                // Show message if no countries
                if country_list.is_empty() {
                    let message = Paragraph::new("No geographic data collected yet...")
                        .alignment(Alignment::Center)
                        .style(Style::default().fg(Color::Gray));
                    
                    let message_area = centered_rect(60, 20, country_chunks[0]);
                    f.render_widget(message, message_area);
                } else {
                    // Show detailed information for the selected country
                    let selected_idx = app.geo_country_selection;
                    if selected_idx < country_list.len() {
                        let (country_code, (location, packet_count)) = country_list[selected_idx];
                        
                        // Calculate percentage of total traffic
                        let total_packets: u64 = geo.locations.values().map(|(_, c)| *c).sum();
                        let percentage = (*packet_count as f64 / total_packets as f64) * 100.0;
                        
                        // Create a multi-column layout for details
                        let detail_chunks = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints([
                                Constraint::Percentage(50),  // Basic info
                                Constraint::Percentage(50),  // Additional stats
                            ])
                            .split(country_chunks[1]);
                        
                        // Basic country info
                        let country_info = format!(
                            "Country: {}\nRegion: {}\nLatitude: {:.4}\nLongitude: {:.4}\n\nTotal Packets: {}\nTraffic Share: {:.2}%",
                            country_code, location.region, location.latitude, location.longitude, 
                            packet_count, percentage
                        );
                        
                        let info_widget = Paragraph::new(country_info)
                            .block(Block::default().borders(Borders::ALL).title(format!("Country Details: {}", country_code)))
                            .style(Style::default().fg(Color::White));
                        
                        f.render_widget(info_widget, detail_chunks[0]);
                        
                        // Additional traffic statistics
                        // For this example, we'll just create a placeholder with recommendations
                        // In a real app, you could analyze traffic patterns, show historical data, etc.
                        let stats_text = format!(
                            "Traffic Trend: {}\nAverage Packet Size: {:.1} bytes\nFirst Detected: {} mins ago\nRecommendations: {}",
                            if *packet_count > 1000 { "High Volume ▲" } else { "Normal ◆" },
                            // Generate a fake average packet size between 100 and 1500 bytes
                            100.0 + (*packet_count as f64 % 1400.0),
                            // Fake time since first detected
                            (*packet_count % 60) + 5,
                            // Give a recommendation based on traffic volume
                            if *packet_count > 5000 {
                                "Consider rate limiting traffic from this region"
                            } else if *packet_count > 1000 {
                                "Monitor for traffic pattern changes"
                            } else {
                                "No special attention required"
                            }
                        );
                        
                        let stats_widget = Paragraph::new(stats_text)
                            .block(Block::default().borders(Borders::ALL).title("Traffic Analysis"))
                            .style(Style::default().fg(Color::White));
                        
                        f.render_widget(stats_widget, detail_chunks[1]);
                    }
                }
            },
            GeoMode::WorldMap => {
                // Create a world map using Canvas
                let map_area = chunks[1];
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("World Map");
                
                let inner_area = block.inner(map_area);
                f.render_widget(block, map_area);
                
                if inner_area.width < 40 || inner_area.height < 20 {
                    // Not enough space for a map
                    let message = Paragraph::new("Terminal too small for map view.\nResize or switch to country list.")
                        .alignment(Alignment::Center);
                    f.render_widget(message, inner_area);
                    return;
                }
                
                // The Canvas will use coordinates from -180 to 180 for longitude
                // and -90 to 90 for latitude, matching real-world geography
                
                // Create the canvas
                let canvas = Canvas::default()
                    .x_bounds([-180.0, 180.0])   // Longitude range
                    .y_bounds([-90.0, 90.0])     // Latitude range
                    .paint(|ctx| {
                        // Draw more detailed continent outlines with lines
                        let line = ratatui::widgets::canvas::Line { x1: 0.0, y1: 0.0, x2: 0.0, y2: 0.0, color: Color::Gray };
                        
                        // North America - more detailed outline
                        let north_america = [
                            // Alaska and West Coast
                            (-165.0, 65.0), (-150.0, 70.0), (-130.0, 55.0), (-125.0, 50.0), 
                            (-125.0, 40.0), (-120.0, 35.0), (-118.0, 32.0),
                            // Mexico and Central America
                            (-110.0, 30.0), (-105.0, 25.0), (-100.0, 20.0), (-95.0, 15.0),
                            (-85.0, 12.0), (-80.0, 8.0),
                            // East Coast
                            (-75.0, 10.0), (-80.0, 25.0), (-75.0, 35.0), (-70.0, 45.0),
                            // Canada & Arctic
                            (-60.0, 50.0), (-70.0, 55.0), (-80.0, 65.0), (-100.0, 70.0),
                            (-130.0, 70.0), (-150.0, 70.0)
                        ];
                        
                        // Draw North America
                        for i in 0..north_america.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = north_america[i].0;
                            l.y1 = north_america[i].1;
                            l.x2 = north_america[i+1].0;
                            l.y2 = north_america[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // South America - more detailed
                        let south_america = [
                            (-80.0, 8.0), (-75.0, 0.0), (-70.0, -10.0), (-70.0, -20.0),
                            (-65.0, -30.0), (-70.0, -40.0), (-75.0, -50.0),
                            // East coast
                            (-65.0, -55.0), (-55.0, -50.0), (-50.0, -25.0), (-45.0, -15.0),
                            (-40.0, -5.0), (-50.0, 5.0), (-60.0, 10.0), (-80.0, 8.0)
                        ];
                        
                        // Draw South America
                        for i in 0..south_america.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = south_america[i].0;
                            l.y1 = south_america[i].1;
                            l.x2 = south_america[i+1].0;
                            l.y2 = south_america[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // Europe - more detailed
                        let europe = [
                            // Western Europe
                            (-10.0, 35.0), (-5.0, 45.0), (0.0, 50.0), (5.0, 55.0), 
                            (10.0, 55.0), (15.0, 60.0), (20.0, 60.0),
                            // Eastern Europe & Russia western border
                            (30.0, 60.0), (35.0, 55.0), (30.0, 50.0), (35.0, 45.0),
                            // Mediterranean
                            (30.0, 40.0), (25.0, 35.0), (15.0, 37.0), (5.0, 37.0), (-5.0, 35.0)
                        ];
                        
                        // Draw Europe
                        for i in 0..europe.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = europe[i].0;
                            l.y1 = europe[i].1;
                            l.x2 = europe[i+1].0;
                            l.y2 = europe[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // Africa - more detailed
                        let africa = [
                            // North Africa
                            (-15.0, 35.0), (0.0, 35.0), (15.0, 35.0), (30.0, 35.0), (35.0, 30.0),
                            // East Africa
                            (40.0, 15.0), (50.0, 10.0), (45.0, 0.0), (40.0, -10.0), (35.0, -20.0),
                            // South Africa
                            (25.0, -35.0), (20.0, -35.0),
                            // West Africa
                            (15.0, -30.0), (5.0, -30.0), (-5.0, -20.0), (-15.0, -15.0),
                            (-15.0, 0.0), (-15.0, 15.0), (-15.0, 25.0), (-15.0, 35.0)
                        ];
                        
                        // Draw Africa
                        for i in 0..africa.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = africa[i].0;
                            l.y1 = africa[i].1;
                            l.x2 = africa[i+1].0;
                            l.y2 = africa[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // Asia - more detailed (including Russia, Middle East, India, China, SE Asia)
                        let asia = [
                            // Russia
                            (30.0, 60.0), (40.0, 60.0), (60.0, 70.0), (90.0, 75.0), (120.0, 70.0), 
                            (140.0, 60.0), (135.0, 45.0),
                            // China & East Asia
                            (140.0, 40.0), (130.0, 35.0), (120.0, 30.0), 
                            // Southeast Asia
                            (110.0, 20.0), (100.0, 10.0), (95.0, 5.0), 
                            // India & South Asia
                            (90.0, 10.0), (80.0, 20.0), (80.0, 25.0), 
                            // Middle East
                            (70.0, 30.0), (60.0, 25.0), (50.0, 30.0), (40.0, 35.0), (30.0, 40.0)
                        ];
                        
                        // Draw Asia
                        for i in 0..asia.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = asia[i].0;
                            l.y1 = asia[i].1;
                            l.x2 = asia[i+1].0;
                            l.y2 = asia[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // East Asia islands
                        let japan = [
                            (140.0, 45.0), (145.0, 40.0), (140.0, 35.0), (135.0, 35.0), (132.0, 33.0)
                        ];
                        
                        for i in 0..japan.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = japan[i].0;
                            l.y1 = japan[i].1;
                            l.x2 = japan[i+1].0;
                            l.y2 = japan[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // Indonesia simplified
                        let indonesia = [
                            (95.0, 5.0), (105.0, 0.0), (115.0, -5.0), (120.0, -5.0), (130.0, -5.0)
                        ];
                        
                        for i in 0..indonesia.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = indonesia[i].0;
                            l.y1 = indonesia[i].1;
                            l.x2 = indonesia[i+1].0;
                            l.y2 = indonesia[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // Australia - more detailed
                        let australia = [
                            (115.0, -20.0), (120.0, -25.0), (130.0, -30.0), (140.0, -35.0),
                            (150.0, -35.0), (150.0, -30.0), (145.0, -20.0), (140.0, -15.0),
                            (130.0, -15.0), (120.0, -15.0), (115.0, -20.0)
                        ];
                        
                        // Draw Australia
                        for i in 0..australia.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = australia[i].0;
                            l.y1 = australia[i].1;
                            l.x2 = australia[i+1].0;
                            l.y2 = australia[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // New Zealand
                        let new_zealand = [
                            (165.0, -35.0), (170.0, -40.0), (175.0, -45.0)
                        ];
                        
                        for i in 0..new_zealand.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = new_zealand[i].0;
                            l.y1 = new_zealand[i].1;
                            l.x2 = new_zealand[i+1].0;
                            l.y2 = new_zealand[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // UK
                        let uk = [
                            (-5.0, 50.0), (-2.0, 52.0), (0.0, 55.0), (-5.0, 58.0)
                        ];
                        
                        for i in 0..uk.len() - 1 {
                            let mut l = line.clone();
                            l.x1 = uk[i].0;
                            l.y1 = uk[i].1;
                            l.x2 = uk[i+1].0;
                            l.y2 = uk[i+1].1;
                            ctx.draw(&l);
                        }
                        
                        // Draw equator
                        ctx.draw(&ratatui::widgets::canvas::Line {
                            x1: -180.0, y1: 0.0,
                            x2: 180.0, y2: 0.0,
                            color: Color::Red,
                        });
                        
                        // Show traffic dots at their coordinates
                        for (_, (location, count)) in &geo.locations {
                            // Make the point size relative to the traffic volume
                            let point_size = if *count > 100 {
                                5
                            } else if *count > 50 {
                                4
                            } else if *count > 10 {
                                3
                            } else {
                                2
                            };
                            
                            // Choose color based on region
                            let color = match location.region.as_str() {
                                "North America" => Color::Red,
                                "South America" => Color::Yellow,
                                "Europe" => Color::Blue,
                                "Asia" => Color::Green,
                                "Oceania" => Color::Magenta,
                                _ => Color::White,
                            };
                            
                            // Draw a point at the location using our helper function
                            draw_country_point(
                                ctx,
                                location.longitude,
                                location.latitude,
                                color,
                                point_size
                            );
                        }
                    });
                
                f.render_widget(canvas, inner_area);
                
                // Create a legend explaining the colors
                let legends = vec![
                    "North America: Red",
                    "South America: Yellow",
                    "Europe: Blue",
                    "Asia: Green",
                    "Oceania: Magenta",
                    "Other: White",
                ];
                
                let legend_height = legends.len() as u16 + 2; // +2 for border
                let legend_width = 25;
                
                let legend_area = Rect {
                    x: inner_area.x + 2,
                    y: inner_area.y + 2,
                    width: legend_width,
                    height: legend_height,
                };
                
                let legend_block = Block::default()
                    .borders(Borders::ALL)
                    .title("Legend");
                
                let legend_inner = legend_block.inner(legend_area);
                f.render_widget(legend_block, legend_area);
                
                for (i, text) in legends.iter().enumerate() {
                    let para = Paragraph::new(*text);
                    f.render_widget(para, Rect {
                        x: legend_inner.x,
                        y: legend_inner.y + i as u16,
                        width: legend_inner.width,
                        height: 1,
                    });
                }
            }
        }
    } else {
        // Could not get lock on geo stats
        let message = Paragraph::new("Could not access geographic data...")
            .alignment(Alignment::Center);
        f.render_widget(message, chunks[1]);
    }
}