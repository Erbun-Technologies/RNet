mod app;
mod network;
mod ui;
mod utils;

use std::{
    io,
    thread,
    time::{Duration, Instant},
    sync::atomic::Ordering,
};

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Tabs},
};
use sysinfo::Networks;

use crate::app::App;
use crate::network::types::Tab;
use crate::network::capture::start_packet_capture;
use crate::ui::*;

fn draw_ui(f: &mut Frame, app: &mut App) {
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
        Tab::GeoMap.to_string(),
    ];
    
    let selected_index = match app.current_tab {
        Tab::Overview => 0,
        Tab::PacketGraph => 1,
        Tab::PacketDistribution => 2,
        Tab::Connections => 3,
        Tab::GeoMap => 4,
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
        Tab::GeoMap => draw_geo_map(f, app, main_chunks[1]),
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
        terminal.draw(|f| draw_ui(f, &mut app))?;
        
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
                                network::types::GraphScale::Linear => network::types::GraphScale::Logarithmic,
                                network::types::GraphScale::Logarithmic => network::types::GraphScale::Linear,
                            };
                        },
                        // Toggle protocol grouping with 'g'
                        KeyCode::Char('g') => {
                            app.protocol_grouping = match app.protocol_grouping {
                                network::types::ProtocolGrouping::Basic => network::types::ProtocolGrouping::Detailed,
                                network::types::ProtocolGrouping::Detailed => network::types::ProtocolGrouping::Basic,
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
                            } else if app.current_tab == Tab::GeoMap {
                                app.geo_mode = app.geo_mode.next();
                            }
                        },
                        // Scroll through connections list or country list
                        KeyCode::Up => {
                            if app.current_tab == Tab::Connections && app.connection_scroll > 0 {
                                app.connection_scroll -= 1;
                            } else if app.current_tab == Tab::GeoMap && 
                                     app.geo_mode == network::types::GeoMode::CountryList && 
                                     app.geo_country_selection > 0 {
                                app.geo_country_selection -= 1;
                            }
                        },
                        KeyCode::Down => {
                            if app.current_tab == Tab::Connections {
                                app.connection_scroll += 1;
                            } else if app.current_tab == Tab::GeoMap && 
                                     app.geo_mode == network::types::GeoMode::CountryList {
                                // We'll limit the max selection in the draw function based on the actual list length
                                app.geo_country_selection += 1;
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
    let geo_stats = app.geo_stats.clone();
    let local_networks = app.local_networks.clone();
    let running = app.running.clone();
    start_packet_capture(interface_name, packet_stats, connections, geo_stats, local_networks, running)?;
    
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