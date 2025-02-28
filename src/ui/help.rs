use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use crate::utils::centered_rect;

pub fn draw_help_overlay(f: &mut Frame, area: Rect) {
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

----- Geo Map Tab Shortcuts -----
f: Toggle between Country List and World Map view
↑/↓: Navigate through countries in the Country List view

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