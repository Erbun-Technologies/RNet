# rnet_claude

A network traffic monitoring dashboard built with Rust and Ratatui.

## Features

- Real-time monitoring of network interfaces
- Traffic statistics (rx/tx bytes, speeds)
- Packet type analysis (TCP, UDP, ICMP, Other)
- Interactive TUI with multiple views:
  - Overview - General network stats
  - Packet Graph - Visual time-series graph of packet types
  - Packet Distribution - Bar chart showing packet type distribution

## Requirements

- Rust 1.76.0 or later
- libpcap development libraries (for packet capture)

### Installing libpcap

- **macOS**: `brew install libpcap` (usually pre-installed)
- **Debian/Ubuntu**: `sudo apt install libpcap-dev`
- **Fedora/RHEL**: `sudo dnf install libpcap-devel`
- **Windows**: See [pcap crate documentation](https://docs.rs/pcap) for installation instructions

## Usage

```bash
# Build the project
cargo build --release

# Run the application (requires appropriate permissions for packet capture)
sudo ./target/release/rnet_claude
```

### Controls

- `q` - Quit the application
- `←` / `→` - Navigate between tabs
- `ESC` - Cancel operation

## License

MIT