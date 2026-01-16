# IPv4 Fragmentation Visualizer - Professional Edition v2.0

A comprehensive desktop application for visualizing and understanding IPv4 packet fragmentation according to RFC 791. This tool provides an interactive, educational interface for network engineers, students, and professionals to explore how IP packets are fragmented across networks with varying Maximum Transmission Units (MTUs).

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## 🌟 Features

### Core Functionality
- **Interactive Visualization**: Real-time graphical representation of packet fragmentation
- **Multiple MTU Simulation**: Test fragmentation across network paths with varying MTU values
- **RFC 791 Compliant**: Accurate implementation of IPv4 fragmentation specifications
- **Fragment Analysis**: Detailed breakdown of each fragment with headers and offsets

### Professional Features
- **Dark/Light Mode**: Customizable appearance for comfortable viewing
- **Export Capabilities**: Save fragmentation data as CSV or JSON
- **Logging System**: Comprehensive rotating log files for debugging
- **Input Validation**: Robust error handling and user input verification
- **Configuration Management**: Persistent settings across sessions

### Educational Tools
- **Step-by-Step Breakdown**: Clear visualization of fragmentation process
- **Header Details**: Complete IPv4 header information for each fragment
- **Offset Calculation**: Transparent display of fragment offset values
- **Flag Interpretation**: Visual representation of More Fragments (MF) flag

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, or Linux
- **Display**: Minimum resolution 1200x700 (recommended 1400x900)

## 🚀 Installation

### 1. Clone or Download
```bash
# If using git
git clone <repository-url>
cd ipv4-fragmentation-visualizer

# Or download and extract the ZIP file
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python ipv4_fragmentation_visualizer.py
```

## 💻 Usage

### Basic Usage

1. **Launch the Application**
   ```bash
   python ipv4_fragmentation_visualizer.py
   ```

2. **Configure Parameters**
   - **Original Packet Size**: Total size of the IP packet (20-65535 bytes)
   - **IP Header Size**: Size of the IP header (20-60 bytes)
   - **MTU Path**: Comma-separated MTU values (e.g., "1500, 576, 1500")

3. **Visualize Fragmentation**
   - Click "Visualize Fragmentation" to see the results
   - Review the detailed fragment breakdown in the results panel

### Advanced Features

#### Export Data
- **CSV Export**: Structured data for spreadsheet analysis
- **JSON Export**: Machine-readable format for integration
- Auto-timestamped filenames for easy organization

#### Configuration
All settings are saved in `config.json` and persist across sessions:
```json
{
  "appearance_mode": "light",
  "color_theme": "blue",
  "default_packet_size": 1500,
  "default_mtu_path": "1500, 576, 1500"
}
```

#### Logging
Application logs are stored in `app.log` with automatic rotation:
- Maximum file size: 5 MB
- Backup count: 3 files
- Log level: INFO

## 📊 Example Scenarios

### Scenario 1: Standard Ethernet Fragmentation
```
Original Packet Size: 1500 bytes
IP Header Size: 20 bytes
MTU Path: 1500
```
**Result**: No fragmentation needed

### Scenario 2: Path MTU Discovery
```
Original Packet Size: 2000 bytes
IP Header Size: 20 bytes
MTU Path: 1500, 576, 1500
```
**Result**: Multiple fragments created at 576 MTU bottleneck

### Scenario 3: Maximum Fragmentation
```
Original Packet Size: 5000 bytes
IP Header Size: 20 bytes
MTU Path: 576
```
**Result**: Multiple small fragments demonstrating extreme case

## 🔧 Configuration Options

### Application Settings (`config.json`)

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `appearance_mode` | "light" | light/dark/system | UI theme |
| `color_theme` | "blue" | blue/green/dark-blue | Color scheme |
| `window_width` | 1400 | 1200+ | Application width (px) |
| `window_height` | 900 | 700+ | Application height (px) |
| `default_packet_size` | 1500 | 20-65535 | Initial packet size |
| `default_header_size` | 20 | 20-60 | Initial header size |
| `default_mtu_path` | "1500, 576, 1500" | - | Initial MTU values |
| `min_mtu` | 68 | 68+ | Minimum allowed MTU |
| `max_mtu` | 65535 | ≤65535 | Maximum allowed MTU |

### Validation Rules

- **Packet Size**: Must be between 20 and 65,535 bytes
- **Header Size**: Must be between 20 and 60 bytes (multiples of 4)
- **MTU Values**: Must be at least 68 bytes (RFC 791 minimum)
- **Fragment Offset**: Cannot exceed 8,191 (13-bit field limit)

## 📚 Technical Details

### Fragmentation Algorithm

1. **Calculate Data Size**: `data_size = packet_size - header_size`
2. **For Each MTU**:
   - Determine maximum payload: `max_payload = (mtu - header_size) ÷ 8 × 8`
   - Create fragments until all data is transmitted
   - Set MF flag for all fragments except the last
   - Calculate fragment offset: `offset = current_position ÷ 8`

### Fragment Header Structure
Each fragment includes:
- **Fragment ID**: Unique identifier for the original packet
- **Fragment Offset**: Position in original datagram (in 8-byte units)
- **More Fragments (MF)**: Flag indicating more fragments follow
- **Total Length**: Size of this fragment (header + data)

### Key Calculations
```python
# Fragment offset (13-bit field, represents 8-byte units)
offset = current_position // 8

# Maximum data per fragment (must be multiple of 8)
max_data = ((mtu - header_size) // 8) * 8

# More Fragments flag
mf_flag = 1 if not last_fragment else 0
```

## 🐛 Troubleshooting

### Common Issues

**Application won't start**
- Verify Python 3.8+ is installed: `python --version`
- Install dependencies: `pip install -r requirements.txt`
- Check `app.log` for error messages

**Fragmentation calculation errors**
- Ensure packet size > header size
- Verify MTU values ≥ 68 bytes
- Check that total packet size ≤ 65,535 bytes

**Export not working**
- Verify write permissions in application directory
- Check available disk space
- Review `app.log` for export errors

**Display issues**
- Ensure minimum resolution (1200x700)
- Try switching appearance mode (light/dark)
- Verify graphics drivers are up to date

## 📖 Educational Resources

### Understanding IPv4 Fragmentation

IPv4 fragmentation occurs when a packet traverses a network with a smaller MTU than the packet size. The router fragments the packet into smaller pieces that fit within the MTU constraint.

**Key Concepts:**
- **MTU (Maximum Transmission Unit)**: Maximum packet size for a network link
- **Fragment Offset**: Position of fragment data in the original packet
- **More Fragments Flag**: Indicates whether more fragments follow
- **Don't Fragment Flag**: Prevents fragmentation (not simulated in this tool)

### Related RFCs
- **RFC 791**: Internet Protocol (IPv4 specification)
- **RFC 1191**: Path MTU Discovery
- **RFC 8900**: IP Fragmentation Considered Fragile

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Setup
```bash
# Clone repository
git clone <repository-url>

# Install development dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest tests/
```

## 📄 License

This project is provided as-is for educational and professional use. Please refer to the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) for modern UI
- Implements RFC 791 IPv4 specification
- Inspired by network engineering education needs

## 📞 Support

For issues, questions, or suggestions:
- Check the `app.log` file for detailed error information
- Review the configuration in `config.json`
- Consult RFC 791 for protocol details

## 🔄 Version History

### v2.0 (2026-01-16) - Professional Edition
- Critical fragment offset calculation bug fix
- Comprehensive input validation
- Professional logging system
- Dark mode support
- Performance optimizations
- Extensive code refactoring
- Enhanced error handling

### v1.0 - Initial Release
- Basic fragmentation visualization
- CSV/JSON export
- Configuration management

---

**Built with ❤️ for network engineers and students worldwide**
