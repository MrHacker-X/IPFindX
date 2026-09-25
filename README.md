<div align="center">

# 🌐 IPFindX - Advanced IP Intelligence Toolkit

<p>
<img src="https://img.shields.io/badge/💎-Premium%20OSINT%20Tool-blueviolet?style=for-the-badge" alt="Premium Tool">
<img src="https://img.shields.io/badge/🎯-Cybersecurity%20Professional-red?style=for-the-badge" alt="Professional">
<img src="https://img.shields.io/badge/⚡-Lightning%20Fast-yellow?style=for-the-badge" alt="Fast">
</p>

### 🚀 *The Ultimate IP Intelligence Reconnaissance Platform for Security Professionals*

**Unleash the power of advanced IP geolocation, threat intelligence, and network forensics in a single, elegant command-line interface. Built by cybersecurity experts, for cybersecurity experts.**

[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows%20|%20Android-lightgrey.svg)](#compatibility)
[![Version](https://img.shields.io/badge/version-3.0.1-brightgreen.svg)](#overview)
[![Status](https://img.shields.io/badge/status-stable-success.svg)](#overview)
[![Maintained](https://img.shields.io/badge/maintained-yes-green.svg)](#contributing)
[![Stars](https://img.shields.io/github/stars/MrHacker-X/IPFindX?style=social)](https://github.com/MrHacker-X/IPFindX)
[![Forks](https://img.shields.io/github/forks/MrHacker-X/IPFindX?style=social)](https://github.com/MrHacker-X/IPFindX)
[![Issues](https://img.shields.io/github/issues/MrHacker-X/IPFindX)](https://github.com/MrHacker-X/IPFindX/issues)
[![Contributors](https://img.shields.io/github/contributors/MrHacker-X/IPFindX)](https://github.com/MrHacker-X/IPFindX/graphs/contributors)
[![Languages](https://img.shields.io/github/languages/count/MrHacker-X/IPFindX)](https://github.com/MrHacker-X/IPFindX)
[![Code Size](https://img.shields.io/github/languages/code-size/MrHacker-X/IPFindX)](https://github.com/MrHacker-X/IPFindX)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Examples](#️-output-examples)
- [Screenshots](#-screenshots)
- [Use Cases](#-use-cases)
- [Project Structure](#-project-structure)
- [API Integration](#-api-integration)
- [Performance](#-performance)
- [Compatibility](#-compatibility)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [Roadmap](#-roadmap)
- [Developer](#-developer)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)


## 🔮 Overview

**IPFindX** is a professional-grade command-line IP intelligence toolkit designed for cybersecurity professionals, network administrators, threat hunters, and OSINT researchers. It provides comprehensive geolocation data, ISP information, security threat indicators, and detailed network intelligence for any public IP address with enterprise-level accuracy.

With its beautifully designed terminal interface and powerful data processing capabilities, IPFindX transforms complex IP reconnaissance into an efficient, streamlined process, delivering actionable intelligence in seconds.

### Key Highlights

- 🎯 **Enterprise-Grade Intelligence**: Detailed geolocation, ISP, organization, and network data with high accuracy
- 🎨 **Elegant CLI Interface**: Rich terminal output with color-coded information and professionally designed tables
- 💾 **Seamless Data Persistence**: All results automatically saved as timestamped JSON files for future analysis
- 📊 **Advanced Batch Processing**: Scan multiple IPs from a file with intelligent progress tracking
- 🛡️ **Sophisticated Validation**: Automatically validates IP addresses and filters private/reserved ranges
- 🗺️ **Integrated Geographic Visualization**: Direct Google Maps integration for precise location mapping
- 🔄 **Real-time Data**: Always up-to-date information from trusted IP intelligence sources
- ⚙️ **Zero Configuration**: Works out of the box with no complex setup or configuration required

## ✨ Features

### Core Functionality
- **Single IP Lookup**: Get comprehensive information for any public IP address
- **Batch IP Scanning**: Process multiple IPs from a text file
- **Geolocation Data**: Country, region, city, coordinates, and timezone information
- **Network Intelligence**: ISP, organization, AS number, and hosting detection
- **Security Indicators**: Proxy, mobile, and hosting status detection
- **DNS Resolution**: Reverse DNS lookup for hostname identification

### Advanced Features
- **Smart IP Validation**: Automatically detects and rejects private/reserved IP ranges
- **Geographic Mapping**: Direct integration with Google Maps for location visualization
- **Timestamped Output**: Organized output files with date/time stamps
- **Progress Tracking**: Real-time status updates for long-running operations
- **Error Handling**: Robust error handling with informative user feedback

### User Experience
- **Rich Terminal Output**: Beautiful tables and panels with syntax highlighting
- **Responsive Design**: Adapts to different terminal sizes with fallback layouts
- **Color-coded Results**: Status indicators and field highlighting for easy reading
- **Organized Storage**: Automatic creation of output directories and file management

## 📋 Requirements

### System Requirements
- **Python**: Version 3.7 or higher
- **Operating System**: Linux, macOS, Windows
- **Internet Connection**: Required for IP-API access
- **Terminal**: Any modern terminal with UTF-8 support

### Python Dependencies
```bash
requests
rich
```

## 🚀 Installation

### Method 1: PyPI (Recommended)
```bash
# Install from PyPI
pip install ipfindx
```

### Method 2: Git Clone
```bash
# Clone the repository
git clone https://github.com/MrHacker-X/IPFindX.git

# Navigate to project directory
cd IPFindX

# Install dependencies
pip install -r requirements.txt

# Run the application
python ipfindx.py --help
```

## 🎯 Usage

IPFindX is a command-line tool with intuitive options for different use cases:

### Single IP Lookup
```bash
# Basic IP lookup
ipfindx -i 8.8.8.8

# Using Python directly (if cloned from Git)
python ipfindx.py -i 1.1.1.1
```

### Batch IP Scanning
```bash
# Scan multiple IPs from a file
ipfindx -l ip_list.txt

# File format (one IP per line):
# 8.8.8.8
# 1.1.1.1
# 208.67.222.222
```

### Information and Help
```bash
# Show detailed information about the tool
ipfindx --about

# Display developer contact information
ipfindx --connect

# Show help message
ipfindx --help
```

### Output Management
All scans automatically save results to the `output-ipfindx/` directory with timestamped filenames:
- Format: `{IP_ADDRESS}-{DDMMYYYY-HHMMSS}.json`
- Example: `8.8.8.8-06082025-225328.json`

## 🖼️ Output Examples

### Terminal Display
```
              IP Details for 8.8.8.8
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Field                     ┃ Value              ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ • Status                  │ success            │
│ • Continent               │ North America      │
│ • Continentcode           │ NA                 │
│ • Country                 │ United States      │
│ • Countrycode             │ US                 │
│ • Region                  │ VA                 │
│ • Regionname              │ Virginia           │
│ • City                    │ Ashburn            │
│ • District                │                    │
│ • Zip                     │ 20149              │
│ • Lat                     │ 39.03              │
│ • Lon                     │ -77.5              │
│ • Timezone                │ America/New_York   │
│ • Offset                  │ -14400             │
│ • Currency                │ USD                │
│ • Isp                     │ Google LLC         │
│ • Org                     │ Google Public DNS  │
│ • As                      │ AS15169 Google LLC │
│ • Asname                  │ GOOGLE             │
│ • Reverse                 │ dns.google         │
│ • Mobile                  │ False              │
│ • Proxy                   │ False              │
│ • Hosting                 │ True               │
│ • Query                   │ 8.8.8.8            │
└───────────────────────────┴────────────────────┘
```

### JSON Output Structure
```json
{
    "status": "success",
    "continent": "North America",
    "continentCode": "NA",
    "country": "United States",
    "countryCode": "US",
    "region": "VA",
    "regionName": "Virginia",
    "city": "Ashburn",
    "district": "",
    "zip": "20149",
    "lat": 39.03,
    "lon": -77.5,
    "timezone": "America/New_York",
    "offset": -14400,
    "currency": "USD",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169 Google LLC",
    "asname": "GOOGLE",
    "reverse": "dns.google",
    "mobile": false,
    "proxy": false,
    "hosting": true,
    "query": "8.8.8.8"
}
```

## 📸 Screenshots

<div align="center">

### Single IP Lookup
![Single IP Lookup](https://i.ibb.co/LDWQpC3S/Screenshot-From-2025-08-07-00-01-40.png)

### Tool Information Display
![About Screen](https://i.ibb.co/gFc8qYzg/Screenshot-From-2025-08-07-00-02-15.png)

</div>


## 🔍 Use Cases

### Cybersecurity Operations
- **Threat Intelligence**: Rapidly investigate suspicious IP addresses during security incidents
- **SOC Analysis**: Integrate into Security Operations Center workflows for faster response
- **Malware Investigation**: Determine the origin of malicious connections or command servers
- **Log Analysis**: Quickly enrich log data with geographic and network context

### Network Administration
- **Traffic Analysis**: Identify the source of unusual network traffic patterns
- **Access Control**: Verify the location of connection attempts for geofencing policies
- **Service Deployment**: Test IP geolocation for CDN and service deployment planning
- **Network Troubleshooting**: Diagnose connectivity issues with detailed IP information

### OSINT Research
- **Digital Investigations**: Gather intelligence on network infrastructure
- **Attribution Research**: Help identify the origin of online activities
- **Geographic Mapping**: Plot network infrastructure on maps for visual analysis
- **Data Enrichment**: Add geolocation context to existing datasets

## 📁 Project Structure

```
IPFindX/
├── ipfindx.py          # Main application script
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
├── LICENSE             # MIT License
└── output-ipfindx/     # Auto-generated output directory
    └── *.json          # Timestamped result files
```

### File Descriptions

- **`ipfindx.py`**: Main application containing all core functionality, CLI parsing, and output formatting
- **`requirements.txt`**: Lists required Python packages (requests, rich)
- **`README.md`**: Comprehensive documentation and usage guide
- **`LICENSE`**: MIT License detail
- **`output-ipfindx/`**: Auto-created directory for storing JSON results

## 🔌 API Integration

IPFindX uses the IP-API.com service for IP intelligence data. The tool intelligently handles API rate limiting and connection issues to ensure reliable operation. Key API features include:

- **Comprehensive Data Fields**: Access to 25+ data points for each IP address
- **High Accuracy**: Enterprise-grade geolocation and network data
- **Optimized Requests**: Efficient API calls with minimal overhead
- **Error Handling**: Graceful handling of API limitations and service disruptions

For high-volume usage, consider [IP-API Pro plans](https://ip-api.com/docs/premium).

## ⚡ Performance

IPFindX is engineered for optimal performance across various environments:

- **Lookup Speed**: ~0.3 seconds per IP address (network dependent)
- **Batch Processing**: Efficiently handles thousands of IPs with minimal resource usage
- **Memory Footprint**: Typically under 50MB RAM even during large batch operations
- **Disk Usage**: Minimal with efficient JSON storage format
- **CPU Utilization**: Low CPU requirements, works well on resource-constrained systems

## 🖥️ Compatibility

### Tested Environments
- **Linux**: Ubuntu 20.04+, Debian 10+, CentOS 8+, Kali Linux, Arch Linux
- **macOS**: Monterey (12.0+), Ventura (13.0+), Sonoma (14.0+)
- **Windows**: Windows 10/11, Windows Server 2019/2022
- **Android**: Termux on Samsung Galaxy S24 Ultra (One UI 7)

### Terminal Compatibility
- **Linux**: GNOME Terminal, Konsole, Alacritty, Terminator, iTerm2
- **macOS**: Terminal.app, iTerm2, Alacritty
- **Windows**: Windows Terminal, PowerShell, Command Prompt, ConEmu, Cmder
- **Android**: Termux Terminal (tested on Samsung Galaxy S24 Ultra One UI 7)

## 🔒 Security Considerations

IPFindX is designed with security in mind:

- **No Sensitive Data Storage**: IP information is only saved locally
- **Input Validation**: All user inputs are validated to prevent injection attacks
- **No External Scripts**: Self-contained operation without external scripts
- **Network Security**: Uses HTTPS for all API communications
- **Minimal Dependencies**: Limited external libraries to reduce attack surface
- **Public IP Focus**: Automatically rejects private/internal IP scanning attempts

## 🔄 Enhanced Features

### Extended Functionality
- **Single IP Lookup**: Get comprehensive information for any public IP address with a single command
- **Batch IP Scanning**: Process multiple IPs from a text file with optimized parallel processing
- **Geolocation Data**: Precise country, region, city, coordinates, and timezone information
- **Network Intelligence**: Detailed ISP, organization, AS number, and hosting detection
- **Security Indicators**: Advanced proxy, mobile, and hosting status detection for threat assessment
- **DNS Resolution**: Reverse DNS lookup for hostname identification and verification

### Advanced Capabilities
- **Smart IP Validation**: Sophisticated detection and filtering of private/reserved IP ranges
- **Geographic Mapping**: Seamless integration with Google Maps for visual location reconnaissance
- **Structured Data Output**: Organized JSON output with consistent field naming for easy parsing
- **Timestamped Records**: Intelligent file naming with precise date/time stamps for audit trails
- **Progress Visualization**: Real-time status updates and progress bars for long-running operations
- **Error Management**: Enterprise-grade error handling with comprehensive user feedback
- **Cross-Platform Support**: Full functionality across Linux, macOS, and Windows environments
- **Memory-Efficient Design**: Optimized resource usage even when processing large IP lists

### Professional User Experience
- **Rich Terminal Visualization**: Beautiful tables and panels with syntax highlighting and UTF-8 characters
- **Responsive Design**: Intelligent terminal size detection with adaptive layout for any screen size
- **Color-coded Indicators**: Intuitive status indicators and field highlighting for rapid information assessment
- **Automatic Storage Management**: Smart creation of output directories and organized file management
- **Command-line Ergonomics**: Intuitive arguments and flags designed for maximum efficiency
- **Comprehensive Help System**: Detailed help messages and usage examples built right in

## 🗺️ Roadmap

Future development plans for IPFindX:

- **Advanced Threat Intelligence**: Integration with threat intelligence databases
- **Expanded Data Sources**: Additional IP intelligence providers
- **Export Formats**: Support for CSV, XML, and other export formats
- **Custom API Keys**: Support for user-provided API keys
- **Interactive Mode**: Terminal-based interactive interface for multiple lookups
- **IP Range Scanning**: Support for CIDR notation and IP ranges
- **Historical Data**: Tracking changes in IP intelligence over time
- **Integration APIs**: Python library interface for integration with other tools
- **Visualization**: Built-in data visualization capabilities
- **Docker Container**: Official Docker image for containerized deployment

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Ways to Contribute
- 🐛 **Bug Reports**: Submit detailed issue reports with reproduction steps
- 💡 **Feature Requests**: Suggest new functionality or improvements
- 🔧 **Code Contributions**: Submit pull requests with enhancements
- 📚 **Documentation**: Improve documentation, examples, and tutorials
- 🧪 **Testing**: Help test the tool across different platforms and scenarios
- 🌐 **Internationalization**: Assist with translations and localization

### Development Setup
```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/yourusername/IPFindX.git

# Create a feature branch
git checkout -b feature/your-feature-name

# Install development dependencies
pip install -r requirements.txt

# Make changes and test thoroughly
python ipfindx.py -i 8.8.8.8

# Commit with descriptive messages
git commit -m "Add: new feature description"

# Push to your fork and create pull request
git push origin feature/your-feature-name
```

### Coding Guidelines
- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include error handling for edge cases
- Test with various IP address types
- Maintain compatibility with Python 3.7+

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Alex Butler (Vritra Security Organization)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 👨‍💻 Developer

<div align="center">

### Alex Butler
**Vritra Security Organization**

[![GitHub](https://img.shields.io/badge/GitHub-MrHacker-X-181717?style=for-the-badge&logo=github)](https://github.com/MrHacker-X)
[![Website](https://img.shields.io/badge/Website-vritrasec.com-FF6B6B?style=for-the-badge&logo=firefox)](https://vritrasec.com)
[![Instagram](https://img.shields.io/badge/Instagram-haxorlex-E4405F?style=for-the-badge&logo=instagram)](https://instagram.com/haxorlex)
[![YouTube](https://img.shields.io/badge/YouTube-Technolex-FF0000?style=for-the-badge&logo=youtube)](https://youtube.com/@Technolex)

### 📱 Telegram Channels
[![Central](https://img.shields.io/badge/Central-LinkCentralX-0088CC?style=for-the-badge&logo=telegram)](https://t.me/LinkCentralX)
[![Main Channel](https://img.shields.io/badge/Main-VritraSec-0088CC?style=for-the-badge&logo=telegram)](https://t.me/VritraSec)
[![Community](https://img.shields.io/badge/Community-MrHacker-X-0088CC?style=for-the-badge&logo=telegram)](https://t.me/MrHacker-X)
[![Support Bot](https://img.shields.io/badge/Support-ethicxbot-0088CC?style=for-the-badge&logo=telegram)](https://t.me/ethicxbot)

</div>

## 🙏 Acknowledgements

- [IP-API](https://ip-api.com/) - For providing the robust IP geolocation API
- [Rich](https://github.com/Textualize/rich) - For the beautiful terminal formatting
- [Requests](https://docs.python-requests.org/) - For reliable HTTP client functionality

---

<div align="center">

### 🌟 Support the Project

If you find IPFindX helpful, please consider:
- ⭐ Starring the repository
- 🍴 Forking and contributing
- 📢 Sharing with others
- 🐛 Reporting issues
- 💡 Suggesting new features

**Made with ❤️ by the <a href="https://vritrasec.com">Vritra Security Organization</a>**

</div>
