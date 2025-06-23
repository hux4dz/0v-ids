# Python-Based Intrusion Detection System (IDS)

## 🛡️ Overview

A comprehensive Intrusion Detection System (IDS) built in Python for monitoring network activity, detecting suspicious behavior, and protecting against various cybersecurity threats. This project combines real-time network monitoring with advanced threat detection capabilities.

## ✨ Key Features

### 🔍 Real-Time Network Monitoring
- **Live Packet Capture**: Real-time monitoring of network interfaces using Scapy
- **Connection Tracking**: Active monitoring of TCP/UDP connections and their states
- **Interface Management**: Support for multiple network interfaces with automatic detection
- **Traffic Analysis**: Deep packet inspection with payload analysis

### 🚨 Threat Detection
- **Connection Flood Detection**: Identifies SYN flood attacks and rapid connection attempts
- **Port Scan Detection**: Detects systematic port scanning behavior with configurable thresholds
- **Data Exfiltration Monitoring**: Alerts on large data transfers that may indicate data theft
- **Malicious IP Detection**: Integration with multiple threat intelligence APIs
- **Attack Pattern Recognition**: Signature-based detection for SQL injection, XSS, and other attacks
- **Suspicious Port Monitoring**: Alerts on access to potentially dangerous services

### 🎯 Security Tools Integration
- **Port Scanner**: Built-in port scanning capabilities for threat investigation
- **IP Information Lookup**: WHOIS and geolocation data for suspicious IPs
- **Malicious IP Verification**: Multi-API checking (AbuseIPDB, VirusTotal, AlienVault)
- **Connection Pinning**: Track and highlight specific connections of interest

### 🖥️ User Interface
- **Modern GUI**: Intuitive Tkinter-based interface with real-time updates
- **Alert Management**: Comprehensive alert display with filtering and export capabilities
- **Settings Configuration**: configuration panel for all detection parameters
- **Connection Visualization**: Real-time connection table with filtering and search
- **Statistics Dashboard**: Live monitoring of system performance and threat metrics

## 📋 Prerequisites

- **Python 3.8+** (3.9+ recommended)
- **Administrator/Root privileges** (required for packet capture)
- **Windows/Linux/macOS** support
- **Network interface access** permissions

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd python-ids
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API Keys (Optional)
Edit `ids_settings.json` to add your API keys for enhanced threat detection:
```json
{
  "api_keys": {
    "abuseipdb": "your_abuseipdb_key",
    "virustotal": "your_virustotal_key",
    "alienvault": "your_alienvault_key"
  }
}
```

## 🎮 Usage

### Starting the Application
```bash
python main.py
```

### Main Interface Navigation

#### 1. **Network Interface Selection**
- Choose your monitoring interface from the dropdown
- Click the refresh button (↻) to update interface list
- Ensure the interface is active before starting monitoring

#### 2. **Monitoring Controls**
- **Start Monitoring**: Begin packet capture and analysis
- **Stop Monitoring**: Halt all monitoring activities
- **Pause/Resume**: Temporarily suspend monitoring
- **Settings**: Configure detection parameters

#### 3. **Alert Management**
- View real-time alerts in the "Recent Alerts" panel
- Filter alerts by type, severity, or time
- Export alerts to CSV or JSON format
- Clear alert history as needed

#### 4. **Connection Analysis**
- Monitor active connections in real-time
- Use the filter system to focus on specific traffic
- Right-click connections for security tools
- Pin important connections for tracking

### Security Tools

#### Port Scanner
- Right-click any connection → "Security Tools" → "Port Scan"
- Configure scan range and timeout settings
- View open ports and service information

#### IP Information
- Right-click any connection → "Security Tools" → "IP Information"
- Get WHOIS data, geolocation, and ISP information
- Export IP intelligence reports

#### Malicious IP Check
- Right-click any connection → "Security Tools" → "Check Malicious IP"
- Multi-API verification against threat databases
- Detailed reputation analysis and confidence scores

## ⚙️ Configuration

### Alert Settings Window
Access via the "Alert Settings" button to configure:

#### Detection Thresholds
- **Connection Flood**: Number of connections before alerting (default: 1250)
- **Port Scan**: Unique ports scanned before alerting (default: 2)
- **Data Exfiltration**: Data transfer size threshold (default: 15MB)

#### Attack Patterns
- **SQL Injection**: Comprehensive regex patterns for SQL attacks
- **XSS**: Cross-site scripting detection patterns
- **Custom Patterns**: Add your own detection signatures

#### Suspicious Ports
- Configure which ports to monitor as suspicious
- Set risk levels and descriptions for each port
- Manage ignored ports for normal traffic

### Settings File Structure
```json
{
  "alert_settings": {
    "connection_flood": {
      "threshold": 1250,
      "cooldown": 60,
      "severity": "low",
      "enabled": true
    },
    "port_scan": {
      "threshold": 2,
      "cooldown": 10,
      "severity": "low",
      "enabled": true
    },
    "data_exfiltration": {
      "size": 15092200,
      "window": 60,
      "severity": "critical",
      "enabled": true
    }
  },
  "attack_patterns": {
    "sql_injection": ["pattern1", "pattern2"],
    "xss": ["pattern1", "pattern2"]
  },
  "suspicious_ports": {
    "22": {"service": "SSH", "risk": "medium"},
    "3306": {"service": "MySQL", "risk": "high"}
  }
}
```

## 🧪 Testing

### Built-in Test Suite
Use `test_alerts.py` to verify detection capabilities:
"Best use from different machine on local network"


```bash
python test_alerts.py
```

#### Available Tests
1. **All Tests**: Run complete test suite
2. **Port Scan Test**: Simulate port scanning (10 ports by default)
3. **SQL Injection Test**: Test SQL injection detection
4. **XSS Test**: Test cross-site scripting detection
5. **Connection Flood Test**: Simulate SYN flood (1300 packets)
6. **Data Exfiltration Test**: Simulate data theft (11,000 packets)

#### Test Configuration
- Customize target IP and port
- Adjust packet counts and delays
- Monitor real-time detection results

## 📁 Project Structure

```
python-ids/
├── main.py                      # Main application entry point
├── alert_manager.py             # Alert handling and management
├── alert_settings_window.py     # Alert configuration UI
├── threat_detection.py          # Core threat detection logic
├── malicious_ip_manager.py      # Malicious IP database management
├── malicious_ip_window.py       # Malicious IP management UI
├── port_scanner.py              # Port scanning functionality
├── ip_info.py                   # IP information lookup
├── settings_manager.py          # Configuration management
├── test_alerts.py               # Attack test simulation
├── ids_settings.json            # Main configuration file
├── malicious_ips.json           # Malicious IP database
├── requirements.txt             # Python dependencies
└── README.md                    # This documentation
```

## 🔧 Features

### Connection Filtering
Use the built-in filter system to focus on specific traffic:
- **Process filtering**: `process chrome`
- **Status filtering**: `status established`
- **Port filtering**: `port 80`
- **IP filtering**: `ip 192.168.1.1`
- **Combined filters**: `process chrome and port 80`

### Alert Export
Export alerts in multiple formats:
- **CSV**: For spreadsheet analysis
- **JSON**: For programmatic processing
- **Text**: For log analysis

### Malicious IP Management
- Add/remove IPs from the malicious database
- Import/export IP lists
- Automatic checking against threat intelligence APIs
- Custom categorization and notes

## 🛠️ Development

### Adding New Detection Rules
1. Edit `ids_settings.json` to add new attack patterns
2. Update `threat_detection.py` for new detection logic
3. Test with `test_alerts.py`

### Extending the GUI
1. Modify the appropriate window class
2. Update the main interface in `main.py`
3. Test UI changes thoroughly


## 🔒 Security Considerations

### Legal Compliance
- **Educational Use**: This tool is designed for educational and monitoring purposes
- **Authorized Testing**: Only test on networks you own or have explicit permission to test


### Best Practices
- Test in isolated environments
- Keep dependencies and threat signatures updated


## 🤝 Contributing

We welcome contributions!:

 **Fork** / **Create** / **Commit** / **Push** / **Open** Do what ever you like !


## 🙏 Acknowledgments

- **Scapy**: powerful packet manipulation capabilities
- **psutil**: system and process monitoring
- **Tkinter**: the GUI framework
- **Open Source Community**: For various supporting libraries

---

**⚠️ Disclaimer**: This tool is for educational purposes only. 