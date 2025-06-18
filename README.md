# Python IDS Project 

## Overview
A comprehensive Intrusion Detection System (IDS) built in Python for monitoring network activity, detecting suspicious behavior, and protecting against various cybersecurity threats. 
This project combines real-time network monitoring with advanced threat detection capabilities.

## Key Features
- **Real-time Network Monitoring**
  - Active connection tracking
  - Port scanning detection
  - Data transfer monitoring
  - Network interface statistics

- **Advanced Threat Detection**
  - Malicious IP detection and management
  - Suspicious port monitoring
  - Attack pattern recognition (SQL Injection, XSS, Command Injection)
  - Connection flood detection
  - Port scan detection
  - Data transfer threshold monitoring

- **User Interface**
  - Modern and intuitive GUI
  - Real-time alert display
  - Alert settings configuration window
  - Malicious IP management interface
  - Network statistics visualization

- **Configuration Management**
  - Centralized settings in `ids_settings.json`
  - Customizable detection thresholds
  - Configurable attack patterns
  - Suspicious ports management
  - Malicious IP database

## Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (required for network monitoring)
- Required Python packages (see requirements.txt)

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-name>
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On Unix/MacOS
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. **Start the Application:**
   ```bash
   python main.py
   ```

2. **Configure Alert Settings:**
   - Access the Alert Settings window from the main UI
   - Adjust detection thresholds
   - Configure suspicious ports
   - Set up attack patterns
   - Save changes to apply new settings

3. **Monitor Network Activity:**
   - View real-time alerts in the Recent Alerts panel
   - Check IP information using the context menu
   - Perform port scans on suspicious IPs
   - Verify IPs against malicious IP database

4. **Manage Malicious IPs:**
   - Add/remove IPs from the malicious database
   - Import/export malicious IP lists
   - View detailed information about flagged IPs

## Project Structure
- `main.py` - Main application entry point
- `alert_manager.py` - Alert handling and management
- `alert_settings_window.py` - Alert configuration UI
- `malicious_ip_manager.py` - Malicious IP database management
- `malicious_ip_window.py` - Malicious IP management UI
- `port_scanner.py` - Port scanning functionality
- `settings_manager.py` - Configuration management
- `threat_detection.py` - Core threat detection logic

## Configuration Files
- `ids_settings.json` - Main configuration file
- `malicious_ips.json` - Malicious IP database

## Development
The project include test file for attack simulation:
- `Attack_test.py` - Alert system tests

## Contributing
Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

 
## Security Note
This tool is designed for educational and monitoring purposes. Always use responsibly and in accordance with applicable laws and regulations. 