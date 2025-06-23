import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from settings_manager import SettingsManager
from malicious_ip_manager import MaliciousIPManager

class ThreatDetector:
    def __init__(self):
        self.settings_manager = SettingsManager()
        self.malicious_ip_manager = MaliciousIPManager()
        self.reload_settings()
        # Connection statistics tracking, keyed by source IP
        self.connection_stats = defaultdict(lambda: {
            'connections': [],  # list connection timestamps
            'ports': [],
            'data_transferred': [],  # List of (timestamp, size)
            'last_alert': {}  # Dict of alert_type -> last_alert_time
        })
        # Alert history
        self.alert_history = []
        # Initialize logging
        logging.basicConfig(
            filename='threat_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.malicious_ip_manager.load_list()

    def reload_settings(self):
        settings = self.settings_manager.load_settings()
        alert_settings = settings.get('alert_settings', {})
        
        # Load all thresholds from settings 
        self.thresholds = {
            'connection_flood': {
                'count': alert_settings.get('connection_flood', {}).get('threshold'),
                'window': alert_settings.get('connection_flood', {}).get('cooldown'),
                'severity': alert_settings.get('connection_flood', {}).get('severity'),
                'enabled': alert_settings.get('connection_flood', {}).get('enabled', True),
                'description': alert_settings.get('connection_flood', {}).get('description')
            },
            'port_scan': {
                'count': alert_settings.get('port_scan', {}).get('threshold'),
                'window': alert_settings.get('port_scan', {}).get('cooldown'),
                'severity': alert_settings.get('port_scan', {}).get('severity'),
                'enabled': alert_settings.get('port_scan', {}).get('enabled', True),
                'description': alert_settings.get('port_scan', {}).get('description')
            },
            'data_exfiltration': {
                'size': alert_settings.get('data_exfiltration', {}).get('size'),
                'window': alert_settings.get('data_exfiltration', {}).get('window'),
                'severity': alert_settings.get('data_exfiltration', {}).get('severity'),
                'enabled': alert_settings.get('data_exfiltration', {}).get('enabled', True),
                'description': alert_settings.get('data_exfiltration', {}).get('description')
            }
        }
        
        # Load other detection settings
        self.detection_settings = {
            'malicious_ip': {
                'severity': alert_settings.get('malicious_ip', {}).get('severity'),
                'enabled': alert_settings.get('malicious_ip', {}).get('enabled', True),
                'description': alert_settings.get('malicious_ip', {}).get('description')
            },
            'suspicious_port': {
                'enabled': alert_settings.get('suspicious_port', {}).get('enabled', True),
                'description': alert_settings.get('suspicious_port', {}).get('description')
            },
            'attack_patterns': {
                'severity': alert_settings.get('attack_patterns', {}).get('severity'),
                'enabled': alert_settings.get('attack_patterns', {}).get('enabled', True),
                'description': alert_settings.get('attack_patterns', {}).get('description')
            },
            'alert_history': {
                'max_alerts': alert_settings.get('alert_history', {}).get('max_alerts', 1000),
                'description': alert_settings.get('alert_history', {}).get('description')
            }
        }
        
        # Load attack patterns from settings
        self.attack_patterns = settings.get('attack_patterns', {})
        # Load suspicious ports
        self.suspicious_ports = settings.get('suspicious_ports', {})

    def analyze_packet(self, src_ip, dst_ip, dst_port, packet_data, tcp_flags=None):
        """Analyze a network packet for potential threats"""
        alerts = []
        current_time = datetime.now()
        packet_size = len(packet_data) if packet_data else 0

        # Check if source IP is in the malicious list
        if self.detection_settings['malicious_ip']['enabled']:
            is_malicious, details = self.malicious_ip_manager.check_ip(src_ip)
            if is_malicious:
                alerts.append({
                    "type": "malicious_ip",
                    "severity": self.detection_settings['malicious_ip']['severity'],
                    "message": f"Connection from known malicious IP: {src_ip}",
                    "details": f"Reason: {details.get('reason', 'N/A')}, Category: {details.get('category', 'N/A')}"
                })

        # Check for suspicious ports
        if self.detection_settings['suspicious_port']['enabled'] and str(dst_port) in self.suspicious_ports:
            port_info = self.suspicious_ports[str(dst_port)]
            alerts.append({
                "type": "suspicious_port",
                "severity": port_info.get("risk", "medium"),
                "message": f"Suspicious port {dst_port} ({port_info.get('service', '')}) detected",
                "details": port_info.get("description", "")
            })

        # Update connection statistics, now keyed by source IP
        stats = self.connection_stats[src_ip]

        # --- Connection Flood Detection ---
        if self.thresholds['connection_flood']['enabled'] and self.thresholds['connection_flood']['count'] and self.thresholds['connection_flood']['window']:
            # Only count pure SYN packets for a "connection" flood
            if tcp_flags == 'S':
                flood_window = timedelta(seconds=self.thresholds['connection_flood']['window'])
                stats['connections'] = [t for t in stats['connections'] if current_time - t < flood_window]
                stats['connections'].append(current_time)

                if len(stats['connections']) >= self.thresholds['connection_flood']['count']:
                    if self._can_alert('connection_flood', stats, flood_window):
                        alerts.append({
                            "type": "connection_flood",
                            "severity": self.thresholds['connection_flood']['severity'],
                            "message": f"Connection flood detected",
                            "details": f"{len(stats['connections'])} connections in {self.thresholds['connection_flood']['window']} seconds"
                        })
                        stats['last_alert']['connection_flood'] = current_time

        # --- Port Scan Detection ---
        if self.thresholds['port_scan']['enabled'] and self.thresholds['port_scan']['count'] and self.thresholds['port_scan']['window']:
            scan_window = timedelta(seconds=self.thresholds['port_scan']['window'])
            
            # Prune old port scan records and add the new one
            stats['ports'] = [(t, p) for t, p in stats['ports'] if current_time - t < scan_window]
            stats['ports'].append((current_time, dst_port))

            # Count unique ports within the window
            unique_ports_in_window = len(set(p for t, p in stats['ports']))

            if unique_ports_in_window >= self.thresholds['port_scan']['count']:
                if self._can_alert('port_scan', stats, scan_window):
                    alerts.append({
                        "type": "port_scan",
                        "severity": self.thresholds['port_scan']['severity'],
                        "message": f"Port scan detected",
                        "details": f"Scanned {unique_ports_in_window} different ports in {self.thresholds['port_scan']['window']} seconds"
                    })
                    stats['last_alert']['port_scan'] = current_time
        
        # --- Data Exfiltration Detection ---
        if self.thresholds['data_exfiltration']['enabled'] and self.thresholds['data_exfiltration']['size'] and self.thresholds['data_exfiltration']['window']:
            exfil_window = timedelta(seconds=self.thresholds['data_exfiltration']['window'])
            stats['data_transferred'] = [(t, s) for t, s in stats['data_transferred'] if current_time - t < exfil_window]
            stats['data_transferred'].append((current_time, packet_size))
            
            total_data = sum(s for t, s in stats['data_transferred'])
            if total_data >= self.thresholds['data_exfiltration']['size']:
                if self._can_alert('data_exfiltration', stats, exfil_window):
                    alerts.append({
                        "type": "data_exfiltration",
                        "severity": self.thresholds['data_exfiltration']['severity'],
                        "message": f"Potential data exfiltration from {src_ip}",
                        "details": f"Transferred {total_data / 1024 / 1024:.2f} MB in {self.thresholds['data_exfiltration']['window']} seconds"
                    })
                    stats['last_alert']['data_exfiltration'] = current_time

        # Check for attack patterns in packet data
        if self.detection_settings['attack_patterns']['enabled'] and packet_data:
            # Decode packet data for regex matching, ignoring errors
            payload_str = ""
            if isinstance(packet_data, bytes):
                payload_str = packet_data.decode('utf-8', errors='ignore')
            
            if payload_str:
                for attack_type, patterns in self.attack_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, payload_str):
                            alerts.append({
                                "type": f"{attack_type}_attempt",
                                "severity": self.detection_settings['attack_patterns']['severity'],
                                "message": f"{attack_type.replace('_', ' ').title()} attempt detected",
                                "details": f"Pattern matched: {pattern}"
                            })
                            break # Move to next attack type once one pattern matches

        # Update alert history
        if alerts:
            self.alert_history.extend(alerts)
            # Keep only max alerts from settings
            max_alerts = self.detection_settings['alert_history']['max_alerts']
            if len(self.alert_history) > max_alerts:
                self.alert_history = self.alert_history[-max_alerts:]

        return alerts

    def _can_alert(self, alert_type, stats, cooldown_window):
        """Check if an alert can be triggered based on cooldown."""
        last_alert_time = stats['last_alert'].get(alert_type)
        if not last_alert_time:
            return True
        if (datetime.now() - last_alert_time) > cooldown_window:
            return True
        return False

    def get_alert_history(self):
        """Get the alert history"""
        return self.alert_history

    def get_connection_stats(self):
        """Get connection statistics"""
        return dict(self.connection_stats)

    def reset_stats(self):
        """Reset all statistics"""
        self.connection_stats.clear()
        self.alert_history.clear()
        logging.info("Threat detection statistics reset") 