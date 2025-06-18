import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from settings_manager import SettingsManager

class ThreatDetector:
    def __init__(self):
        self.settings_manager = SettingsManager()
        self.reload_settings()
        # Connection statistics tracking
        self.connection_stats = defaultdict(lambda: {
            'connections': [],
            'ports': set(),
            'data_transferred': 0,
            'last_alert': None
        })
        # Alert history
        self.alert_history = []
        # Initialize logging
        logging.basicConfig(
            filename='threat_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def reload_settings(self):
        settings = self.settings_manager.load_settings()
        alert_settings = settings.get('alert_settings', {})
        # Load thresholds
        self.thresholds = {
            'connection_flood': {
                'count': alert_settings.get('connection_flood', {}).get('threshold', 100),
                'window': alert_settings.get('connection_flood', {}).get('cooldown', 60),
                'description': alert_settings.get('connection_flood', {}).get('description', 'Number of connections from a single IP within time window')
            },
            'port_scan': {
                'count': alert_settings.get('port_scan', {}).get('threshold', 10),
                'window': alert_settings.get('port_scan', {}).get('cooldown', 300),
                'description': alert_settings.get('port_scan', {}).get('description', 'Number of different ports scanned within time window')
            },
            'data_exfiltration': {
                'size': alert_settings.get('data_transfer', {}).get('threshold', 10485760),
                'window': alert_settings.get('data_transfer', {}).get('cooldown', 60),
                'description': alert_settings.get('data_transfer', {}).get('description', 'Amount of data transferred within time window')
            }
        }
        # Load attack patterns
        self.attack_patterns = settings.get('attack_patterns', {
            'sql_injection': [
                r"(?i)(\\b(select|insert|update|delete|drop|union|exec|declare)\\b.*\\b(from|into|where|set)\\b)",
                r"(?i)(\\b(select|insert|update|delete|drop|union|exec|declare)\\b.*\\b(select|insert|update|delete|drop|union|exec|declare)\\b)",
                r"(?i)(\\b(select|insert|update|delete|drop|union|exec|declare)\\b.*\\b(select|insert|update|delete|drop|union|exec|declare)\\b.*\\b(select|insert|update|delete|drop|union|exec|declare)\\b)"
            ],
            'xss': [
                r"(?i)(<script.*?>.*?</script>)",
                r"(?i)(javascript:.*?\\(.*?\\))",
                r"(?i)(on\\w+\\s*=\\s*['\"].*?['\"])",
                r"(?i)(<img.*?onerror=.*?>)",
                r"(?i)(<iframe.*?src=.*?>)"
            ],
            'command_injection': [
                r"(?i)(\\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\\b.*\\b(>|<|\\||;|&|&&|\\|\\|)\\b)",
                r"(?i)(\\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\\b.*\\b(>|<|\\||;|&|&&|\\|\\|)\\b.*\\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\\b)",
                r"(?i)(\\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\\b.*\\b(>|<|\\||;|&|&&|\\|\\|)\\b.*\\b(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|php)\\b.*\\b(>|<|\\||;|&|&&|\\|\\|)\\b)"
            ]
        })
        # Load suspicious ports
        self.suspicious_ports = settings.get('suspicious_ports', {})

    def analyze_packet(self, src_ip, dst_ip, dst_port, packet_data):
        """Analyze a network packet for potential threats"""
        alerts = []
        current_time = datetime.now()

        # Check for suspicious ports
        if str(dst_port) in self.suspicious_ports:
            port_info = self.suspicious_ports[str(dst_port)]
            alerts.append({
                "type": "suspicious_port",
                "severity": port_info.get("risk", "medium"),
                "message": f"Suspicious port {dst_port} ({port_info.get('service', '')}) detected",
                "details": port_info.get("description", "")
            })

        # Update connection statistics
        conn_key = f"{src_ip}:{dst_ip}"
        stats = self.connection_stats[conn_key]

        # Clean old connections
        stats['connections'] = [t for t in stats['connections'] 
                              if current_time - t < timedelta(seconds=self.thresholds['connection_flood']['window'])]

        # Add new connection
        stats['connections'].append(current_time)
        stats['ports'].add(dst_port)

        # Check for connection flooding
        if len(stats['connections']) >= self.thresholds['connection_flood']['count']:
            if not stats['last_alert'] or \
               (current_time - stats['last_alert']) > timedelta(seconds=self.thresholds['connection_flood']['window']):
                alerts.append({
                    "type": "connection_flood",
                    "severity": "high",
                    "message": f"Connection flood detected from {src_ip}",
                    "details": f"{len(stats['connections'])} connections in {self.thresholds['connection_flood']['window']} seconds"
                })
                stats['last_alert'] = current_time

        # Check for port scanning
        if len(stats['ports']) >= self.thresholds['port_scan']['count']:
            if not stats['last_alert'] or \
               (current_time - stats['last_alert']) > timedelta(seconds=self.thresholds['port_scan']['window']):
                alerts.append({
                    "type": "port_scan",
                    "severity": "high",
                    "message": f"Port scan detected from {src_ip}",
                    "details": f"Scanned {len(stats['ports'])} different ports"
                })
                stats['last_alert'] = current_time

        # Check for attack patterns in packet data
        if packet_data:
            for attack_type, patterns in self.attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, packet_data.decode('utf-8', errors='ignore')):
                        alerts.append({
                            "type": f"{attack_type}_attempt",
                            "severity": "high",
                            "message": f"{attack_type.replace('_', ' ').title()} attempt detected",
                            "details": f"Pattern matched: {pattern}"
                        })

        # Update alert history
        if alerts:
            self.alert_history.extend(alerts)
            # Keep only last 1000 alerts
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-1000:]

        return alerts

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