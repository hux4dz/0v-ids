import time
from datetime import datetime
from collections import defaultdict
import logging
import json
import os
from settings_manager import SettingsManager
from threat_detection import ThreatDetector
from malicious_ip_manager import MaliciousIPManager
from scapy.all import ICMP


def deep_update(d, u):
    for k, v in u.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            deep_update(d[k], v)
        else:
            d[k] = v
    return d


def is_local_ip(ip):
    return ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.') or ip.startswith('127.')


class AlertManager:
    def __init__(self, callback):
        self.callback = callback
        self.threat_detector = ThreatDetector()
        self.malicious_ip_manager = MaliciousIPManager()

        self.suspicious_ports = {
            22: {"service": "SSH", "risk": "medium", "description": "Secure Shell - Remote access protocol"},
            23: {"service": "Telnet", "risk": "high", "description": "Telnet - Unencrypted remote access"},
            445: {"service": "SMB", "risk": "high", "description": "Server Message Block - File sharing protocol"},
            3389: {"service": "RDP", "risk": "medium", "description": "Remote Desktop Protocol"},
            1433: {"service": "MSSQL", "risk": "high", "description": "Microsoft SQL Server"},
            3306: {"service": "MySQL", "risk": "high", "description": "MySQL Database Server"},
            5432: {"service": "PostgreSQL", "risk": "high", "description": "PostgreSQL Database Server"},
            27017: {"service": "MongoDB", "risk": "high", "description": "MongoDB Database Server"},
            6379: {"service": "Redis", "risk": "high", "description": "Redis Cache Server"},
            9200: {"service": "Elasticsearch", "risk": "high", "description": "Elasticsearch Server"},
            11211: {"service": "Memcached", "risk": "high", "description": "Memcached Server"}
        }

        self.known_malicious_ips = {}
        self.connection_stats = defaultdict(lambda: {"count": 0, "last_seen": None, "bytes_sent": 0, "bytes_received": 0})

        self.alert_settings = {
            "connection_flood": {
                "threshold": 100,
                "cooldown": 60,
                "description": "Number of connections before alerting",
                "severity": "high"
            },
            "port_scan": {
                "threshold": 10,
                "cooldown": 300,
                "description": "Number of ports scanned before alerting",
                "severity": "high"
            },
            "data_transfer": {
                "threshold": 10485760,
                "cooldown": 60,
                "description": "Data transfer size threshold in bytes",
                "severity": "medium"
            },
            "suspicious_pattern": {
                "port_threshold": 5,
                "connection_threshold": 10,
                "cooldown": 300,
                "description": "Thresholds for suspicious connection patterns",
                "severity": "high"
            },
            "alert_cooldown": {
                "default": 60,
                "description": "Default cooldown period between repeated alerts"
            }
        }

        self.last_alert_time = {}

        self.ignored_ports = {
            80: "Standard HTTP traffic",
            443: "Standard HTTPS traffic",
            53: "Standard DNS traffic"
        }

        self.ignored_protocols = {
            "DNS": "Standard DNS protocol",
            "HTTP": "Standard HTTP protocol",
            "HTTPS": "Standard HTTPS protocol"
        }

        self.port_scan_attempts = defaultdict(lambda: {"count": 0, "first_seen": None, "last_seen": None})
        self.data_transfer_sizes = defaultdict(lambda: {"size": 0, "first_seen": None, "last_seen": None})
        self.connection_patterns = defaultdict(lambda: {
            "count": 0,
            "ports": set(),
            "first_seen": None,
            "last_seen": None,
            "total_bytes": 0
        })

        self.alert_stats = {
            "total_alerts": 0,
            "alerts_by_type": defaultdict(int),
            "alerts_by_severity": defaultdict(int)
        }

        self.malicious_ips = set()

        sm = SettingsManager()
        settings = sm.load_settings()
        self.alert_settings = deep_update(self.alert_settings, settings.get('alert_settings', {}))
        self.suspicious_ports = {int(k): v for k, v in settings.get('suspicious_ports', {}).items()}
        self.ignored_protocols = settings.get('ignored_protocols', self.ignored_protocols)
        self.excluded_high_volume_hosts = set(settings.get('excluded_high_volume_hosts', []))

    def add_excluded_host(self, ip):
        self.excluded_high_volume_hosts.add(ip)
        sm = SettingsManager()
        settings = sm.load_settings()
        settings['excluded_high_volume_hosts'] = list(self.excluded_high_volume_hosts)
        sm.save_settings(settings)

    def remove_excluded_host(self, ip):
        self.excluded_high_volume_hosts.discard(ip)
        sm = SettingsManager()
        settings = sm.load_settings()
        settings['excluded_high_volume_hosts'] = list(self.excluded_high_volume_hosts)
        sm.save_settings(settings)

    def is_excluded_host(self, ip):
        return ip in self.excluded_high_volume_hosts

    def analyze_packet(self, src_ip, dst_ip, dst_port, packet_data, tcp_flags=None):
        alerts = []

        # Check source IP for malicious activity
        is_malicious_src, src_details = self.malicious_ip_manager.check_ip(src_ip)
        if is_malicious_src:
            alerts.append({
                "type": "malicious_ip_connection",
                "severity": src_details.get("severity", "high"),
                "message": f"Connection from known malicious IP: {src_ip}",
                "details": f"Category: {src_details.get('category', 'unknown')}, Reason: {src_details.get('reason', 'No reason provided')}"
            })

        # Check destination IP for malicious activity
        is_malicious_dst, dst_details = self.malicious_ip_manager.check_ip(dst_ip)
        if is_malicious_dst:
            alerts.append({
                "type": "malicious_ip_visit",
                "severity": dst_details.get("severity", "high"),
                "message": f"Connection to known malicious IP: {dst_ip}",
                "details": f"Category: {dst_details.get('category', 'unknown')}, Reason: {dst_details.get('reason', 'No reason provided')}"
            })

        # Check for ICMP (ping) packets
        if packet_data and isinstance(packet_data, bytes):
            try:
                # Try to decode the packet data to check for ICMP
                if b'\x01' in packet_data[:20]:  # ICMP type 1 (echo request) is typically in the first 20 bytes
                    # Check both source and destination for malicious IPs in ping
                    if is_malicious_src:
                        alerts.append({
                            "type": "malicious_ip_ping",
                            "severity": src_details.get("severity", "high"),
                            "message": f"Ping from known malicious IP: {src_ip}",
                            "details": f"Category: {src_details.get('category', 'unknown')}, Reason: {src_details.get('reason', 'No reason provided')}"
                        })
                    if is_malicious_dst:
                        alerts.append({
                            "type": "malicious_ip_ping",
                            "severity": dst_details.get("severity", "high"),
                            "message": f"Ping to known malicious IP: {dst_ip}",
                            "details": f"Category: {dst_details.get('category', 'unknown')}, Reason: {dst_details.get('reason', 'No reason provided')}"
                        })
            except Exception as e:
                logging.error(f"Error processing packet data: {str(e)}")

        try:
            # Get alerts from threat detector
            alerts += self.threat_detector.analyze_packet(src_ip, dst_ip, dst_port, packet_data, tcp_flags=tcp_flags)

            # Update alert statistics
            if alerts:
                self.alert_stats["total_alerts"] += len(alerts)

                for alert in alerts:
                    alert_type = alert["type"]
                    self.alert_stats["alerts_by_type"][alert_type] += 1

                    severity = alert["severity"]
                    self.alert_stats["alerts_by_severity"][severity] += 1

                    if severity == "high":
                        self.malicious_ips.add(src_ip)
                        self.malicious_ips.add(dst_ip)

            return alerts

        except Exception as e:
            logging.error(f"Error analyzing packet: {str(e)}")
            return []

    def get_alert_stats(self):
        return self.alert_stats

    def get_connection_stats(self):
        return self.threat_detector.get_connection_stats()

    def get_alert_history(self):
        return self.threat_detector.get_alert_history()

    def add_malicious_ip(self, ip):
        self.malicious_ips.add(ip)
        logging.info(f"Added malicious IP: {ip}")

    def remove_malicious_ip(self, ip):
        self.malicious_ips.discard(ip)
        logging.info(f"Removed malicious IP: {ip}")

    def is_malicious_ip(self, ip):
        return ip in self.malicious_ips

    def get_alert_rules(self):
        return {
            "suspicious_ports": self.suspicious_ports,
            "alert_settings": self.alert_settings,
            "ignored_ports": self.ignored_ports,
            "ignored_protocols": self.ignored_protocols
        }

    def update_alert_settings(self, settings):
        for key, value in settings.items():
            if key in self.alert_settings:
                if isinstance(value, dict):
                    self.alert_settings[key].update(value)
                else:
                    self.alert_settings[key] = value
        logging.info(f"Updated alert settings: {settings}")

    def reset_stats(self):
        self.alert_stats = {
            "total_alerts": 0,
            "alerts_by_type": defaultdict(int),
            "alerts_by_severity": defaultdict(int)
        }
        self.malicious_ips.clear()
        self.threat_detector.reset_stats()
        logging.info("Alert statistics reset")
