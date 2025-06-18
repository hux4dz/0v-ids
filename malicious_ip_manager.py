import json
import os
import ipaddress
from datetime import datetime
import logging
from typing import Dict, List, Optional, Tuple

class MaliciousIPManager:
    def __init__(self, list_file: str = "malicious_ips.json"):
        self.list_file = list_file
        self.malicious_ips: Dict[str, Dict] = {}
        self.load_list()

    def load_list(self) -> None:
        """Load the malicious IP list from file"""
        try:
            if os.path.exists(self.list_file):
                with open(self.list_file, 'r') as f:
                    self.malicious_ips = json.load(f)
                logging.info(f"Loaded {len(self.malicious_ips)} malicious IPs from {self.list_file}")
        except Exception as e:
            logging.error(f"Error loading malicious IP list: {e}")
            self.malicious_ips = {}

    def save_list(self) -> None:
        """Save the malicious IP list to file"""
        try:
            with open(self.list_file, 'w') as f:
                json.dump(self.malicious_ips, f, indent=4)
            logging.info(f"Saved {len(self.malicious_ips)} malicious IPs to {self.list_file}")
        except Exception as e:
            logging.error(f"Error saving malicious IP list: {e}")

    def add_ip(self, ip: str, reason: str = "", category: str = "custom", 
               severity: str = "medium", expiry: Optional[str] = None, added_date: Optional[str] = None) -> Tuple[bool, str]:
        """
        Add an IP to the malicious list
        Returns: (success, message)
        """
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            # Check if IP already exists
            if ip in self.malicious_ips:
                return False, f"IP {ip} is already in the malicious list"
            
            # Add IP with metadata
            self.malicious_ips[ip] = {
                "added_date": added_date if added_date else datetime.now().isoformat(),
                "reason": reason,
                "category": category,
                "severity": severity,
                "expiry": expiry
            }
            
            self.save_list()
            return True, f"Successfully added {ip} to malicious list"
            
        except ValueError:
            return False, f"Invalid IP address: {ip}"
        except Exception as e:
            return False, f"Error adding IP: {str(e)}"

    def remove_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Remove an IP from the malicious list
        Returns: (success, message)
        """
        try:
            if ip in self.malicious_ips:
                del self.malicious_ips[ip]
                self.save_list()
                return True, f"Successfully removed {ip} from malicious list"
            return False, f"IP {ip} not found in malicious list"
        except Exception as e:
            return False, f"Error removing IP: {str(e)}"

    def check_ip(self, ip: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if an IP is in the malicious list
        Returns: (is_malicious, details)
        """
        try:
            if ip in self.malicious_ips:
                details = self.malicious_ips[ip]
                
                # Check if IP has expired
                if details.get("expiry"):
                    expiry_date = datetime.fromisoformat(details["expiry"])
                    if datetime.now() > expiry_date:
                        # Remove expired IP
                        self.remove_ip(ip)
                        return False, None
                
                return True, details
            return False, None
        except Exception as e:
            logging.error(f"Error checking IP {ip}: {e}")
            return False, None

    def get_all_ips(self) -> List[Dict]:
        """Get all malicious IPs with their details"""
        try:
            # Clean up expired IPs
            current_time = datetime.now()
            expired_ips = []
            
            for ip, details in self.malicious_ips.items():
                if details.get("expiry"):
                    expiry_date = datetime.fromisoformat(details["expiry"])
                    if current_time > expiry_date:
                        expired_ips.append(ip)
            
            # Remove expired IPs
            for ip in expired_ips:
                self.remove_ip(ip)
            
            # Return all active IPs
            return [
                {"ip": ip, **details}
                for ip, details in self.malicious_ips.items()
            ]
        except Exception as e:
            logging.error(f"Error getting IP list: {e}")
            return []

    def import_from_file(self, file_path: str) -> Tuple[int, int, List[str]]:
        """
        Import IPs from a text file (one IP per line)
        Returns: (total_imported, failed_imports, error_messages)
        """
        imported = 0
        failed = 0
        errors = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        success, message = self.add_ip(ip)
                        if success:
                            imported += 1
                        else:
                            failed += 1
                            errors.append(f"Failed to import {ip}: {message}")
            
            return imported, failed, errors
        except Exception as e:
            return 0, 0, [f"Error importing from file: {str(e)}"]

    def export_to_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Export malicious IPs to a text file
        Returns: (success, message)
        """
        try:
            with open(file_path, 'w') as f:
                for ip in self.malicious_ips.keys():
                    f.write(f"{ip}\n")
            return True, f"Successfully exported {len(self.malicious_ips)} IPs to {file_path}"
        except Exception as e:
            return False, f"Error exporting to file: {str(e)}"

    def get_stats(self) -> Dict:
        """Get statistics about the malicious IP list"""
        try:
            total = len(self.malicious_ips)
            categories = {}
            severities = {}
            
            for details in self.malicious_ips.values():
                # Count by category
                category = details.get("category", "unknown")
                categories[category] = categories.get(category, 0) + 1
                
                # Count by severity
                severity = details.get("severity", "unknown")
                severities[severity] = severities.get(severity, 0) + 1
            
            return {
                "total_ips": total,
                "by_category": categories,
                "by_severity": severities
            }
        except Exception as e:
            logging.error(f"Error getting stats: {e}")
            return {
                "total_ips": 0,
                "by_category": {},
                "by_severity": {}
            }

    def bulk_add_ips(self, ip_list: List[str], reason: str = "", category: str = "custom", 
                    severity: str = "high", expiry: Optional[str] = None) -> Tuple[int, int, List[str]]:
        """
        Bulk add multiple IPs with common metadata
        Returns: (successful_adds, failed_adds, error_messages)
        """
        successful = 0
        failed = 0
        errors = []
        
        for ip in ip_list:
            ip = ip.strip()
            if ip:
                success, message = self.add_ip(ip, reason, category, severity, expiry)
                if success:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"Failed to add {ip}: {message}")
        
        return successful, failed, errors 