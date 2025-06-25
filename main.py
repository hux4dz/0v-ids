import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, Menu, filedialog, messagebox, simpledialog
import psutil
import csv
import time
import logging
from datetime import datetime
import json
from collections import defaultdict
import re
from scapy.all import sniff, IP, TCP, UDP, get_if_list, sr1, ICMP, Raw
import socket
import struct
import requests
import whois
from concurrent.futures import ThreadPoolExecutor
from port_scanner import PortScanWindow
from ip_info import IPInfoWindow
from settings_manager import SettingsManager, SettingsWindow
from alert_manager import AlertManager
from alert_settings_window import AlertSettingsWindow

# Configure logging
logging.basicConfig(
    filename='network_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_network_interfaces():
    """Get list of available network interfaces with their details"""
    interfaces = []
    
    # Get all network interfaces using psutil
    net_if_addrs = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    
    for iface_name in net_if_addrs.keys():
        try:
            # Get interface addresses
            addrs = net_if_addrs[iface_name]
            stats = net_if_stats.get(iface_name)
            
            # Get IPv4 address
            ipv4 = next((addr.address for addr in addrs if addr.family == socket.AF_INET), "No IP")
            
            # Get interface status
            is_up = stats.isup if stats else False
            speed = f"{stats.speed}Mbps" if stats and stats.speed > 0 else "Unknown"
            
            # Create interface description
            description = f"{iface_name} ({ipv4}) - {speed}"
            if not is_up:
                description += " [Down]"
            
            interfaces.append({
                "name": iface_name,
                "ip": ipv4,
                "description": description,
                "is_up": is_up
            })
            
        except Exception as e:
            logging.error(f"Error getting interface details for {iface_name}: {e}")
            # Still add the interface even if we can't get all details
            interfaces.append({
                "name": iface_name,
                "ip": "Unknown",
                "description": f"{iface_name} (Unknown)",
                "is_up": False
            })
    
    # Sort interfaces: active first, then by name
    interfaces.sort(key=lambda x: (not x["is_up"], x["name"]))
    return interfaces

# --- 1. NetworkMonitor Class ---
class NetworkMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.paused = False
        self.alert_manager = AlertManager(callback)
        self.stats = {
            "total_packets": 0,
            "suspicious_connections": 0,
            "alerts": []
        }
        self.last_log_time = time.time()
        self.log_interval = 1.0
        self.monitor_thread = None
        self.selected_interface = None

    def set_interface(self, interface_name):
        """Set the network interface to monitor"""
        if self.running:
            self.stop()
        self.selected_interface = interface_name
        self.callback("log", f"[SYSTEM] Selected interface: {interface_name}")
        logging.info(f"Interface set to: {interface_name}")

    def start(self):
        if self.running:
            return

        if not self.selected_interface:
            self.callback("log", "[ERROR] No network interface selected")
            return

        self.running = True
        self.paused = False
        self.monitor_thread = threading.Thread(target=self._monitor_traffic, daemon=True)
        self.monitor_thread.start()
        self.callback("log", f"[SYSTEM] Network monitoring started on {self.selected_interface}")
        logging.info(f"Network monitoring started on {self.selected_interface}")

    def stop(self):
        if not self.running:
            return

        self.running = False
        self.callback("log", "[SYSTEM] Network monitoring thread stopped.")
        logging.info("Network monitoring stopped")

    def toggle_pause(self):
        self.paused = not self.paused
        status = "paused" if self.paused else "resumed"
        self.callback("log", f"[SYSTEM] Monitoring {status}.")
        logging.info(f"Monitoring {status}")

    def _packet_callback(self, packet):
        if not self.running or self.paused:
            return

        try:
            # Load ignored processes from settings
            settings_manager = SettingsManager()
            settings = settings_manager.load_settings()
            ignored_processes = set([p.lower() for p in settings.get('ignored_processes', [])])

            # Helper to get process name for a connection
            def get_process_name(ip, port, direction):
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if direction == "OUTGOING":
                            if conn.laddr and conn.raddr and \
                               conn.laddr.ip == ip and conn.laddr.port == port:
                                if conn.pid:
                                    return psutil.Process(conn.pid).name().lower()
                        elif direction == "INCOMING":
                            if conn.raddr and conn.laddr and \
                               conn.raddr.ip == ip and conn.raddr.port == port:
                                if conn.pid:
                                    return psutil.Process(conn.pid).name().lower()
                    except Exception:
                        continue
                return None

            if isinstance(packet, dict): # HTTP data
                src_ip = packet['src_ip']
                dst_ip = packet['dst_ip']
                dst_port = packet['dst_port']
                packet_bytes = packet['payload']
                protocol = "HTTP"
                direction = "INCOMING" if dst_ip == self.get_local_ip() else "OUTGOING"
                analysis_src_ip = src_ip
                analysis_dst_ip = dst_ip
                analysis_dst_port = dst_port
                tcp_flags = None
            elif IP in packet: # Scapy packet
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                tcp_flags = None
                if TCP in packet:
                    dst_port = packet[TCP].dport
                    src_port = packet[TCP].sport
                    protocol = "TCP"
                    tcp_flags = packet[TCP].flags
                elif UDP in packet:
                    dst_port = packet[UDP].dport
                    src_port = packet[UDP].sport
                    protocol = "UDP"
                elif ICMP in packet:
                    dst_port = 0  # ICMP doesn't use ports
                    src_port = 0
                    protocol = "ICMP"
                else:
                    return # Not a supported protocol
                local_ip = self.get_local_ip()
                if dst_ip == local_ip:
                    direction = "INCOMING"
                    proc_ip = src_ip
                    proc_port = src_port
                else:
                    direction = "OUTGOING"
                    proc_ip = src_ip
                    proc_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)

                # We should NOT swap src and dst for analysis.
                # The ThreatDetector should analyze based on the actual source of the packet.
                analysis_src_ip = src_ip
                analysis_dst_ip = dst_ip
                analysis_dst_port = dst_port
                
                packet_bytes = bytes(packet.getlayer(Raw)) if packet.haslayer(Raw) else b''
            else:
                return # Not a recognizable packet format

            # --- Ignore packets from ignored processes ---
            proc_name = get_process_name(proc_ip, proc_port, direction)
            if proc_name and proc_name in ignored_processes:
                return  # Skip analysis for ignored processes

            # Update statistics
            self.stats["total_packets"] += 1

            # Pass the packet bytes to the alert manager for analysis
            alerts = self.alert_manager.analyze_packet(
                analysis_src_ip, analysis_dst_ip, analysis_dst_port, packet_bytes, tcp_flags=tcp_flags
            )

            if alerts:
                self.stats["suspicious_connections"] += 1
                for alert in alerts:
                    self.stats["alerts"].append({
                        "timestamp": datetime.now().isoformat(),
                        "alert": alert["message"],
                        "src": analysis_src_ip,
                        "dst": analysis_dst_ip,
                        "port": analysis_dst_port,
                        "type": alert["type"],
                        "severity": alert["severity"],
                        "details": alert["details"],
                        "direction": direction
                    })
                    self.callback(
                        "alert",
                        alert["message"],
                        src_ip=analysis_src_ip,
                        dst_ip=analysis_dst_ip,
                        dst_port=analysis_dst_port,
                        alert_type=alert.get("type", ""),
                        severity=alert.get("severity", ""),
                        details=alert.get("details", ""),
                        direction=direction
                    )

            # Rate limit logging
            current_time = time.time()
            if current_time - self.last_log_time >= self.log_interval:
                msg = f"[{direction}] {src_ip}:{getattr(packet, 'sport', 'N/A')} -> {dst_ip}:{dst_port} ({protocol})"
                self.callback("log", msg, src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, direction=direction)
                self.last_log_time = current_time

            self.callback("packet", (src_ip, dst_ip, dst_port, direction))

        except Exception as e:
            if self.running:
                error_msg = f"[Error] Packet processing: {str(e)}"
                self.callback("log", error_msg)
                logging.error(error_msg)

    def get_local_ip(self):
        """Get the local IP address of the selected interface"""
        try:
            if self.selected_interface:
                # Get interface addresses
                addrs = psutil.net_if_addrs().get(self.selected_interface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        return addr.address
            return "127.0.0.1"  # Fallback
        except Exception:
            return "127.0.0.1"  # Fallback

    def _monitor_traffic(self):
        try:
            # Start packet capture with interface filter
            sniff(
                iface=self.selected_interface,
                filter="ip and (tcp or udp or icmp)",
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            error_msg = f"[Error] Packet capture failed on {self.selected_interface}: {str(e)}"
            self.callback("log", error_msg)
            logging.error(error_msg)
        finally:
            self.running = False
            self.callback("update_ui_on_stop")

    def get_current_connections(self):
        connections_data = []
        # Load ignored processes from settings
        settings_manager = SettingsManager()
        settings = settings_manager.load_settings()
        ignored_processes = set([p.lower() for p in settings.get('ignored_processes', [])])
        for conn in psutil.net_connections(kind='inet'):
            try:
                proc = psutil.Process(conn.pid)
                proc_name = proc.name().lower()
                if proc_name in ignored_processes:
                    continue  # Skip ignored processes
                # Include both listening and established connections
                if conn.raddr:  # Outgoing connections
                    connections_data.append({
                        "pid": conn.pid,
                        "process_name": proc.name(),
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "direction": "OUTGOING"
                    })
                elif conn.status == 'LISTEN':  # Listening connections (incoming)
                    connections_data.append({
                        "pid": conn.pid,
                        "process_name": proc.name(),
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": "LISTENING",
                        "status": conn.status,
                        "direction": "INCOMING"
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                error_msg = f"[Error] psutil connection fetching: {e}"
                self.callback("log", error_msg)
                logging.error(error_msg)
        return connections_data

    def get_stats(self):
        stats = self.stats.copy()
        stats.update(self.alert_manager.get_alert_stats())
        return stats

    def add_malicious_ip(self, ip):
        self.alert_manager.add_malicious_ip(ip)
        logging.info(f"Added malicious IP: {ip}")

    def remove_malicious_ip(self, ip):
        self.alert_manager.remove_malicious_ip(ip)
        logging.info(f"Removed malicious IP: {ip}")

# --- 2. ConnectionManager Class ---
class ConnectionManager:
    def __init__(self):
        self.connections = {}  # key: (pid, proc_name, local_addr, remote_addr, status, direction), value: {data, is_pinned, pin_tag}
        self.pinned_rows = {}  # key: (pid, proc_name, local_addr, remote_addr, status, direction), value: pin_tag
        self.color_cycle = ["#ffe699", "#d9ead3", "#cfe2f3", "#f4cccc", "#ead1dc"]
        self.color_index = 0

    def add_or_update_connection(self, conn_data):
        # Create a tuple for the key based on common identifiable values
        key = (
            conn_data["pid"],
            conn_data["process_name"],
            conn_data["local_address"],
            conn_data["remote_address"],
            conn_data["status"],
            conn_data.get("direction", "UNKNOWN")
        )
        if key not in self.connections:
            self.connections[key] = {"data": conn_data, "is_pinned": False, "pin_tag": ""}

    def get_all_connections_for_display(self):
        # Returns connections in a format suitable for Treeview insertion
        display_data = []
        for key, conn_info in self.connections.items():
            values = list(key) # Convert tuple key back to list of values
            tag = conn_info["pin_tag"] if conn_info["is_pinned"] else ""
            display_data.append({"values": values, "tag": tag})
        return display_data

    def pin_connection(self, connection_key):
        if connection_key in self.connections and not self.connections[connection_key]["is_pinned"]:
            color = self.color_cycle[self.color_index % len(self.color_cycle)]
            tag_name = f"pin_color_{self.color_index}"
            self.connections[connection_key]["is_pinned"] = True
            self.connections[connection_key]["pin_tag"] = tag_name
            self.pinned_rows[connection_key] = tag_name
            self.color_index += 1
            return tag_name, color
        return None, None

    def unpin_connection(self, connection_key):
        if connection_key in self.connections and self.connections[connection_key]["is_pinned"]:
            self.connections[connection_key]["is_pinned"] = False
            self.connections[connection_key]["pin_tag"] = ""
            if connection_key in self.pinned_rows:
                del self.pinned_rows[connection_key]
            return True
        return False

    def is_connection_pinned(self, src_ip, dst_ip, dst_port):
        for key in self.pinned_rows:
            # key is (PID, Process, Local, Remote, Status, Direction)
            pinned_local_ip, pinned_local_port = key[2].split(":")
            pinned_remote_ip, pinned_remote_port = key[3].split(":")

            if str(src_ip) == pinned_local_ip and \
               str(dst_ip) == pinned_remote_ip and \
               str(dst_port) == pinned_remote_port:
                return True
        return False

    def export_connections(self, filename):
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["PID", "Process", "Local", "Remote", "Status", "Direction", "Pinned"])
            for key, conn_info in self.connections.items():
                is_pinned = "Yes" if conn_info["is_pinned"] else "No"
                writer.writerow(list(key) + [is_pinned])

    def import_connections(self, filename):
        self.connections.clear()
        self.pinned_rows.clear()
        self.color_index = 0
        imported_pinned_tags = []

        with open(filename, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                conn_key = (
                    int(row["PID"]),
                    row["Process"],
                    row["Local"],
                    row["Remote"],
                    row["Status"],
                    row["Direction"]
                )
                conn_data = {
                    "pid": int(row["PID"]),
                    "process_name": row["Process"],
                    "local_address": row["Local"],
                    "remote_address": row["Remote"],
                    "status": row["Status"],
                    "direction": row["Direction"]
                }
                self.connections[conn_key] = {"data": conn_data, "is_pinned": False, "pin_tag": ""}

                if row.get("Pinned", "No") == "Yes":
                    # Re-pin the connection using the manager's pin method
                    tag_name, color = self.pin_connection(conn_key)
                    if tag_name and color:
                        imported_pinned_tags.append((tag_name, color))
        return imported_pinned_tags # Return tags and colors for GUI to configure

# Add new security tools class
class SecurityTools:
    def __init__(self, callback):
        self.callback = callback
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.settings_manager = SettingsManager()
        self.api_keys = self.settings_manager.get_setting('api_keys')  # Get entire api_keys category

    def get_ip_info(self, ip):
        """Get information about an IP address"""
        try:
            # Basic IP information
            info = {
                "ip": ip,
                "hostname": socket.gethostbyaddr(ip)[0] if self._is_valid_ip(ip) else "Unknown",
                "whois": self._get_whois_info(ip),
                "geolocation": self._get_geolocation(ip)
            }
            return info
        except Exception as e:
            return {"error": str(e)}

    def _is_valid_ip(self, ip):
        """Check if IP is valid"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

    def _get_whois_info(self, ip):
        """Get WHOIS information for an IP"""
        try:
            w = whois.whois(ip)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date)
            }
        except:
            return "No WHOIS information available"

    def _get_geolocation(self, ip):
        """Get geolocation information for an IP"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown")
                }
        except:
            pass
        return "No geolocation information available"

    def check_malicious_ip(self):
        """Open malicious IP check window for selected connection"""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            remote_addr = values[3].split(":")[0]  # Get IP from Remote column
            MaliciousIPCheckWindow(self.master, remote_addr, self.security_tools)  # Pass security_tools instead of api_keys

# Add new window classes for security tools
class SecurityToolWindow:
    def __init__(self, parent, title):
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("600x400")
        self.window.transient(parent)  # Make window stay on top of parent
        self.window.grab_set()  # Make window modal
        
        # Create main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create text area with scrollbar
        self.text_area = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        self.text_area.tag_config("info", foreground="blue")
        self.text_area.tag_config("warning", foreground="red")
        self.text_area.tag_config("success", foreground="green")
        
    def add_text(self, text, tag=None):
        self.text_area.insert(tk.END, text + "\n", tag)
        self.text_area.see(tk.END)
        
    def clear(self):
        self.text_area.delete(1.0, tk.END)

class IPInfoWindow(SecurityToolWindow):
    def __init__(self, parent, ip, security_tools):
        super().__init__(parent, f"IP Information - {ip}")
        self.ip = ip
        self.security_tools = security_tools
        
        # Add control buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export", command=self.export_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=self.window.destroy).pack(side=tk.RIGHT, padx=5)
        
        self.refresh_info()
        
    def refresh_info(self):
        self.clear()
        self.add_text(f"Gathering information for {self.ip}...", "info")
        
        def get_info():
            info = self.security_tools.get_ip_info(self.ip)
            
            if "error" in info:
                self.add_text(f"Error: {info['error']}", "warning")
                return
            
            self.add_text(f"\nIP Information for {self.ip}:", "info")
            self.add_text(f"Hostname: {info.get('hostname', 'Unknown')}", "info")
            
            if isinstance(info.get('whois'), dict):
                whois_info = info['whois']
                self.add_text("\nWHOIS Information:", "info")
                self.add_text(f"Registrar: {whois_info.get('registrar', 'Unknown')}", "info")
                self.add_text(f"Creation Date: {whois_info.get('creation_date', 'Unknown')}", "info")
                self.add_text(f"Expiration Date: {whois_info.get('expiration_date', 'Unknown')}", "info")
            
            if isinstance(info.get('geolocation'), dict):
                geo_info = info['geolocation']
                self.add_text("\nGeolocation Information:", "info")
                self.add_text(f"Location: {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}", "info")
                self.add_text(f"ISP: {geo_info.get('isp', 'Unknown')}", "info")
        
        self.security_tools.executor.submit(get_info)
        
    def export_info(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"ip_info_{self.ip}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.text_area.get(1.0, tk.END))
            self.add_text(f"\nInformation exported to {filename}", "success")

class MaliciousIPCheckWindow(SecurityToolWindow):
    def __init__(self, parent, ip, security_tools):
        super().__init__(parent, f"Malicious IP Check - {ip}")
        self.ip = ip
        self.security_tools = security_tools
        
        # Set window size and make it resizable
        self.window.geometry("800x600")
        self.window.minsize(600, 400)  # Set minimum window size
        
        # Configure grid weights for resizing
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        # Create a frame for the header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Add IP address label
        ttk.Label(header_frame, text=f"IP Address: {ip}", font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT)
        
        # Add timestamp
        self.timestamp_label = ttk.Label(header_frame, text="", font=("TkDefaultFont", 9))
        self.timestamp_label.pack(side=tk.RIGHT)
        
        # Add control buttons with better styling
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        # Style the buttons
        style = ttk.Style()
        style.configure("Action.TButton", padding=5)
        
        ttk.Button(button_frame, text="Check Again", command=self.check_ip, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Report", command=self.export_report, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=self.window.destroy, style="Action.TButton").pack(side=tk.RIGHT, padx=5)
        
        # Add a separator
        ttk.Separator(self.main_frame, orient='horizontal').pack(fill=tk.X, pady=5)
        
        # Configure text area for better resizing
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure additional text tags
        self.text_area.tag_config("api", foreground="purple")
        self.text_area.tag_config("timestamp", foreground="gray")
        self.text_area.tag_config("header", font=("TkDefaultFont", 10, "bold"))
        
        # Center the window on the parent
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
        
        self.check_ip()
        
    def check_ip(self):
        self.clear()
        self.add_text("Starting IP check...", "info")
        self.timestamp_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        def check():
            try:
                # Get API keys from settings
                api_keys = self.security_tools.settings_manager.get_setting('api_keys')
                
                if not api_keys:
                    self.add_text("\nError: No API keys configured. Please add API keys in Settings.", "warning")
                    return
                
                # Check each available API
                results = []
                used_apis = []
                
                for api_name, api_key in api_keys.items():
                    if not api_key:  # Skip if API key is empty
                        continue
                        
                    try:
                        self.add_text(f"\nChecking {api_name.upper()}...", "api")
                        if api_name == 'abuseipdb':
                            result = self._check_abuseipdb(api_key)
                        elif api_name == 'virustotal':
                            result = self._check_virustotal(api_key)
                        elif api_name == 'alienvault':
                            result = self._check_alienvault(api_key)
                        else:
                            continue
                            
                        if result:
                            results.append(result)
                            used_apis.append(api_name.upper())
                            self.add_text(f"✓ {api_name.upper()} check completed", "success")
                    except Exception as e:
                        self.add_text(f"✗ {api_name.upper()} check failed: {str(e)}", "warning")
                
                if not results:
                    self.add_text("\nNo results available from any API.", "warning")
                    return
                
                # Add a separator
                self.add_text("\n" + "="*50)
                
                # Show summary header
                self.add_text("\nCheck Summary:", "header")
                self.add_text(f"IP Address: {self.ip}")
                self.add_text(f"Check Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "timestamp")
                self.add_text(f"APIs Used: {', '.join(used_apis)}")
                
                # Combine results
                is_malicious = any(r.get('is_malicious', False) for r in results)
                confidence = max((r.get('confidence', 0) for r in results), default=0)
                reports = sum(r.get('reports', 0) for r in results)
                
                # Add another separator
                self.add_text("\n" + "="*50)
                
                # Show results
                if is_malicious:
                    self.add_text("\nWARNING: IP is potentially malicious!", "warning")
                    self.add_text(f"Confidence Score: {confidence}%", "warning")
                    self.add_text(f"Total Reports: {reports}", "warning")
                else:
                    self.add_text("\nIP appears to be clean", "success")
                    self.add_text(f"Confidence Score: {confidence}%", "success")
                    self.add_text(f"Total Reports: {reports}", "success")
                
            except Exception as e:
                self.add_text(f"\nError during IP check: {str(e)}", "warning")
        
        self.security_tools.executor.submit(check)
    
    def _check_abuseipdb(self, api_key):
        """Check IP using AbuseIPDB API"""
        try:
            url = f'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': api_key,
                'Accept': 'application/json',
            }
            params = {
                'ipAddress': self.ip,
                'maxAgeInDays': '90'
            }
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'is_malicious': data['abuseConfidenceScore'] > 25,
                    'confidence': data['abuseConfidenceScore'],
                    'reports': data['totalReports']
                }
        except Exception as e:
            self.add_text(f"AbuseIPDB API error: {str(e)}", "warning")
        return None
    
    def _check_virustotal(self, api_key):
        """Check IP using VirusTotal API"""
        try:
            url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {'apikey': api_key, 'ip': self.ip}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                return {
                    'is_malicious': positives > 0,
                    'confidence': (positives / total * 100) if total > 0 else 0,
                    'reports': positives
                }
        except Exception as e:
            self.add_text(f"VirusTotal API error: {str(e)}", "warning")
        return None
    
    def _check_alienvault(self, api_key):
        """Check IP using AlienVault OTX API"""
        try:
            url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{self.ip}/general'
            headers = {'X-OTX-API-KEY': api_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                return {
                    'is_malicious': pulse_count > 0,
                    'confidence': min(pulse_count * 10, 100),  # Scale confidence based on pulse count
                    'reports': pulse_count
                }
        except Exception as e:
            self.add_text(f"AlienVault API error: {str(e)}", "warning")
        return None
        
    def export_report(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"malicious_check_{self.ip}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.text_area.get(1.0, tk.END))
            self.add_text(f"\nReport exported to {filename}", "success")

# --- 3. GUI Class ---
class IDSAppGUI:
    def __init__(self, master, network_monitor, connection_manager):
        self.master = master
        self.master.title("Python-based IDS System")
        self.master.geometry("1200x800")

        self.network_monitor = network_monitor
        self.connection_manager = connection_manager
        self.security_tools = SecurityTools(self.log_message)
        self.settings_manager = self.security_tools.settings_manager
        self.api_keys = self.settings_manager.get_setting('api_keys')  # Initialize API keys

        self.filter_var = tk.StringVar()
        self.filter_history = []
        self.max_filter_history = 10
        self._create_widgets()
        self.update_connections_periodically()
        self.update_stats_periodically()

    def _create_widgets(self):
        # Main container
        main_container = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Left panel for controls and stats
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, weight=1)

        # Right panel for connections and logs
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=2)

        # Controls Frame
        controls_frame = ttk.LabelFrame(left_panel, text="Controls")
        controls_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create a frame for the control buttons first
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        # Create all buttons first
        self.start_btn = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring_ui)
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_btn = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring_ui, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.pause_btn = ttk.Button(button_frame, text="Pause", command=self.toggle_pause_ui, state='disabled')
        self.pause_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Add Settings button
        self.settings_btn = ttk.Button(button_frame, text="Settings", command=self.show_settings)
        self.settings_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        # Add Malicious IP Manager button
        self.malicious_ip_btn = ttk.Button(button_frame, text="Malicious IP Manager", command=self.show_malicious_ip_manager)
        self.malicious_ip_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        # Add Alert Settings button
        self.alert_settings_btn = ttk.Button(button_frame, text="Alert Settings", command=self.show_alert_settings)
        self.alert_settings_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        # Interface Selection Frame
        interface_frame = ttk.LabelFrame(controls_frame, text="Network Interface Selection")
        interface_frame.pack(fill=tk.X, padx=5, pady=5)

        # Interface dropdown with refresh button
        interface_select_frame = ttk.Frame(interface_frame)
        interface_select_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(interface_select_frame, text="Select Interface:").pack(side=tk.LEFT, padx=5)
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            interface_select_frame, 
            textvariable=self.interface_var,
            state="readonly",
            width=40
        )
        self.interface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Add refresh button
        refresh_btn = ttk.Button(
            interface_select_frame,
            text="↻",
            width=3,
            command=self.refresh_interfaces
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Populate interface list
        self.update_interface_list()
        
        # Bind interface selection event
        self.interface_combo.bind('<<ComboboxSelected>>', self.on_interface_selected)

        # Stats Frame
        stats_frame = ttk.LabelFrame(left_panel, text="Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)

        self.stats_label = ttk.Label(stats_frame, text="No data available")
        self.stats_label.pack(padx=5, pady=5)

        # Alerts Frame
        alerts_frame = ttk.LabelFrame(left_panel, text="Recent Alerts")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add Clear Alerts and Export Alerts buttons
        alerts_btn_frame = ttk.Frame(alerts_frame)
        alerts_btn_frame.pack(fill=tk.X, padx=5, pady=(2, 0))
        ttk.Button(alerts_btn_frame, text="Clear Alerts", command=self.clear_alerts).pack(side=tk.RIGHT)
        ttk.Button(alerts_btn_frame, text="Export Alerts", command=self.export_alerts_to_file).pack(side=tk.RIGHT, padx=(0, 5))

        # --- Replace ScrolledText with Treeview for alerts ---
        self.alerts_tree = ttk.Treeview(
            alerts_frame,
            columns=("Time", "Type", "Severity", "Source IP", "Destination IP", "Port", "Direction", "Message"),
            show="headings",
            height=10
        )
        self.alerts_tree.heading("Time", text="Time")
        self.alerts_tree.column("Time", width=70, anchor=tk.CENTER)
        self.alerts_tree.heading("Type", text="Type")
        self.alerts_tree.column("Type", width=90, anchor=tk.CENTER)
        self.alerts_tree.heading("Severity", text="Severity")
        self.alerts_tree.column("Severity", width=70, anchor=tk.CENTER)
        self.alerts_tree.heading("Source IP", text="Source IP")
        self.alerts_tree.column("Source IP", width=140, anchor=tk.CENTER)
        self.alerts_tree.heading("Destination IP", text="Destination IP")
        self.alerts_tree.column("Destination IP", width=140, anchor=tk.CENTER)
        self.alerts_tree.heading("Port", text="Port")
        self.alerts_tree.column("Port", width=60, anchor=tk.CENTER)
        self.alerts_tree.heading("Direction", text="Direction")
        self.alerts_tree.column("Direction", width=80, anchor=tk.CENTER)
        self.alerts_tree.heading("Message", text="Message")
        self.alerts_tree.column("Message", width=270, anchor=tk.W)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add horizontal scrollbar
        alert_scroll_x = ttk.Scrollbar(alerts_frame, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(xscrollcommand=alert_scroll_x.set)
        alert_scroll_x.pack(fill=tk.X, side=tk.BOTTOM)

        # Add right-click context menu for alerts
        self.alerts_menu = Menu(self.alerts_tree, tearoff=0)
        self.alerts_menu.add_command(label="Scan Port Source IP", command=self.scan_alert_src_ip)
        self.alerts_menu.add_command(label="Scan Port Destination IP", command=self.scan_alert_dst_ip)
        self.alerts_menu.add_command(label="Show Source IP Info", command=self.show_alert_src_ip_info)
        self.alerts_menu.add_command(label="Show Destination IP Info", command=self.show_alert_dst_ip_info)
        self.alerts_menu.add_command(label="Check Source Malicious IP", command=self.check_alert_src_malicious_ip)
        self.alerts_menu.add_command(label="Check Destination Malicious IP", command=self.check_alert_dst_malicious_ip)
        self.alerts_tree.bind("<Button-3>", self.show_alerts_context_menu)

        # Store alerts for context menu actions
        self._recent_alerts = []

        # Table Frame
        conn_frame = ttk.LabelFrame(right_panel, text="Active Connections")
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add filter frame
        filter_frame = ttk.Frame(conn_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        # Filter label and entry
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=40)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.filter_entry.bind('<Return>', self.apply_filter)
        self.filter_entry.bind('<KeyRelease>', self._on_filter_change)

        # Filter buttons
        ttk.Button(filter_frame, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="Clear", command=self.clear_filter).pack(side=tk.LEFT, padx=2)
        
        # Filter presets button
        presets_button = ttk.Button(filter_frame, text="Presets ▼", command=self.show_filter_presets)
        presets_button.pack(side=tk.LEFT, padx=2)
        
        # Create presets menu with categories
        self.presets_menu = Menu(presets_button, tearoff=0)
        
        # Connection Status Presets
        status_menu = Menu(self.presets_menu, tearoff=0)
        self.presets_menu.add_cascade(label="Connection Status", menu=status_menu)
        self.presets_menu.add_command(label="All Established Connections", 
                              command=lambda: self.apply_preset_filter("status established"))
        self.presets_menu.add_command(label="All Listening Ports", 
                              command=lambda: self.apply_preset_filter("status listen"))
        self.presets_menu.add_command(label="All Time Wait Connections", 
                              command=lambda: self.apply_preset_filter("status time_wait"))
        self.presets_menu.add_command(label="All Close Wait Connections", 
                              command=lambda: self.apply_preset_filter("status close_wait"))
        
        # Common Ports Presets
        ports_menu = Menu(self.presets_menu, tearoff=0)
        self.presets_menu.add_cascade(label="Common Ports", menu=ports_menu)
        ports_menu.add_command(label="Web Traffic (80, 443)", 
                             command=lambda: self.apply_preset_filter("port 80 or port 443"))
        ports_menu.add_command(label="DNS (53)", 
                             command=lambda: self.apply_preset_filter("port 53"))
        ports_menu.add_command(label="SSH (22)", 
                             command=lambda: self.apply_preset_filter("port 22"))
        ports_menu.add_command(label="RDP (3389)", 
                             command=lambda: self.apply_preset_filter("port 3389"))
        ports_menu.add_command(label="Custom Port...", 
                             command=self.show_custom_port_filter)
        
        # Common Applications
        apps_menu = Menu(self.presets_menu, tearoff=0)
        self.presets_menu.add_cascade(label="Common Applications", menu=apps_menu)
        apps_menu.add_command(label="Chrome Browser", 
                            command=lambda: self.apply_preset_filter("process chrome"))
        apps_menu.add_command(label="Firefox Browser", 
                            command=lambda: self.apply_preset_filter("process firefox"))
        apps_menu.add_command(label="Edge Browser", 
                            command=lambda: self.apply_preset_filter("process msedge"))
        apps_menu.add_command(label="System Processes", 
                            command=lambda: self.apply_preset_filter("process system"))
        
        # Security Related
        security_menu = Menu(self.presets_menu, tearoff=0)
        self.presets_menu.add_cascade(label="Security", menu=security_menu)
        security_menu.add_command(label="All Remote Connections", 
                                command=lambda: self.apply_preset_filter("status established and not ip 127.0.0.1"))
        security_menu.add_command(label="High Ports (>1024)", 
                                command=lambda: self.apply_preset_filter("port > 1024"))
        security_menu.add_command(label="Local Connections Only", 
                                command=lambda: self.apply_preset_filter("ip 127.0.0.1"))
        
        self.presets_menu.add_separator()
        self.presets_menu.add_command(label="Clear Filter", 
                                    command=self.clear_filter)

        # Add filter help tooltip
        self._create_filter_help_tooltip(filter_frame)

        self.tree_scroll = ttk.Scrollbar(conn_frame)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            conn_frame,
            columns=("PID", "Process", "Local", "Remote", "Status", "Direction"),
            show='headings',
            yscrollcommand=self.tree_scroll.set
        )
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            if col == "Direction":
                self.tree.column(col, width=100)
            else:
                self.tree.column(col, width=150)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree_scroll.config(command=self.tree.yview)

        # Log Area Frame
        log_frame = ttk.LabelFrame(right_panel, text="Log Messages")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_area.tag_config("pinned", foreground="orange", font=("TkDefaultFont", 9, "bold"))
        self.log_area.tag_config("alert", foreground="red", font=("TkDefaultFont", 9, "bold"))

        # Status Bar
        self.status_bar = ttk.Label(self.master, text="Status: Stopped", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Context Menu
        self.tree.bind("<Button-3>", self.show_tree_context_menu)
        self.tree_menu = Menu(self.tree, tearoff=0)
        
        # Connection Management
        self.tree_menu.add_command(label="Pin Connection", command=self.pin_selected_connection)
        self.tree_menu.add_command(label="Unpin Connection", command=self.unpin_selected_connection)
        self.tree_menu.add_command(label="Add Process to Ignore List", command=self.add_selected_process_to_ignore_list)
        self.tree_menu.add_separator()
        
        # Security Tools Right Click Menu
        security_menu = Menu(self.tree_menu, tearoff=0)
        self.tree_menu.add_cascade(label="Security Tools", menu=security_menu)
        security_menu.add_command(label="Port Scan", command=self.port_scan_selected)
        security_menu.add_command(label="IP Information", command=self.show_ip_info)
        security_menu.add_command(label="Check Malicious IP", command=self.check_malicious_ip)
        
        # IP Management
        self.tree_menu.add_separator()
        self.tree_menu.add_command(label="Mark IP as Malicious", command=self.mark_ip_as_malicious)
        self.tree_menu.add_command(label="Remove IP from Malicious List", command=self.remove_ip_from_malicious)

    def start_monitoring_ui(self):
            self.network_monitor.start()
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.pause_btn.config(state="normal")
            self.status_bar.config(text="Status: Monitoring...")

    def stop_monitoring_ui(self):
        self.network_monitor.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.pause_btn.config(state="disabled")
        self.status_bar.config(text="Status: Stopped")

    def toggle_pause_ui(self):
        self.network_monitor.toggle_pause()
        self.pause_btn.config(text="Resume" if self.network_monitor.paused else "Pause")
        status_text = "Status: Paused" if self.network_monitor.paused else "Status: Monitoring..."
        self.status_bar.config(text=status_text)

    def update_stats_periodically(self):
        if self.network_monitor.running:
            stats = self.network_monitor.get_stats()
            stats_text = f"Total Packets: {stats['total_packets']}\n"
            stats_text += f"Suspicious Connections: {stats['suspicious_connections']}\n"
            stats_text += f"Active Alerts: {len(stats['alerts'])}"
            self.stats_label.config(text=stats_text)
            self.master.after(1000, self.update_stats_periodically)

    def mark_ip_as_malicious(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            remote_addr = values[3].split(":")[0]  # Get IP from Remote column
            self.network_monitor.add_malicious_ip(remote_addr)
            self.log_message(f"[SECURITY] Marked IP {remote_addr} as malicious", alert=True)

    def remove_ip_from_malicious(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            remote_addr = values[3].split(":")[0]  # Get IP from Remote column
            self.network_monitor.remove_malicious_ip(remote_addr)
            self.log_message(f"[SECURITY] Removed IP {remote_addr} from malicious list")

    def log_message(self, message, src_ip=None, dst_ip=None, dst_port=None, alert=False, alert_type="", severity="", details="", direction=""):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        info = f"[{now}]"
        if direction:
            info += f" [{direction}]"
        if alert:
            info += f" [{alert_type or 'Alert'}] [{severity or 'medium'}]"
        if src_ip:
            info += f" [SRC: {src_ip}]"
        if dst_ip:
            info += f" [DST: {dst_ip}]"
        if dst_port:
            info += f" [PORT: {dst_port}]"
        if details:
            info += f" [Details: {details}]"
        info += f" {message}"

        # --- Severity Filtering ---
        # (Removed: notification_settings and severity_filter logic)
        if alert:
            alert_row = (
                now.split()[1],  # Only time for the table
                alert_type or "Alert",
                severity or "medium",
                src_ip or "",
                dst_ip or "",
                dst_port or "",
                direction or "",
                message
            )
            self.alerts_tree.insert("", 0, values=alert_row)
            self._recent_alerts.insert(0, alert_row)
            if len(self._recent_alerts) > 100:
                self._recent_alerts.pop()
                children = self.alerts_tree.get_children()
                if len(children) > 100:
                    self.alerts_tree.delete(children[-1])
            # Also log to log_area for alerts
            self.log_area.insert(tk.END, info + "\n", "alert")
            self.log_area.see(tk.END)
            return
        is_pinned = self.connection_manager.is_connection_pinned(src_ip, dst_ip, dst_port) if src_ip else False
        if is_pinned:
            self.log_area.insert(tk.END, info + "\n", "pinned")
        else:
            self.log_area.insert(tk.END, info + "\n")
        self.log_area.see(tk.END)

    def update_connections_periodically(self):
        # Get latest connections from monitor
        current_psutil_connections = self.network_monitor.get_current_connections()
        for conn_data in current_psutil_connections:
            self.connection_manager.add_or_update_connection(conn_data)
        self.update_treeview() # Refresh the treeview

        # Schedule the next update
        if self.network_monitor.running and not self.network_monitor.paused:
            self.master.after(2000, self.update_connections_periodically) # Update every 2 seconds
        elif not self.network_monitor.running:
             # If stopped, ensure no further updates are scheduled by this loop
             pass
        else: # Paused
             self.master.after(2000, self.update_connections_periodically) # Continue scheduling even if paused, but monitor won't update

    def show_tree_context_menu(self, event):
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            self.tree_menu.post(event.x_root, event.y_root)

    def pin_selected_connection(self):
        selected_item = self.tree.selection()
        if selected_item:
            values_tuple = tuple(self.tree.item(selected_item[0])["values"])
            tag_name, color = self.connection_manager.pin_connection(values_tuple)
            if tag_name and color:
                self.tree.tag_configure(tag_name, background=color)
                self.tree.item(selected_item[0], tags=(tag_name,))
                self.log_message(f"[PINNED] Connection: {values_tuple}")

    def unpin_selected_connection(self):
        selected_item = self.tree.selection()
        if selected_item:
            values_tuple = tuple(self.tree.item(selected_item[0])["values"])
            if self.connection_manager.unpin_connection(values_tuple):
                self.tree.item(selected_item[0], tags=()) # Remove all tags
                self.log_message(f"[UNPINNED] Connection: {values_tuple}")
                # Re-configure the treeview to remove the specific tag from display, if necessary
                # For simplicity, we just remove the tag from the item.
                # If tags were globally managed, you might need a cleanup here.

    def update_treeview(self):
        # Clear existing entries in the treeview
        for child in self.tree.get_children():
            self.tree.delete(child)

        # Get current connections from the manager and populate treeview
        connections_to_display = self.connection_manager.get_all_connections_for_display()
        for conn_info in connections_to_display:
            self.tree.insert('', tk.END, values=conn_info["values"], tags=(conn_info["tag"],))

        # Update status
        self.status_bar.config(text=f"Filter: {self.filter_var.get()} - Showing {len(connections_to_display)} connections")

    def handle_monitor_callback(self, type, *args, **kwargs):
        if type == "log":
            message = args[0]
            src_ip = kwargs.get('src_ip')
            dst_ip = kwargs.get('dst_ip')
            dst_port = kwargs.get('dst_port')
            direction = kwargs.get('direction', 'UNKNOWN')
            self.master.after(0, lambda: self.log_message(message, src_ip, dst_ip, dst_port, direction=direction))
        elif type == "alert":
            message = args[0]
            src_ip = kwargs.get('src_ip')
            dst_ip = kwargs.get('dst_ip')
            dst_port = kwargs.get('dst_port')
            alert_type = kwargs.get('alert_type', "")
            severity = kwargs.get('severity', "")
            details = kwargs.get('details', "")
            direction = kwargs.get('direction', 'UNKNOWN')
            self.master.after(0, lambda: self.log_message(
                message, src_ip, dst_ip, dst_port, alert=True,
                alert_type=alert_type, severity=severity, details=details, direction=direction
            ))
        elif type == "packet":
            pass
        elif type == "update_ui_on_stop":
            self.master.after(0, self.stop_monitoring_ui)

    def refresh_interfaces(self):
        """Refresh the network interface list"""
        self.update_interface_list()
        self.log_message("[SYSTEM] Network interfaces refreshed")

    def update_interface_list(self):
        """Update the network interface dropdown list"""
        interfaces = get_network_interfaces()
        if interfaces:
            self.interface_combo['values'] = [iface['description'] for iface in interfaces]
            # Try to keep the current selection if possible
            current = self.interface_var.get()
            if current and current in self.interface_combo['values']:
                self.interface_combo.set(current)
            else:
                self.interface_combo.set(interfaces[0]['description'])
                self.network_monitor.set_interface(interfaces[0]['name'])
            self.start_btn.config(state='normal')
        else:
            self.interface_combo['values'] = ['No interfaces available']
            self.interface_combo.set('No interfaces available')
            self.start_btn.config(state='disabled')
            self.log_message("[WARNING] No network interfaces detected")

    def on_interface_selected(self, event):
        """Handle interface selection"""
        selected = self.interface_var.get()
        if selected != 'No interfaces available':
            # Extract interface name from the description
            interface_name = selected.split(' (')[0]
            self.network_monitor.set_interface(interface_name)
            self.start_btn.config(state='normal')
            self.log_message(f"[SYSTEM] Selected interface: {interface_name}")
        else:
            self.start_btn.config(state='disabled')

    def port_scan_selected(self):
        """Open port scan window for selected connection"""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            remote_addr = values[3].split(":")[0]  # Get IP from Remote column
            PortScanWindow(self.master, remote_addr)

    def show_ip_info(self):
        """Open IP information window for selected connection"""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            remote_addr = values[3].split(":")[0]  # Get IP from Remote column
            IPInfoWindow(self.master, remote_addr, self.security_tools)

    def check_malicious_ip(self):
        """Open malicious IP check window for selected connection"""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            remote_addr = values[3].split(":")[0]  # Get IP from Remote column
            MaliciousIPCheckWindow(self.master, remote_addr, self.security_tools)  # Pass security_tools instead of api_keys

    def show_settings(self):
        """Open settings window"""
        SettingsWindow(self.master, self.settings_manager)

    def show_alert_settings(self):
        AlertSettingsWindow(self.master, self.network_monitor.alert_manager)

    def show_malicious_ip_manager(self):
        """Open the malicious IP manager window"""
        from malicious_ip_list import MaliciousIPWindowList
        MaliciousIPWindowList(self.master)

    def _create_filter_help_tooltip(self, parent):
        help_text = """Filter Syntax:
- Process: process chrome
- Status: status established
- Port: port 80
- IP: ip 192.168.1.1
- PID: pid 1234

Examples:
  process chrome
  status established
  port 80
  ip 192.168.1.1
  pid 1234
  
Combined filters:
  process chrome and port 80
  status established and ip 192.168.1.1
  process chrome or process firefox"""
        
        help_button = ttk.Button(parent, text="?", width=2, command=lambda: self.show_filter_help(help_text))
        help_button.pack(side=tk.LEFT, padx=2)

    def show_filter_help(self, help_text):
        help_window = tk.Toplevel(self.master)
        help_window.title("Filter Help")
        help_window.geometry("400x300")
        
        text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=5)

    def show_filter_presets(self, event=None):
        try:
            self.presets_menu.post(self.filter_entry.winfo_rootx(),
                                 self.filter_entry.winfo_rooty() + self.filter_entry.winfo_height())
        except Exception as e:
            logging.error(f"Error showing filter presets: {e}")

    def show_custom_port_filter(self):
        """Show a dialog for custom port filtering with options"""
        dialog = tk.Toplevel(self.master)
        dialog.title("Custom Port Filter")
        dialog.geometry("300x200")
        dialog.transient(self.master)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')
        
        # Create frame for content
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Port number entry
        ttk.Label(frame, text="Port Number:").pack(anchor=tk.W, pady=(0, 5))
        port_var = tk.StringVar()
        port_entry = ttk.Entry(frame, textvariable=port_var, width=10)
        port_entry.pack(anchor=tk.W, pady=(0, 10))
        
        # Filter type selection
        ttk.Label(frame, text="Filter Type:").pack(anchor=tk.W, pady=(0, 5))
        filter_type = tk.StringVar(value="exact")
        
        ttk.Radiobutton(frame, text="Exact Port", variable=filter_type, value="exact").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="Port Range", variable=filter_type, value="range").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="Ports Above", variable=filter_type, value="above").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="Ports Below", variable=filter_type, value="below").pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def apply_custom_filter():
            try:
                port = int(port_var.get())
                if not (1 <= port <= 65535):
                    raise ValueError("Port must be between 1 and 65535")
                
                filter_type_value = filter_type.get()
                if filter_type_value == "exact":
                    filter_text = f"port {port}"
                elif filter_type_value == "range":
                    filter_text = f"port >= {port-10} and port <= {port+10}"
                elif filter_type_value == "above":
                    filter_text = f"port > {port}"
                else:  # below
                    filter_text = f"port < {port}"
                
                self.apply_preset_filter(filter_text)
                dialog.destroy()
                
            except ValueError as e:
                messagebox.showerror("Invalid Port", str(e), parent=dialog)
        
        ttk.Button(button_frame, text="Apply", command=apply_custom_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Set focus to port entry
        port_entry.focus_set()

    def apply_preset_filter(self, filter_text):
        self.filter_var.set(filter_text)
        self.apply_filter()

    def _on_filter_change(self, event=None):
        # Auto-apply filter after typing stops (with delay)
        if hasattr(self, '_filter_after'):
            self.master.after_cancel(self._filter_after)
        self._filter_after = self.master.after(500, self.apply_filter)

    def apply_filter(self, event=None):
        filter_text = self.filter_var.get().strip()
        if not filter_text:
            self.clear_filter()
            return

        # Add to history if not empty and not already the last item
        if filter_text and (not self.filter_history or self.filter_history[-1] != filter_text):
            self.filter_history.append(filter_text)
            if len(self.filter_history) > self.max_filter_history:
                self.filter_history.pop(0)

        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Get all connections
            connections = self.connection_manager.get_all_connections_for_display()
            
            # Apply filter
            filtered_connections = []
            for conn in connections:
                values = conn["values"]
                if self._evaluate_filter(filter_text, values):
                    filtered_connections.append(conn)

            # Update treeview with filtered results
            for conn in filtered_connections:
                self.tree.insert('', tk.END, values=conn["values"], tags=(conn["tag"],))

            # Update status
            self.status_bar.config(text=f"Filter: {filter_text} - Showing {len(filtered_connections)} connections")

        except Exception as e:
            self.status_bar.config(text=f"Filter Error: {str(e)}")
            logging.error(f"Filter error: {e}")

    def _evaluate_filter(self, filter_text, values):
        try:
            # Parse the filter text
            filter_text = filter_text.lower()
            
            # Extract connection details
            pid, process, local, remote, status = values
            local_ip, local_port = local.split(':')
            remote_ip, remote_port = remote.split(':')
            
            # Convert port to integer
            local_port = int(local_port)
            remote_port = int(remote_port)
            
            # Split filter into conditions if using 'and' or 'or'
            if ' and ' in filter_text:
                conditions = filter_text.split(' and ')
                return all(self._evaluate_single_condition(cond.strip(), pid, process, local_ip, local_port, remote_ip, remote_port, status) 
                         for cond in conditions)
            elif ' or ' in filter_text:
                conditions = filter_text.split(' or ')
                return any(self._evaluate_single_condition(cond.strip(), pid, process, local_ip, local_port, remote_ip, remote_port, status) 
                         for cond in conditions)
            else:
                return self._evaluate_single_condition(filter_text, pid, process, local_ip, local_port, remote_ip, remote_port, status)
            
        except Exception as e:
            logging.error(f"Error evaluating filter: {e}")
            return False

    def _evaluate_single_condition(self, condition, pid, process, local_ip, local_port, remote_ip, remote_port, status):
        """Evaluate a single filter condition"""
        try:
            # Process filter
            if condition.startswith('process '):
                proc = condition.split(' ')[1].lower()
                return proc in process.lower()
            
            # Status filter
            elif condition.startswith('status '):
                stat = condition.split(' ')[1].upper()
                return status == stat
            
            # Port filter
            elif condition.startswith('port '):
                port = int(condition.split(' ')[1])
                return local_port == port or remote_port == port
            
            # IP filter
            elif condition.startswith('ip '):
                ip = condition.split(' ')[1]
                return local_ip == ip or remote_ip == ip
            
            # PID filter
            elif condition.startswith('pid '):
                filter_pid = int(condition.split(' ')[1])
                return pid == filter_pid
            
            # Exact match for status
            elif condition.upper() in ['ESTABLISHED', 'LISTEN', 'CLOSE_WAIT', 'TIME_WAIT']:
                return status == condition.upper()
            
            # Exact match for process
            elif condition.lower() in process.lower():
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error evaluating condition '{condition}': {e}")
            return False

    def clear_filter(self):
        self.filter_var.set("")
        self.update_treeview()
        self.status_bar.config(text="Filter cleared")

    def show_alerts_context_menu(self, event):
        row_id = self.alerts_tree.identify_row(event.y)
        if row_id:
            self.alerts_tree.selection_set(row_id)
            self.alerts_menu.post(event.x_root, event.y_root)

    def scan_alert_src_ip(self):
        selected = self.alerts_tree.selection()
        if selected:
            values = self.alerts_tree.item(selected[0])["values"]
            src_ip = values[3]
            if src_ip:
                PortScanWindow(self.master, src_ip)

    def scan_alert_dst_ip(self):
        selected = self.alerts_tree.selection()
        if selected:
            values = self.alerts_tree.item(selected[0])["values"]
            dst_ip = values[4]
            if dst_ip:
                PortScanWindow(self.master, dst_ip)

    def show_alert_src_ip_info(self):
        selected = self.alerts_tree.selection()
        if selected:
            values = self.alerts_tree.item(selected[0])["values"]
            src_ip = values[3]
            if src_ip:
                IPInfoWindow(self.master, src_ip, self.security_tools)

    def show_alert_dst_ip_info(self):
        selected = self.alerts_tree.selection()
        if selected:
            values = self.alerts_tree.item(selected[0])["values"]
            dst_ip = values[4]
            if dst_ip:
                IPInfoWindow(self.master, dst_ip, self.security_tools)

    def check_alert_src_malicious_ip(self):
        selected = self.alerts_tree.selection()
        if selected:
            values = self.alerts_tree.item(selected[0])["values"]
            src_ip = values[3]
            if src_ip:
                MaliciousIPCheckWindow(self.master, src_ip, self.security_tools)

    def check_alert_dst_malicious_ip(self):
        selected = self.alerts_tree.selection()
        if selected:
            values = self.alerts_tree.item(selected[0])["values"]
            dst_ip = values[4]
            if dst_ip:
                MaliciousIPCheckWindow(self.master, dst_ip, self.security_tools)

    def clear_alerts(self):
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        self._recent_alerts.clear()

    def export_alerts_to_file(self):
        # Ask user for file location and format
        filetypes = [("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=filetypes,
            title="Export Alerts"
        )
        if not filename:
            return
        try:
            # Gather all alert info from self._recent_alerts
            alerts = self._recent_alerts
            if filename.endswith('.csv'):
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Write all columns
                    writer.writerow(["Time", "Type", "Severity", "Source IP", "Destination IP", "Port","Direction", "Message"])
                    for alert in alerts:
                        writer.writerow(list(alert))
            elif filename.endswith('.json'):
                import json
                # Convert tuples to dicts for JSON
                keys = ["Time", "Type", "Severity", "Source IP", "Destination IP", "Port", "Message"]
                alert_dicts = [dict(zip(keys, alert)) for alert in alerts]
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(alert_dicts, f, indent=2)
            else:
                with open(filename, 'w', encoding='utf-8') as f:
                    for alert in alerts:
                        f.write(str(alert) + '\n')
            messagebox.showinfo("Export Successful", f"Alerts exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export alerts: {e}")

    def add_selected_process_to_ignore_list(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0])["values"]
            process_name = values[1] 
            settings_manager = SettingsManager()
            settings = settings_manager.load_settings()
            ignored = settings.get('ignored_processes', [])
            if process_name not in ignored:
                ignored.append(process_name)
                settings['ignored_processes'] = ignored
                settings_manager.save_settings(settings)
                messagebox.showinfo("Ignore List", f"Process '{process_name}' added to ignore list.")
                self.update_treeview()
            else:
                messagebox.showinfo("Ignore List", f"Process '{process_name}' is already in the ignore list.")

# --- Main Application Logic ---
if __name__ == "__main__":
    root = tk.Tk()

    # Create a temporary callback function
    def temp_callback(type, *args, **kwargs):
        pass  # This will be replaced once the GUI is created
    
    # Initialize components
    connection_manager = ConnectionManager()
    network_monitor = NetworkMonitor(callback=temp_callback)
    app_gui = IDSAppGUI(root, network_monitor, connection_manager)
    
    # Update the network monitor's callback to use the GUI
    network_monitor.callback = app_gui.handle_monitor_callback

    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit the IDS application?"):
            network_monitor.stop()
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()