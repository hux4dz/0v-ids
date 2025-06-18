import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import socket
import requests
import whois
from concurrent.futures import ThreadPoolExecutor

class IPInfoGatherer:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=5)

    def get_ip_info(self, ip):
        """Get comprehensive information about an IP address"""
        try:
            # Basic IP information
            info = {
                "ip": ip,
                "hostname": self._get_hostname(ip),
                "whois": self._get_whois_info(ip),
                "geolocation": self._get_geolocation(ip),
                "reverse_dns": self._get_reverse_dns(ip),
                "asn": self._get_asn_info(ip)
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

    def _get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            if self._is_valid_ip(ip):
                return socket.gethostbyaddr(ip)[0]
        except:
            pass
        return "Unknown"

    def _get_reverse_dns(self, ip):
        """Get reverse DNS information"""
        try:
            if self._is_valid_ip(ip):
                return socket.gethostbyaddr(ip)
        except:
            pass
        return None

    def _get_whois_info(self, ip):
        """Get WHOIS information for an IP"""
        try:
            w = whois.whois(ip)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status
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
                    "country_code": data.get("countryCode", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "organization": data.get("org", "Unknown"),
                    "latitude": data.get("lat", "Unknown"),
                    "longitude": data.get("lon", "Unknown"),
                    "timezone": data.get("timezone", "Unknown")
                }
        except:
            pass
        return "No geolocation information available"

    def _get_asn_info(self, ip):
        """Get ASN (Autonomous System Number) information"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                return {
                    "as": data.get("as", "Unknown"),
                    "as_name": data.get("asname", "Unknown")
                }
        except:
            pass
        return "No ASN information available"

class IPInfoWindow:
    def __init__(self, parent, ip, security_tools=None):
        self.window = tk.Toplevel(parent)
        self.window.title(f"IP Information - {ip}")
        self.window.geometry("800x600")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.ip = ip
        self.info_gatherer = IPInfoGatherer()
        self.security_tools = security_tools
        
        self._create_widgets()
        
    def _create_widgets(self):
        # Main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control panel
        control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding="5")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export", command=self.export_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=self.window.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Information display
        info_frame = ttk.LabelFrame(self.main_frame, text="IP Information", padding="5")
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create notebook for tabbed display
        self.notebook = ttk.Notebook(info_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.basic_tab = ttk.Frame(self.notebook)
        self.whois_tab = ttk.Frame(self.notebook)
        self.geo_tab = ttk.Frame(self.notebook)
        self.asn_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.basic_tab, text="Basic Info")
        self.notebook.add(self.whois_tab, text="WHOIS")
        self.notebook.add(self.geo_tab, text="Geolocation")
        self.notebook.add(self.asn_tab, text="ASN")
        
        # Create text areas for each tab
        self.basic_text = scrolledtext.ScrolledText(self.basic_tab, wrap=tk.WORD)
        self.basic_text.pack(fill=tk.BOTH, expand=True)
        
        self.whois_text = scrolledtext.ScrolledText(self.whois_tab, wrap=tk.WORD)
        self.whois_text.pack(fill=tk.BOTH, expand=True)
        
        self.geo_text = scrolledtext.ScrolledText(self.geo_tab, wrap=tk.WORD)
        self.geo_text.pack(fill=tk.BOTH, expand=True)
        
        self.asn_text = scrolledtext.ScrolledText(self.asn_tab, wrap=tk.WORD)
        self.asn_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        for text_widget in [self.basic_text, self.whois_text, self.geo_text, self.asn_text]:
            text_widget.tag_config("header", font=("TkDefaultFont", 10, "bold"))
            text_widget.tag_config("info", foreground="blue")
            text_widget.tag_config("warning", foreground="red")
            text_widget.tag_config("success", foreground="green")
        
        # Initial data load
        self.refresh_info()
    
    def refresh_info(self):
        """Refresh all IP information"""
        self.clear_all()
        self.add_text(self.basic_text, f"Gathering information for {self.ip}...", "info")
        
        def get_info():
            info = self.info_gatherer.get_ip_info(self.ip)
            
            if "error" in info:
                self.add_text(self.basic_text, f"Error: {info['error']}", "warning")
                return
            
            # Basic Information
            self.add_text(self.basic_text, "Basic Information", "header")
            self.add_text(self.basic_text, f"IP Address: {info['ip']}")
            self.add_text(self.basic_text, f"Hostname: {info['hostname']}")
            if info.get('reverse_dns'):
                self.add_text(self.basic_text, f"Reverse DNS: {info['reverse_dns'][0]}")
            
            # WHOIS Information
            if isinstance(info.get('whois'), dict):
                self.add_text(self.whois_text, "WHOIS Information", "header")
                whois_info = info['whois']
                self.add_text(self.whois_text, f"Registrar: {whois_info.get('registrar', 'Unknown')}")
                self.add_text(self.whois_text, f"Creation Date: {whois_info.get('creation_date', 'Unknown')}")
                self.add_text(self.whois_text, f"Expiration Date: {whois_info.get('expiration_date', 'Unknown')}")
                self.add_text(self.whois_text, f"Name Servers: {', '.join(whois_info.get('name_servers', ['Unknown']))}")
                self.add_text(self.whois_text, f"Status: {whois_info.get('status', 'Unknown')}")
            
            # Geolocation Information
            if isinstance(info.get('geolocation'), dict):
                self.add_text(self.geo_text, "Geolocation Information", "header")
                geo_info = info['geolocation']
                self.add_text(self.geo_text, f"Country: {geo_info.get('country', 'Unknown')} ({geo_info.get('country_code', 'Unknown')})")
                self.add_text(self.geo_text, f"Region: {geo_info.get('region', 'Unknown')}")
                self.add_text(self.geo_text, f"City: {geo_info.get('city', 'Unknown')}")
                self.add_text(self.geo_text, f"ISP: {geo_info.get('isp', 'Unknown')}")
                self.add_text(self.geo_text, f"Organization: {geo_info.get('organization', 'Unknown')}")
                self.add_text(self.geo_text, f"Location: {geo_info.get('latitude', 'Unknown')}, {geo_info.get('longitude', 'Unknown')}")
                self.add_text(self.geo_text, f"Timezone: {geo_info.get('timezone', 'Unknown')}")
            
            # ASN Information
            if isinstance(info.get('asn'), dict):
                self.add_text(self.asn_text, "ASN Information", "header")
                asn_info = info['asn']
                self.add_text(self.asn_text, f"AS Number: {asn_info.get('as', 'Unknown')}")
                self.add_text(self.asn_text, f"AS Name: {asn_info.get('as_name', 'Unknown')}")
        
        self.info_gatherer.executor.submit(get_info)
    
    def export_info(self):
        """Export all IP information to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"ip_info_{self.ip}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write("=== Basic Information ===\n")
                f.write(self.basic_text.get(1.0, tk.END))
                f.write("\n=== WHOIS Information ===\n")
                f.write(self.whois_text.get(1.0, tk.END))
                f.write("\n=== Geolocation Information ===\n")
                f.write(self.geo_text.get(1.0, tk.END))
                f.write("\n=== ASN Information ===\n")
                f.write(self.asn_text.get(1.0, tk.END))
            self.add_text(self.basic_text, f"\nInformation exported to {filename}", "success")
    
    def add_text(self, text_widget, text, tag=None):
        """Add text to a text widget with optional tag"""
        text_widget.insert(tk.END, text + "\n", tag)
        text_widget.see(tk.END)
    
    def clear_all(self):
        """Clear all text widgets"""
        for text_widget in [self.basic_text, self.whois_text, self.geo_text, self.asn_text]:
            text_widget.delete(1.0, tk.END) 