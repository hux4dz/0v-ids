import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self):
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.scan_timeout = 1  # seconds

    def scan_port(self, ip, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = self._get_service_name(port)
                return f"Port {port} ({service}) is open"
            sock.close()
        except:
            pass
        return None

    def scan_ports(self, ip, ports=None):
        """Scan multiple ports"""
        if ports is None:
            ports = self.common_ports
        
        results = []
        for port in ports:
            result = self.scan_port(ip, port)
            if result:
                results.append(result)
        return results

    def _get_service_name(self, port):
        """Get common service name for a port"""
        services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Proxy"
        }
        return services.get(port, "Unknown")

class PortScanWindow:
    def __init__(self, parent, ip):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Port Scan - {ip}")
        self.window.geometry("600x400")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.ip = ip
        self.scanner = PortScanner()
        
        self._create_widgets()
        
    def _create_widgets(self):
        # Main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create control panel frame
        control_frame = ttk.LabelFrame(self.main_frame, text="Scan Controls", padding="5")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Port selection mode
        mode_frame = ttk.Frame(control_frame)
        mode_frame.pack(fill=tk.X, pady=5)
        
        self.scan_mode = tk.StringVar(value="default")
        ttk.Radiobutton(mode_frame, text="Default Ports", variable=self.scan_mode, 
                       value="default", command=self.update_port_inputs).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Port Range", variable=self.scan_mode,
                       value="range", command=self.update_port_inputs).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Custom Ports", variable=self.scan_mode,
                       value="custom", command=self.update_port_inputs).pack(side=tk.LEFT, padx=5)
        
        # Port range inputs
        self.range_frame = ttk.Frame(control_frame)
        self.range_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.range_frame, text="Start Port:").pack(side=tk.LEFT, padx=5)
        self.start_port = ttk.Entry(self.range_frame, width=10)
        self.start_port.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.range_frame, text="End Port:").pack(side=tk.LEFT, padx=5)
        self.end_port = ttk.Entry(self.range_frame, width=10)
        self.end_port.pack(side=tk.LEFT, padx=5)
        
        # Custom ports input
        self.custom_frame = ttk.Frame(control_frame)
        self.custom_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.custom_frame, text="Ports (comma-separated):").pack(side=tk.LEFT, padx=5)
        self.custom_ports = ttk.Entry(self.custom_frame, width=40)
        self.custom_ports.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Default ports display
        self.default_frame = ttk.Frame(control_frame)
        self.default_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.default_frame, text="Default Ports:").pack(side=tk.LEFT, padx=5)
        default_ports_text = ", ".join(str(p) for p in self.scanner.common_ports)
        ttk.Label(self.default_frame, text=default_ports_text).pack(side=tk.LEFT, padx=5)
        
        # Button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Results", command=self.export_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=self.window.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Text area for results
        self.text_area = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        self.text_area.tag_config("info", foreground="blue")
        self.text_area.tag_config("warning", foreground="red")
        self.text_area.tag_config("success", foreground="green")
        
        # Initialize port inputs visibility
        self.update_port_inputs()
        
        self.add_text(f"Port Scan Tool for {self.ip}", "info")
        self.add_text("Select scan mode and click 'Start Scan' to begin.", "info")
    
    def update_port_inputs(self):
        """Update visibility of port input fields based on selected mode"""
        mode = self.scan_mode.get()
        self.range_frame.pack_forget()
        self.custom_frame.pack_forget()
        self.default_frame.pack_forget()
        
        if mode == "range":
            self.range_frame.pack(fill=tk.X, pady=5)
        elif mode == "custom":
            self.custom_frame.pack(fill=tk.X, pady=5)
        else:  # default
            self.default_frame.pack(fill=tk.X, pady=5)
    
    def get_ports_to_scan(self):
        """Get list of ports to scan based on selected mode"""
        mode = self.scan_mode.get()
        
        if mode == "default":
            return self.scanner.common_ports
        
        elif mode == "range":
            try:
                start = int(self.start_port.get())
                end = int(self.end_port.get())
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    return list(range(start, end + 1))
                else:
                    self.add_text("Invalid port range. Ports must be between 1 and 65535.", "warning")
                    return None
            except ValueError:
                self.add_text("Invalid port range. Please enter valid numbers.", "warning")
                return None
        
        elif mode == "custom":
            try:
                ports = [int(p.strip()) for p in self.custom_ports.get().split(",") if p.strip()]
                if all(1 <= p <= 65535 for p in ports):
                    return ports
                else:
                    self.add_text("Invalid ports. Ports must be between 1 and 65535.", "warning")
                    return None
            except ValueError:
                self.add_text("Invalid port list. Please enter comma-separated numbers.", "warning")
                return None
        
        return None
    
    def start_scan(self):
        """Start port scan with selected options"""
        ports = self.get_ports_to_scan()
        if not ports:
            return
        
        self.clear()
        self.add_text(f"Starting port scan on {self.ip}...", "info")
        self.add_text(f"Scanning {len(ports)} ports...", "info")
        
        def scan():
            results = self.scanner.scan_ports(self.ip, ports)
            if results:
                self.add_text(f"\nOpen ports on {self.ip}:", "success")
                for result in results:
                    self.add_text(result, "success")
            else:
                self.add_text(f"\nNo open ports found on {self.ip}", "warning")
        
        self.scanner.executor.submit(scan)
    
    def export_results(self):
        """Export scan results to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"port_scan_{self.ip}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.text_area.get(1.0, tk.END))
            self.add_text(f"\nResults exported to {filename}", "success")
    
    def add_text(self, text, tag=None):
        """Add text to the text area with optional tag"""
        self.text_area.insert(tk.END, text + "\n", tag)
        self.text_area.see(tk.END)
    
    def clear(self):
        """Clear the text area"""
        self.text_area.delete(1.0, tk.END) 