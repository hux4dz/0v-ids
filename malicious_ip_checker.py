import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import requests
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import socket
import whois

class MaliciousIPChecker:
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.cache = {}  # Simple cache for results
        self.cache_timeout = 3600  # Cache timeout in seconds (1 hour)

    def check_ip(self, ip):
        """Check IP against multiple threat intelligence sources"""
        try:
            # Check cache first
            if ip in self.cache:
                cache_entry = self.cache[ip]
                if (datetime.now() - cache_entry['timestamp']).total_seconds() < self.cache_timeout:
                    return cache_entry['data']

            results = {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'sources': {}
            }

            # Run all checks in parallel
            futures = []
            futures.append(self.executor.submit(self._check_abuseipdb, ip))
            futures.append(self.executor.submit(self._check_virustotal, ip))
            futures.append(self.executor.submit(self._check_alienvault, ip))
            futures.append(self.executor.submit(self._check_threatfox, ip))

            # Collect results
            for future in futures:
                try:
                    source, data = future.result()
                    results['sources'][source] = data
                except Exception as e:
                    results['sources'][source] = {'error': str(e)}

            # Calculate overall risk score
            results['risk_score'] = self._calculate_risk_score(results['sources'])
            results['risk_level'] = self._get_risk_level(results['risk_score'])

            # Cache the results
            self.cache[ip] = {
                'timestamp': datetime.now(),
                'data': results
            }

            return results

        except Exception as e:
            return {'error': str(e)}

    def _check_abuseipdb(self, ip):
        """Check IP against AbuseIPDB"""
        try:
            if 'abuseipdb' not in self.api_keys:
                return 'abuseipdb', {'error': 'API key not configured'}

            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={
                    'Key': self.api_keys['abuseipdb'],
                    'Accept': 'application/json'
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                return 'abuseipdb', {
                    'abuse_score': data.get('data', {}).get('abuseConfidenceScore', 0),
                    'total_reports': data.get('data', {}).get('totalReports', 0),
                    'last_reported': data.get('data', {}).get('lastReportedAt'),
                    'country': data.get('data', {}).get('countryCode'),
                    'domain': data.get('data', {}).get('domain'),
                    'is_whitelisted': data.get('data', {}).get('isWhitelisted', False)
                }
            return 'abuseipdb', {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return 'abuseipdb', {'error': str(e)}

    def _check_virustotal(self, ip):
        """Check IP against VirusTotal"""
        try:
            if 'virustotal' not in self.api_keys:
                return 'virustotal', {'error': 'API key not configured'}

            response = requests.get(
                f"https://www.virustotal.com/vtapi/v2/ip-address/report",
                params={'apikey': self.api_keys['virustotal'], 'ip': ip}
            )
            
            if response.status_code == 200:
                data = response.json()
                return 'virustotal', {
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'detection_ratio': data.get('positives', 0) / max(data.get('total', 1), 1),
                    'categories': data.get('categories', []),
                    'as_owner': data.get('as_owner'),
                    'country': data.get('country'),
                    'last_updated': data.get('last_updated')
                }
            return 'virustotal', {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return 'virustotal', {'error': str(e)}

    def _check_alienvault(self, ip):
        """Check IP against AlienVault OTX"""
        try:
            if 'alienvault' not in self.api_keys:
                return 'alienvault', {'error': 'API key not configured'}

            response = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={'X-OTX-API-KEY': self.api_keys['alienvault']}
            )
            
            if response.status_code == 200:
                data = response.json()
                return 'alienvault', {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'asn': data.get('asn'),
                    'reputation': data.get('reputation', 0),
                    'threat_types': [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])]
                }
            return 'alienvault', {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return 'alienvault', {'error': str(e)}

    def _check_threatfox(self, ip):
        """Check IP against ThreatFox"""
        try:
            if 'threatfox' not in self.api_keys:
                return 'threatfox', {'error': 'API key not configured'}

            response = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={
                    "query": "search_ioc",
                    "search_term": ip
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    return 'threatfox', {
                        'found': True,
                        'malware': data.get('data', [{}])[0].get('malware'),
                        'malware_type': data.get('data', [{}])[0].get('malware_type'),
                        'confidence_level': data.get('data', [{}])[0].get('confidence_level'),
                        'first_seen': data.get('data', [{}])[0].get('first_seen'),
                        'last_seen': data.get('data', [{}])[0].get('last_seen')
                    }
                return 'threatfox', {'found': False}
            return 'threatfox', {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return 'threatfox', {'error': str(e)}

    def _calculate_risk_score(self, sources):
        """Calculate overall risk score based on all sources"""
        score = 0
        weights = {
            'abuseipdb': 0.4,
            'virustotal': 0.3,
            'alienvault': 0.2,
            'threatfox': 0.1
        }

        for source, data in sources.items():
            if 'error' in data:
                continue

            if source == 'abuseipdb':
                score += data.get('abuse_score', 0) * weights[source]
            elif source == 'virustotal':
                score += data.get('detection_ratio', 0) * 100 * weights[source]
            elif source == 'alienvault':
                score += (100 - data.get('reputation', 50)) * weights[source]
            elif source == 'threatfox':
                if data.get('found', False):
                    score += 100 * weights[source]

        return min(100, score)

    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"

class MaliciousIPWindow:
    def __init__(self, parent, ip, api_keys=None):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Malicious IP Check - {ip}")
        self.window.geometry("900x700")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.ip = ip
        self.checker = MaliciousIPChecker(api_keys)
        
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
        
        ttk.Button(button_frame, text="Check Again", command=self.check_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=self.window.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Information display
        info_frame = ttk.LabelFrame(self.main_frame, text="Threat Intelligence", padding="5")
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create notebook for tabbed display
        self.notebook = ttk.Notebook(info_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.summary_tab = ttk.Frame(self.notebook)
        self.abuseipdb_tab = ttk.Frame(self.notebook)
        self.virustotal_tab = ttk.Frame(self.notebook)
        self.alienvault_tab = ttk.Frame(self.notebook)
        self.threatfox_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.summary_tab, text="Summary")
        self.notebook.add(self.abuseipdb_tab, text="AbuseIPDB")
        self.notebook.add(self.virustotal_tab, text="VirusTotal")
        self.notebook.add(self.alienvault_tab, text="AlienVault")
        self.notebook.add(self.threatfox_tab, text="ThreatFox")
        
        # Create text areas for each tab
        self.summary_text = scrolledtext.ScrolledText(self.summary_tab, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        
        self.abuseipdb_text = scrolledtext.ScrolledText(self.abuseipdb_tab, wrap=tk.WORD)
        self.abuseipdb_text.pack(fill=tk.BOTH, expand=True)
        
        self.virustotal_text = scrolledtext.ScrolledText(self.virustotal_tab, wrap=tk.WORD)
        self.virustotal_text.pack(fill=tk.BOTH, expand=True)
        
        self.alienvault_text = scrolledtext.ScrolledText(self.alienvault_tab, wrap=tk.WORD)
        self.alienvault_text.pack(fill=tk.BOTH, expand=True)
        
        self.threatfox_text = scrolledtext.ScrolledText(self.threatfox_tab, wrap=tk.WORD)
        self.threatfox_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        for text_widget in [self.summary_text, self.abuseipdb_text, self.virustotal_text, 
                          self.alienvault_text, self.threatfox_text]:
            text_widget.tag_config("header", font=("TkDefaultFont", 10, "bold"))
            text_widget.tag_config("info", foreground="blue")
            text_widget.tag_config("warning", foreground="red")
            text_widget.tag_config("success", foreground="green")
            text_widget.tag_config("critical", foreground="red", font=("TkDefaultFont", 10, "bold"))
            text_widget.tag_config("high", foreground="orange", font=("TkDefaultFont", 10, "bold"))
            text_widget.tag_config("medium", foreground="yellow", font=("TkDefaultFont", 10, "bold"))
            text_widget.tag_config("low", foreground="green", font=("TkDefaultFont", 10, "bold"))
        
        # Initial check
        self.check_ip()
    
    def check_ip(self):
        """Check IP against all sources"""
        self.clear_all()
        self.add_text(self.summary_text, f"Checking {self.ip} against threat intelligence sources...", "info")
        
        def check():
            results = self.checker.check_ip(self.ip)
            
            if 'error' in results:
                self.add_text(self.summary_text, f"Error: {results['error']}", "warning")
                return
            
            # Summary tab
            self.add_text(self.summary_text, "Threat Intelligence Summary", "header")
            self.add_text(self.summary_text, f"IP Address: {results['ip']}")
            self.add_text(self.summary_text, f"Check Time: {results['timestamp']}")
            
            risk_level = results['risk_level']
            risk_tag = risk_level.lower()
            self.add_text(self.summary_text, f"\nRisk Level: {risk_level}", risk_tag)
            self.add_text(self.summary_text, f"Risk Score: {results['risk_score']:.1f}/100")
            
            # Source summaries
            self.add_text(self.summary_text, "\nSource Summaries:", "header")
            for source, data in results['sources'].items():
                if 'error' in data:
                    self.add_text(self.summary_text, f"\n{source}: Error - {data['error']}", "warning")
                else:
                    self.add_text(self.summary_text, f"\n{source}:", "info")
                    if source == 'abuseipdb':
                        self.add_text(self.summary_text, f"  Abuse Score: {data.get('abuse_score', 0)}/100")
                        self.add_text(self.summary_text, f"  Total Reports: {data.get('total_reports', 0)}")
                    elif source == 'virustotal':
                        self.add_text(self.summary_text, f"  Detection Ratio: {data.get('detection_ratio', 0)*100:.1f}%")
                        self.add_text(self.summary_text, f"  Positives: {data.get('positives', 0)}/{data.get('total', 0)}")
                    elif source == 'alienvault':
                        self.add_text(self.summary_text, f"  Pulse Count: {data.get('pulse_count', 0)}")
                        self.add_text(self.summary_text, f"  Reputation: {data.get('reputation', 0)}/100")
                    elif source == 'threatfox':
                        if data.get('found', False):
                            self.add_text(self.summary_text, f"  Malware: {data.get('malware', 'Unknown')}")
                            self.add_text(self.summary_text, f"  Confidence: {data.get('confidence_level', 'Unknown')}")
            
            # Detailed source information
            self._update_source_tab(self.abuseipdb_text, "AbuseIPDB", results['sources'].get('abuseipdb', {}))
            self._update_source_tab(self.virustotal_text, "VirusTotal", results['sources'].get('virustotal', {}))
            self._update_source_tab(self.alienvault_text, "AlienVault", results['sources'].get('alienvault', {}))
            self._update_source_tab(self.threatfox_text, "ThreatFox", results['sources'].get('threatfox', {}))
        
        self.checker.executor.submit(check)
    
    def _update_source_tab(self, text_widget, source_name, data):
        """Update a source tab with detailed information"""
        self.add_text(text_widget, f"{source_name} Information", "header")
        
        if 'error' in data:
            self.add_text(text_widget, f"Error: {data['error']}", "warning")
            return
        
        for key, value in data.items():
            if isinstance(value, list):
                self.add_text(text_widget, f"{key.replace('_', ' ').title()}: {', '.join(map(str, value))}")
            else:
                self.add_text(text_widget, f"{key.replace('_', ' ').title()}: {value}")
    
    def export_report(self):
        """Export threat intelligence report to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"threat_intel_{self.ip}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write("=== Threat Intelligence Report ===\n")
                f.write(self.summary_text.get(1.0, tk.END))
                f.write("\n=== AbuseIPDB Details ===\n")
                f.write(self.abuseipdb_text.get(1.0, tk.END))
                f.write("\n=== VirusTotal Details ===\n")
                f.write(self.virustotal_text.get(1.0, tk.END))
                f.write("\n=== AlienVault Details ===\n")
                f.write(self.alienvault_text.get(1.0, tk.END))
                f.write("\n=== ThreatFox Details ===\n")
                f.write(self.threatfox_text.get(1.0, tk.END))
            self.add_text(self.summary_text, f"\nReport exported to {filename}", "success")
    
    def add_text(self, text_widget, text, tag=None):
        """Add text to a text widget with optional tag"""
        text_widget.insert(tk.END, text + "\n", tag)
        text_widget.see(tk.END)
    
    def clear_all(self):
        """Clear all text widgets"""
        for text_widget in [self.summary_text, self.abuseipdb_text, self.virustotal_text, 
                          self.alienvault_text, self.threatfox_text]:
            text_widget.delete(1.0, tk.END) 