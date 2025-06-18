import json
import os
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog

class SettingsManager:
    def __init__(self):
        self.settings_file = "ids_settings.json"
        self.default_settings = {
            'api_keys': {
                'abuseipdb': '',
                'virustotal': '',
                'alienvault': '',
                'threatfox': ''
            },
            'scan_settings': {
                'default_ports': '20-25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
                'scan_timeout': 2,
                'max_threads': 50
            },
            'monitor_settings': {
                'alert_threshold': 100,
                'alert_cooldown': 60,
                'log_interval': 1.0
            },
            'ui_settings': {
                'theme': 'default',
                'font_size': 10,
                'window_size': '1200x800'
            }
        }
        self.current_settings = self.load_settings()

    def load_settings(self):
        """Load settings from file or create default if not exists"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            return self.default_settings.copy()
        except Exception as e:
            print(f"Error loading settings: {e}")
            return self.default_settings.copy()

    def save_settings(self, settings):
        """Save settings to file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            self.current_settings = settings
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False

    def get_setting(self, category, key=None):
        """Get a specific setting value or entire category if key is None"""
        if key is None:
            return self.current_settings.get(category, {})
        return self.current_settings.get(category, {}).get(key)

    def update_setting(self, category, key, value):
        """Update a specific setting value"""
        if category not in self.current_settings:
            self.current_settings[category] = {}
        self.current_settings[category][key] = value
        return self.save_settings(self.current_settings)

class SettingsWindow:
    def __init__(self, parent, settings_manager):
        self.window = tk.Toplevel(parent)
        self.window.title("IDS Settings")
        self.window.geometry("800x600")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.settings_manager = settings_manager
        self.current_settings = settings_manager.current_settings.copy()
        
        self._create_widgets()
        
    def _create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for different setting categories
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.api_tab = ttk.Frame(self.notebook)
        self.scan_tab = ttk.Frame(self.notebook)
        self.monitor_tab = ttk.Frame(self.notebook)
        self.ui_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.api_tab, text="API Keys")
        self.notebook.add(self.scan_tab, text="Scan Settings")
        self.notebook.add(self.monitor_tab, text="Monitor Settings")
        self.notebook.add(self.ui_tab, text="UI Settings")
        
        # Create content for each tab
        self._create_api_tab()
        self._create_scan_tab()
        self._create_monitor_tab()
        self._create_ui_tab()
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Save", command=self.save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.window.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_settings).pack(side=tk.RIGHT, padx=5)
        
    def _create_api_tab(self):
        frame = ttk.LabelFrame(self.api_tab, text="API Keys", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create entry fields for each API key
        self.api_entries = {}
        row = 0
        for api_name in self.current_settings['api_keys'].keys():
            ttk.Label(frame, text=f"{api_name.title()} API Key:").grid(row=row, column=0, sticky=tk.W, pady=2)
            entry = ttk.Entry(frame, width=50, show="*")
            entry.insert(0, self.current_settings['api_keys'][api_name])
            entry.grid(row=row, column=1, sticky=tk.W, pady=2)
            self.api_entries[api_name] = entry
            row += 1
            
        # Add help text
        help_text = """
        API Keys are required for various security features:
        - AbuseIPDB: For IP reputation checking
        - VirusTotal: For malware detection
        - AlienVault: For threat intelligence
        - ThreatFox: For malware information
        
        Get your API keys from their respective websites:
        - AbuseIPDB: https://www.abuseipdb.com/
        - VirusTotal: https://www.virustotal.com/
        - AlienVault: https://otx.alienvault.com/
        - ThreatFox: https://threatfox-api.abuse.ch/
        """
        help_label = ttk.Label(frame, text=help_text, wraplength=600)
        help_label.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=10)
        
    def _create_scan_tab(self):
        frame = ttk.LabelFrame(self.scan_tab, text="Port Scan Settings", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Default ports
        ttk.Label(frame, text="Default Ports:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.default_ports_entry = ttk.Entry(frame, width=50)
        self.default_ports_entry.insert(0, self.current_settings['scan_settings']['default_ports'])
        self.default_ports_entry.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Scan timeout
        ttk.Label(frame, text="Scan Timeout (seconds):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.timeout_entry = ttk.Entry(frame, width=10)
        self.timeout_entry.insert(0, str(self.current_settings['scan_settings']['scan_timeout']))
        self.timeout_entry.grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Max threads
        ttk.Label(frame, text="Max Threads:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.threads_entry = ttk.Entry(frame, width=10)
        self.threads_entry.insert(0, str(self.current_settings['scan_settings']['max_threads']))
        self.threads_entry.grid(row=2, column=1, sticky=tk.W, pady=2)
        
    def _create_monitor_tab(self):
        frame = ttk.LabelFrame(self.monitor_tab, text="Network Monitor Settings", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alert threshold
        ttk.Label(frame, text="Alert Threshold:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.threshold_entry = ttk.Entry(frame, width=10)
        self.threshold_entry.insert(0, str(self.current_settings['monitor_settings']['alert_threshold']))
        self.threshold_entry.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Alert cooldown
        ttk.Label(frame, text="Alert Cooldown (seconds):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.cooldown_entry = ttk.Entry(frame, width=10)
        self.cooldown_entry.insert(0, str(self.current_settings['monitor_settings']['alert_cooldown']))
        self.cooldown_entry.grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Log interval
        ttk.Label(frame, text="Log Interval (seconds):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.log_interval_entry = ttk.Entry(frame, width=10)
        self.log_interval_entry.insert(0, str(self.current_settings['monitor_settings']['log_interval']))
        self.log_interval_entry.grid(row=2, column=1, sticky=tk.W, pady=2)
        
    def _create_ui_tab(self):
        frame = ttk.LabelFrame(self.ui_tab, text="User Interface Settings", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Theme selection
        ttk.Label(frame, text="Theme:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.theme_var = tk.StringVar(value=self.current_settings['ui_settings']['theme'])
        theme_combo = ttk.Combobox(frame, textvariable=self.theme_var, values=['default', 'dark', 'light'])
        theme_combo.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Font size
        ttk.Label(frame, text="Font Size:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.font_size_entry = ttk.Entry(frame, width=10)
        self.font_size_entry.insert(0, str(self.current_settings['ui_settings']['font_size']))
        self.font_size_entry.grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Window size
        ttk.Label(frame, text="Window Size:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.window_size_entry = ttk.Entry(frame, width=10)
        self.window_size_entry.insert(0, self.current_settings['ui_settings']['window_size'])
        self.window_size_entry.grid(row=2, column=1, sticky=tk.W, pady=2)
        
    def save_settings(self):
        """Save all settings"""
        try:
            # Update API keys
            for api_name, entry in self.api_entries.items():
                self.current_settings['api_keys'][api_name] = entry.get()
            
            # Update scan settings
            self.current_settings['scan_settings'].update({
                'default_ports': self.default_ports_entry.get(),
                'scan_timeout': float(self.timeout_entry.get()),
                'max_threads': int(self.threads_entry.get())
            })
            
            # Update monitor settings
            self.current_settings['monitor_settings'].update({
                'alert_threshold': int(self.threshold_entry.get()),
                'alert_cooldown': int(self.cooldown_entry.get()),
                'log_interval': float(self.log_interval_entry.get())
            })
            
            # Update UI settings
            self.current_settings['ui_settings'].update({
                'theme': self.theme_var.get(),
                'font_size': int(self.font_size_entry.get()),
                'window_size': self.window_size_entry.get()
            })
            
            if self.settings_manager.save_settings(self.current_settings):
                messagebox.showinfo("Success", "Settings saved successfully!")
                self.window.destroy()
            else:
                messagebox.showerror("Error", "Failed to save settings!")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid value: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def reset_settings(self):
        """Reset all settings to default values"""
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all settings to default values?"):
            self.current_settings = self.settings_manager.default_settings.copy()
            self.window.destroy()
            SettingsWindow(self.window.master, self.settings_manager) 