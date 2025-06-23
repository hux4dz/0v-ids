import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import copy
from settings_manager import SettingsManager
from alert_manager import AlertManager, deep_update
import logging

class AlertSettingsWindow:
    def __init__(self, parent, alert_manager):
        self.window = tk.Toplevel(parent)
        self.window.title("Alert Settings")
        self.window.geometry("800x800")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.alert_manager = alert_manager
        self.threat_detector = alert_manager.threat_detector
        self.settings_manager = SettingsManager()
        
        # --- Sidebar + Content Layout ---
        main_container = ttk.Frame(self.window)
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        self.sidebar = ttk.Frame(main_container, width=180, padding="10 10 10 10")
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.content_frame = ttk.Frame(main_container, padding="10 10 10 10")
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # --- Sidebar Navigation Buttons ---
        self.sections = [
            ("Thresholds", self._show_thresholds),
            ("Suspicious Ports", self._show_ports),
            ("Attack Patterns", self._show_patterns),
            ("Ignored Processes", self._show_ignored_processes)
        ]
        self.sidebar_buttons = {}
        for idx, (label, callback) in enumerate(self.sections):
            btn = ttk.Button(self.sidebar, text=label, command=callback, style="Sidebar.TButton")
            btn.pack(fill=tk.X, pady=2)
            self.sidebar_buttons[label] = btn
        
        # --- Style for Sidebar ---
        style = ttk.Style()
        style.configure("Sidebar.TButton", font=("TkDefaultFont", 11, "bold"), anchor="w", padding=6)
        
        # --- Save/Restore/Cancel Buttons (Pinned to Bottom) ---
        button_frame = ttk.Frame(self.window)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=8)
        ttk.Button(button_frame, text="Save", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Restore Recommended", command=self.reset_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.window.destroy).pack(side=tk.RIGHT, padx=5)
        
        # --- Show the first section by default ---
        self._show_thresholds()

    # --- Section Show Methods ---
    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _show_thresholds(self):
        self._clear_content()
        self._create_thresholds_tab(parent=self.content_frame)

    def _show_ports(self):
        self._clear_content()
        self._create_ports_tab(parent=self.content_frame)

    def _show_patterns(self):
        self._clear_content()
        self._create_patterns_tab(parent=self.content_frame)

    def _show_ignored_processes(self):
        self._clear_content()
        self._create_ignored_processes_tab(parent=self.content_frame)

    def _create_thresholds_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create variables for thresholds
        self.threshold_vars = {}
        row = 0
        
        # Connection Flood Settings
        flood_frame = ttk.LabelFrame(frame, text="Connection Flood Detection", padding="5")
        flood_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Label(flood_frame, text="Enabled:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood_enabled'] = tk.BooleanVar(value=self.alert_manager.alert_settings['connection_flood'].get('enabled', True))
        ttk.Checkbutton(flood_frame, text="Enable detection", variable=self.threshold_vars['connection_flood_enabled']).grid(row=0, column=1, padx=5)
        
        ttk.Label(flood_frame, text="Threshold (connections):").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood'] = tk.StringVar(value=str(self.alert_manager.alert_settings['connection_flood'].get('threshold', 550)))
        ttk.Entry(flood_frame, textvariable=self.threshold_vars['connection_flood'], width=10).grid(row=1, column=1, padx=5)
        
        ttk.Label(flood_frame, text="Cooldown (seconds):").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood_cooldown'] = tk.StringVar(value=str(self.alert_manager.alert_settings['connection_flood'].get('cooldown', 133)))
        ttk.Entry(flood_frame, textvariable=self.threshold_vars['connection_flood_cooldown'], width=10).grid(row=1, column=3, padx=5)
        
        ttk.Label(flood_frame, text="Severity:").grid(row=1, column=4, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood_severity'] = tk.StringVar(value=self.alert_manager.alert_settings['connection_flood'].get('severity', 'low'))
        severity_combo = ttk.Combobox(flood_frame, textvariable=self.threshold_vars['connection_flood_severity'], 
                                    values=['low', 'medium', 'high', 'critical'], width=10)
        severity_combo.grid(row=1, column=5, padx=5)
        
        row += 1
        
        # Port Scan Settings
        port_scan_frame = ttk.LabelFrame(frame, text="Port Scan Detection", padding="5")
        port_scan_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Label(port_scan_frame, text="Enabled:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan_enabled'] = tk.BooleanVar(value=self.alert_manager.alert_settings['port_scan'].get('enabled', True))
        ttk.Checkbutton(port_scan_frame, text="Enable detection", variable=self.threshold_vars['port_scan_enabled']).grid(row=0, column=1, padx=5)
        
        ttk.Label(port_scan_frame, text="Threshold (ports):").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan'] = tk.StringVar(value=str(self.alert_manager.alert_settings['port_scan'].get('threshold', 22)))
        ttk.Entry(port_scan_frame, textvariable=self.threshold_vars['port_scan'], width=10).grid(row=1, column=1, padx=5)
        
        ttk.Label(port_scan_frame, text="Cooldown (seconds):").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan_cooldown'] = tk.StringVar(value=str(self.alert_manager.alert_settings['port_scan'].get('cooldown', 472)))
        ttk.Entry(port_scan_frame, textvariable=self.threshold_vars['port_scan_cooldown'], width=10).grid(row=1, column=3, padx=5)
        
        ttk.Label(port_scan_frame, text="Severity:").grid(row=1, column=4, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan_severity'] = tk.StringVar(value=self.alert_manager.alert_settings['port_scan'].get('severity', 'low'))
        severity_combo = ttk.Combobox(port_scan_frame, textvariable=self.threshold_vars['port_scan_severity'], 
                                    values=['low', 'medium', 'high', 'critical'], width=10)
        severity_combo.grid(row=1, column=5, padx=5)
        
        row += 1
        
        # Data Exfiltration Settings
        data_frame = ttk.LabelFrame(frame, text="Data Exfiltration Detection", padding="5")
        data_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Label(data_frame, text="Enabled:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['data_exfiltration_enabled'] = tk.BooleanVar(value=self.alert_manager.alert_settings['data_exfiltration'].get('enabled', True))
        ttk.Checkbutton(data_frame, text="Enable detection", variable=self.threshold_vars['data_exfiltration_enabled']).grid(row=0, column=1, padx=5)
        
        ttk.Label(data_frame, text="Size threshold (bytes):").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['data_exfiltration_size'] = tk.StringVar(value=str(self.alert_manager.alert_settings['data_exfiltration'].get('size', 52428800)))
        ttk.Entry(data_frame, textvariable=self.threshold_vars['data_exfiltration_size'], width=15).grid(row=1, column=1, padx=5)
        
        ttk.Label(data_frame, text="Time window (seconds):").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['data_exfiltration_window'] = tk.StringVar(value=str(self.alert_manager.alert_settings['data_exfiltration'].get('window', 60)))
        ttk.Entry(data_frame, textvariable=self.threshold_vars['data_exfiltration_window'], width=10).grid(row=1, column=3, padx=5)
        
        ttk.Label(data_frame, text="Severity:").grid(row=1, column=4, sticky=tk.W, padx=5)
        self.threshold_vars['data_exfiltration_severity'] = tk.StringVar(value=self.alert_manager.alert_settings['data_exfiltration'].get('severity', 'critical'))
        severity_combo = ttk.Combobox(data_frame, textvariable=self.threshold_vars['data_exfiltration_severity'], 
                                    values=['low', 'medium', 'high', 'critical'], width=10)
        severity_combo.grid(row=1, column=5, padx=5)
        
        row += 1
        
        # Other Detection Settings
        other_frame = ttk.LabelFrame(frame, text="Other Detection Settings", padding="5")
        other_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        # Malicious IP Detection
        ttk.Label(other_frame, text="Malicious IP Detection:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['malicious_ip_enabled'] = tk.BooleanVar(value=self.alert_manager.alert_settings.get('malicious_ip', {}).get('enabled', True))
        ttk.Checkbutton(other_frame, text="Enable", variable=self.threshold_vars['malicious_ip_enabled']).grid(row=0, column=1, padx=5)
        
        ttk.Label(other_frame, text="Severity:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['malicious_ip_severity'] = tk.StringVar(value=self.alert_manager.alert_settings.get('malicious_ip', {}).get('severity', 'high'))
        severity_combo = ttk.Combobox(other_frame, textvariable=self.threshold_vars['malicious_ip_severity'], 
                                    values=['low', 'medium', 'high', 'critical'], width=10)
        severity_combo.grid(row=0, column=3, padx=5)
        
        # Suspicious Port Detection
        ttk.Label(other_frame, text="Suspicious Port Detection:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['suspicious_port_enabled'] = tk.BooleanVar(value=self.alert_manager.alert_settings.get('suspicious_port', {}).get('enabled', True))
        ttk.Checkbutton(other_frame, text="Enable", variable=self.threshold_vars['suspicious_port_enabled']).grid(row=1, column=1, padx=5)
        
        # Attack Pattern Detection
        ttk.Label(other_frame, text="Attack Pattern Detection:").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['attack_patterns_enabled'] = tk.BooleanVar(value=self.alert_manager.alert_settings.get('attack_patterns', {}).get('enabled', True))
        ttk.Checkbutton(other_frame, text="Enable", variable=self.threshold_vars['attack_patterns_enabled']).grid(row=2, column=1, padx=5)
        
        ttk.Label(other_frame, text="Severity:").grid(row=2, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['attack_patterns_severity'] = tk.StringVar(value=self.alert_manager.alert_settings.get('attack_patterns', {}).get('severity', 'high'))
        severity_combo = ttk.Combobox(other_frame, textvariable=self.threshold_vars['attack_patterns_severity'], 
                                    values=['low', 'medium', 'high', 'critical'], width=10)
        severity_combo.grid(row=2, column=3, padx=5)
        
        # Alert History Settings
        ttk.Label(other_frame, text="Max Alerts in History:").grid(row=3, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['max_alerts'] = tk.StringVar(value=str(self.alert_manager.alert_settings.get('alert_history', {}).get('max_alerts', 1000)))
        ttk.Entry(other_frame, textvariable=self.threshold_vars['max_alerts'], width=10).grid(row=3, column=1, padx=5)
        
        row += 1
        
        # Add help text
        help_text = """
        Threat Detection Settings Guide:
        - Connection Flood: Detects rapid connection attempts from a single source
        - Port Scan: Identifies systematic port scanning behavior  
        - Data Exfiltration: Monitors for large data transfers
        - Malicious IP: Checks against known malicious IP lists
        - Suspicious Port: Alerts on access to potentially dangerous ports
        - Attack Patterns: Detects common attack signatures in traffic
        
        Enable/Disable: Turn individual detection methods on or off
        Threshold: Number of events before alerting
        Cooldown: Time window for counting events
        Severity: Alert importance level (low/medium/high/critical)
        """
        help_label = ttk.Label(frame, text=help_text, wraplength=800)
        help_label.grid(row=row+1, column=0, columnspan=2, sticky=tk.W, pady=10)

    def _create_ports_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for ports and protocols
        port_notebook = ttk.Notebook(frame)
        port_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Suspicious Ports tab
        suspicious_frame = ttk.Frame(port_notebook)
        port_notebook.add(suspicious_frame, text="Suspicious Ports")
        
        # Create treeview for suspicious ports
        columns = ("Port", "Service", "Risk Level", "Description")
        self.port_tree = ttk.Treeview(suspicious_frame, columns=columns, show="headings")
        
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=150)
        
        self.port_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(suspicious_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.port_tree.configure(yscrollcommand=scrollbar.set)
        
        # Add buttons for port management
        button_frame = ttk.Frame(suspicious_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Add Port", command=self._add_suspicious_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Port", command=self._edit_suspicious_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Port", command=self._remove_suspicious_port).pack(side=tk.LEFT, padx=5)
        
        # Ignored Ports tab
        ignored_frame = ttk.Frame(port_notebook)
        port_notebook.add(ignored_frame, text="Ignored Ports")
        
        # Create treeview for ignored ports
        self.ignored_tree = ttk.Treeview(ignored_frame, columns=("Port", "Protocol", "Description"), show="headings")
        
        for col in ("Port", "Protocol", "Description"):
            self.ignored_tree.heading(col, text=col)
            self.ignored_tree.column(col, width=150)
        
        self.ignored_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Add scrollbar
        ignored_scrollbar = ttk.Scrollbar(ignored_frame, orient=tk.VERTICAL, command=self.ignored_tree.yview)
        ignored_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.ignored_tree.configure(yscrollcommand=ignored_scrollbar.set)
        
        # Add buttons for ignored ports
        ignored_button_frame = ttk.Frame(ignored_frame)
        ignored_button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(ignored_button_frame, text="Add Ignored Port", command=self._add_ignored_port).pack(side=tk.LEFT, padx=5)
        ttk.Button(ignored_button_frame, text="Remove Ignored Port", command=self._remove_ignored_port).pack(side=tk.LEFT, padx=5)
        
        # Populate trees
        self._populate_port_trees()

    def _create_patterns_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        # Create Treeview for patterns
        self.pattern_tree = ttk.Treeview(frame, columns=("Type", "Pattern"), show="headings")
        self.pattern_tree.heading("Type", text="Attack Type")
        self.pattern_tree.heading("Pattern", text="RegEx Pattern")
        self.pattern_tree.column("Type", width=150, anchor="w")
        self.pattern_tree.column("Pattern", width=500, anchor="w")
        self.pattern_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.pattern_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.pattern_tree.configure(yscrollcommand=scrollbar.set)

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add Pattern", command=self._add_pattern).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Pattern", command=self._edit_pattern).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Pattern", command=self._remove_pattern).pack(side=tk.LEFT, padx=5)

        self._populate_patterns()

    def _populate_patterns(self):
        for i in self.pattern_tree.get_children():
            self.pattern_tree.delete(i)
        
        patterns = self.settings_manager.load_settings().get('attack_patterns', {})
        for attack_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                self.pattern_tree.insert("", tk.END, values=(attack_type, pattern))

    def _add_pattern(self):
        self._edit_pattern_dialog(None)

    def _edit_pattern(self):
        selected_item = self.pattern_tree.focus()
        if not selected_item:
            messagebox.showerror("Error", "No pattern selected.")
            return
        self._edit_pattern_dialog(selected_item)

    def _edit_pattern_dialog(self, item):
        is_new = item is None
        title = "Add Pattern" if is_new else "Edit Pattern"
        
        dialog = tk.Toplevel(self.window)
        dialog.title(title)
        dialog.transient(self.window)
        dialog.grab_set()
        
        if is_new:
            current_type, current_pattern = "", ""
        else:
            values = self.pattern_tree.item(item, 'values')
            current_type, current_pattern = values[0], values[1]

        # Widgets
        ttk.Label(dialog, text="Attack Type:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        type_var = tk.StringVar(value=current_type)
        attack_types = list(self.settings_manager.load_settings().get('attack_patterns', {}).keys())
        type_combo = ttk.Combobox(dialog, textvariable=type_var, values=attack_types)
        type_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Pattern (Regex):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        pattern_var = tk.StringVar(value=current_pattern)
        ttk.Entry(dialog, textvariable=pattern_var, width=80).grid(row=1, column=1, padx=5, pady=5)

        def save():
            new_type = type_var.get().strip()
            new_pattern = pattern_var.get().strip()
            if not new_type or not new_pattern:
                messagebox.showerror("Error", "All fields are required.", parent=dialog)
                return

            settings = self.settings_manager.load_settings()
            patterns = settings.get('attack_patterns', {})

            if not is_new:
                # Remove old pattern
                if current_type in patterns and current_pattern in patterns[current_type]:
                    patterns[current_type].remove(current_pattern)
                    if not patterns[current_type]:
                        del patterns[current_type]

            # Add new pattern
            if new_type not in patterns:
                patterns[new_type] = []
            patterns[new_type].append(new_pattern)
            
            settings['attack_patterns'] = patterns
            self.settings_manager.save_settings(settings)
            self._populate_patterns()
            dialog.destroy()

        save_button = ttk.Button(dialog, text="Save", command=save)
        save_button.grid(row=2, column=1, padx=5, pady=10, sticky="e")
        cancel_button = ttk.Button(dialog, text="Cancel", command=dialog.destroy)
        cancel_button.grid(row=2, column=0, padx=5, pady=10, sticky="e")

    def _remove_pattern(self):
        selected_item = self.pattern_tree.focus()
        if not selected_item:
            messagebox.showerror("Error", "No pattern selected.")
            return
            
        values = self.pattern_tree.item(selected_item, 'values')
        attack_type, pattern_to_remove = values[0], values[1]

        if messagebox.askyesno("Confirm", f"Remove pattern for '{attack_type}'?"):
            settings = self.settings_manager.load_settings()
            patterns = settings.get('attack_patterns', {})
            if attack_type in patterns and pattern_to_remove in patterns[attack_type]:
                patterns[attack_type].remove(pattern_to_remove)
                if not patterns[attack_type]:
                    del patterns[attack_type]
                settings['attack_patterns'] = patterns
                self.settings_manager.save_settings(settings)
                self._populate_patterns()

    def _populate_port_trees(self):
        # Populate suspicious ports
        for port, info in self.alert_manager.suspicious_ports.items():
            self.port_tree.insert("", tk.END, values=(port, info.get('service', ''), 
                                                     info.get('risk_level', 'medium'),
                                                     info.get('description', '')))
        
        # Populate ignored ports
        for port, info in self.alert_manager.ignored_ports.items():
            if isinstance(info, dict):
                protocol = info.get('protocol', '')
                description = info.get('description', '')
            else:
                protocol = ''
                description = str(info)
            self.ignored_tree.insert("", tk.END, values=(port, protocol, description))

    def _add_suspicious_port(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Add Suspicious Port")
        dialog.geometry("400x200")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Port:").grid(row=0, column=0, padx=5, pady=5)
        port_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=port_var).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Service:").grid(row=1, column=0, padx=5, pady=5)
        service_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=service_var).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Risk Level:").grid(row=2, column=0, padx=5, pady=5)
        risk_var = tk.StringVar(value="medium")
        ttk.Combobox(dialog, textvariable=risk_var, values=['low', 'medium', 'high']).grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Description:").grid(row=3, column=0, padx=5, pady=5)
        desc_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=desc_var).grid(row=3, column=1, padx=5, pady=5)
        
        def save():
            try:
                port = int(port_var.get())
                if not (1 <= port <= 65535):
                    raise ValueError("Port must be between 1 and 65535")
                
                self.alert_manager.suspicious_ports[port] = {
                    'service': service_var.get(),
                    'risk_level': risk_var.get(),
                    'description': desc_var.get()
                }
                self._populate_port_trees()
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e), parent=dialog)
        
        ttk.Button(dialog, text="Save", command=save).grid(row=4, column=0, columnspan=2, pady=10)

    def _edit_suspicious_port(self):
        selected = self.port_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a port to edit")
            return
        
        values = self.port_tree.item(selected[0])['values']
        port = int(values[0])
        
        dialog = tk.Toplevel(self.window)
        dialog.title("Edit Suspicious Port")
        dialog.geometry("400x200")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Port:").grid(row=0, column=0, padx=5, pady=5)
        port_var = tk.StringVar(value=str(port))
        ttk.Entry(dialog, textvariable=port_var, state='readonly').grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Service:").grid(row=1, column=0, padx=5, pady=5)
        service_var = tk.StringVar(value=values[1])
        ttk.Entry(dialog, textvariable=service_var).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Risk Level:").grid(row=2, column=0, padx=5, pady=5)
        risk_var = tk.StringVar(value=values[2])
        ttk.Combobox(dialog, textvariable=risk_var, values=['low', 'medium', 'high']).grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Description:").grid(row=3, column=0, padx=5, pady=5)
        desc_var = tk.StringVar(value=values[3])
        ttk.Entry(dialog, textvariable=desc_var).grid(row=3, column=1, padx=5, pady=5)
        
        def save():
            self.alert_manager.suspicious_ports[port] = {
                'service': service_var.get(),
                'risk_level': risk_var.get(),
                'description': desc_var.get()
            }
            self._populate_port_trees()
            dialog.destroy()
        
        ttk.Button(dialog, text="Save", command=save).grid(row=4, column=0, columnspan=2, pady=10)

    def _remove_suspicious_port(self):
        selected = self.port_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a port to remove")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to remove this port?"):
            values = self.port_tree.item(selected[0])['values']
            port = int(values[0])
            if port in self.alert_manager.suspicious_ports:
                del self.alert_manager.suspicious_ports[port]
                self._populate_port_trees()

    def _add_ignored_port(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Add Ignored Port")
        dialog.geometry("400x150")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Port:").grid(row=0, column=0, padx=5, pady=5)
        port_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=port_var).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Protocol:").grid(row=1, column=0, padx=5, pady=5)
        protocol_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=protocol_var).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Description:").grid(row=2, column=0, padx=5, pady=5)
        desc_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=desc_var).grid(row=2, column=1, padx=5, pady=5)
        
        def save():
            try:
                port = int(port_var.get())
                if not (1 <= port <= 65535):
                    raise ValueError("Port must be between 1 and 65535")
                
                self.alert_manager.ignored_ports[port] = {
                    'protocol': protocol_var.get(),
                    'description': desc_var.get()
                }
                self._populate_port_trees()
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e), parent=dialog)
        
        ttk.Button(dialog, text="Save", command=save).grid(row=3, column=0, columnspan=2, pady=10)

    def _remove_ignored_port(self):
        selected = self.ignored_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a port to remove")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to remove this port?"):
            values = self.ignored_tree.item(selected[0])['values']
            port = int(values[0])
            if port in self.alert_manager.ignored_ports:
                del self.alert_manager.ignored_ports[port]
                self._populate_port_trees()

    def _create_ignored_processes_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Ignored Processes (by name):", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))

        self.ignored_process_var = tk.StringVar()
        self.ignored_process_entry = ttk.Entry(frame, textvariable=self.ignored_process_var, width=30)
        self.ignored_process_entry.pack(anchor=tk.W, pady=(0, 5))

        add_btn = ttk.Button(frame, text="Add Process", command=self._add_ignored_process)
        add_btn.pack(anchor=tk.W, pady=(0, 10))

        self.ignored_process_listbox = tk.Listbox(frame, height=8, width=40)
        self.ignored_process_listbox.pack(anchor=tk.W, pady=(0, 5))
        self._refresh_ignored_process_listbox()

        remove_btn = ttk.Button(frame, text="Remove Selected", command=self._remove_selected_ignored_process)
        remove_btn.pack(anchor=tk.W, pady=(0, 10))

    def _add_ignored_process(self):
        name = self.ignored_process_var.get().strip()
        if name:
            if name not in self.settings_manager.load_settings().get('ignored_processes', []):
                settings = self.settings_manager.load_settings()
                settings.setdefault('ignored_processes', []).append(name)
                self.settings_manager.save_settings(settings)
                self.ignored_process_var.set("")
                self._refresh_ignored_process_listbox()

    def _remove_selected_ignored_process(self):
        selection = self.ignored_process_listbox.curselection()
        if selection:
            idx = selection[0]
            settings = self.settings_manager.load_settings()
            ignored = settings.get('ignored_processes', [])
            if 0 <= idx < len(ignored):
                ignored.pop(idx)
                settings['ignored_processes'] = ignored
                self.settings_manager.save_settings(settings)
                self._refresh_ignored_process_listbox()

    def _refresh_ignored_process_listbox(self):
        self.ignored_process_listbox.delete(0, tk.END)
        ignored = self.settings_manager.load_settings().get('ignored_processes', [])
        for name in ignored:
            self.ignored_process_listbox.insert(tk.END, name)

    def save_settings(self):
        try:
            # --- Load current settings ---
            current_settings = self.settings_manager.load_settings()
            
            # --- Create a deep copy to modify ---
            new_settings = copy.deepcopy(current_settings)

            # --- Save Thresholds ---
            if hasattr(self, 'threshold_vars'):
                alert_settings = new_settings.get('alert_settings', {})
                
                # Helper to update a setting group
                def update_threshold_group(group_name, settings_map):
                    group = alert_settings.get(group_name, {})
                    for key, var_name in settings_map.items():
                        if var_name in self.threshold_vars:
                            try:
                                value = self.threshold_vars[var_name].get()
                                # Convert to correct type
                                if isinstance(value, str) and value.isdigit():
                                    value = int(value)
                                group[key] = value
                            except (tk.TclError, ValueError) as e:
                                logging.warning(f"Could not get value for {var_name}: {e}")
                    alert_settings[group_name] = group
                
                # Update all threshold groups
                update_threshold_group('connection_flood', {'enabled': 'connection_flood_enabled', 'threshold': 'connection_flood', 'cooldown': 'connection_flood_cooldown', 'severity': 'connection_flood_severity'})
                update_threshold_group('port_scan', {'enabled': 'port_scan_enabled', 'threshold': 'port_scan', 'cooldown': 'port_scan_cooldown', 'severity': 'port_scan_severity'})
                update_threshold_group('data_exfiltration', {'enabled': 'data_exfiltration_enabled', 'size': 'data_exfiltration_size', 'window': 'data_exfiltration_window', 'severity': 'data_exfiltration_severity'})
                update_threshold_group('malicious_ip', {'enabled': 'malicious_ip_enabled', 'severity': 'malicious_ip_severity'})
                update_threshold_group('suspicious_port', {'enabled': 'suspicious_port_enabled'})
                update_threshold_group('attack_patterns', {'enabled': 'attack_patterns_enabled', 'severity': 'attack_patterns_severity'})
                update_threshold_group('alert_history', {'max_alerts': 'max_alerts'})
                
                new_settings['alert_settings'] = alert_settings

            # --- Save Suspicious and Ignored Ports ---
            if hasattr(self, 'port_tree'):
                # Save suspicious ports
                suspicious_ports = {}
                for iid in self.port_tree.get_children():
                    item = self.port_tree.item(iid)
                    values = item['values']
                    port = str(values[0])
                    suspicious_ports[port] = {"service": values[1], "risk": values[2], "description": values[3]}
                new_settings['suspicious_ports'] = suspicious_ports
            
            if hasattr(self, 'ignored_port_tree'):
                # Save ignored ports
                ignored_ports = {}
                for iid in self.ignored_port_tree.get_children():
                    item = self.ignored_port_tree.item(iid)
                    values = item['values']
                    ignored_ports[str(values[0])] = values[1]
                new_settings['ignored_ports'] = ignored_ports

            # --- Save Attack Patterns ---
            if hasattr(self, 'pattern_tree'):
                attack_patterns = new_settings.get('attack_patterns', {})
                # Clear old patterns and repopulate
                for key in attack_patterns:
                    attack_patterns[key] = []
                    
                for iid in self.pattern_tree.get_children():
                    item = self.pattern_tree.item(iid)
                    values = item['values']
                    attack_type, pattern = values[0], values[1]
                    if attack_type in attack_patterns:
                        attack_patterns[attack_type].append(pattern)
                new_settings['attack_patterns'] = attack_patterns

            # --- Save Ignored Processes ---
            if hasattr(self, 'ignored_process_listbox'):
                processes = list(self.ignored_process_listbox.get(0, tk.END))
                new_settings['ignored_processes'] = processes

            # --- Use the SettingsManager to save ---
            self.settings_manager.save_settings(new_settings)

            # --- Reload settings in the application ---
            if self.alert_manager and hasattr(self.alert_manager, 'threat_detector'):
                self.alert_manager.threat_detector.reload_settings()

            messagebox.showinfo("Success", "Settings saved successfully and reloaded (Please Restart Your App!)", parent=self.window)
            self.window.destroy()
            
        except Exception as e:
            logging.error(f"Error saving settings: {str(e)}")
            messagebox.showerror("Error", f"Could not save settings: {e}", parent=self.window)


    def reset_settings(self):
        if messagebox.askokcancel("Confirm Reset", 
                                "Are you sure you want to restore all settings to their recommended defaults? This will overwrite your current settings.",
                                parent=self.window):
            try:
                # --- Define Recommended Default Settings ---
                recommended_defaults = {
                    "alert_settings": {
                        "connection_flood": {
                            "threshold": 1250, "cooldown": 60, "severity": "low", "enabled": True,
                            "description": "Number of connections before alerting"
                        },
                        "port_scan": {
                            "threshold": 2, "cooldown": 10, "severity": "low", "enabled": True,
                            "description": "Number of ports scanned before alerting"
                        },
                        "data_exfiltration": {
                            "size": 15092200, "window": 60, "severity": "critical", "enabled": True,
                            "description": "Amount of data transferred within time window (in bytes)"
                        },
                        "malicious_ip": {
                            "enabled": True, "severity": "high",
                            "description": "Connection from known malicious IP"
                        },
                        "suspicious_port": {
                            "enabled": True,
                            "description": "Access to suspicious port detected"
                        },
                        "attack_patterns": {
                            "enabled": True, "severity": "high",
                            "description": "Attack pattern detected in traffic"
                        },
                        "alert_history": {
                            "max_alerts": 1000,
                            "description": "Maximum number of alerts to keep in history"
                        }
                    },
                    "suspicious_ports": {
                        "22": {"service": "SSH", "risk": "medium", "description": "Secure Shell - Remote access protocol"},
                        "23": {"service": "Telnet", "risk": "high", "description": "Telnet - Unencrypted remote access"},
                        "445": {"service": "SMB", "risk": "high", "description": "Server Message Block - File sharing protocol"},
                        "3389": {"service": "RDP", "risk": "medium", "description": "Remote Desktop Protocol"},
                        "1433": {"service": "MSSQL", "risk": "high", "description": "Microsoft SQL Server"},
                        "3306": {"service": "MySQL", "risk": "high", "description": "MySQL Database Server"},
                        "5432": {"service": "PostgreSQL", "risk": "high", "description": "PostgreSQL Database Server"}
                    },
                    "attack_patterns": {
                        "sql_injection": [
                            "(?i)('|\"|%27|%22|`).*(or|and).*(%3D|=|>|<|'|\"|%27|%22|`)",
                            "(?i)('|\"|%27|%22|`).*\\s(union|select)\\s.*(from|into)",
                            "(?i)('|\"|%27|%22|`|;).*(waitfor|sleep|benchmark)\\(",
                            "(?i)(--|#|\\/\\*|;)",
                            "(\\b(exec|execute|xp_cmdshell|sp_executesql)\\b)"
                        ],
                        "xss": [
                            "(?i)(<|%3C)script.*?(>|%3E).*(<|%3C)\\/script.*?(>|%3E)",
                            "(?i)javascript:",
                            "(?i)on(error|load|click|mouseover|focus|submit|change|input|drag|drop|keypress|keydown|keyup)\\s*=",
                            "(?i)<(iframe|frame|embed|object|svg|math|img|body|a|div|style|video|audio|form|input|button|textarea)",
                            "\\b(alert|confirm|prompt)\\s*\\(",
                            "document\\.(cookie|location|domain|write)",
                            "eval\\s*\\(",
                            "window\\."
                        ]
                    },
                    "ignored_processes": [
                        "chrome.exe", "firefox.exe", "msedge.exe", 
                        "System Idle Process", "spoolsv.exe", "Cursor.exe", "asus_framework.exe"
                    ]
                }

                # --- Load current settings and update with defaults ---
                current_settings = self.settings_manager.load_settings()
                
                # Update only the sections managed by this window
                current_settings['alert_settings'] = recommended_defaults['alert_settings']
                current_settings['suspicious_ports'] = recommended_defaults['suspicious_ports']
                current_settings['attack_patterns'] = recommended_defaults['attack_patterns']
                current_settings['ignored_processes'] = recommended_defaults['ignored_processes']

                # --- Save the updated settings ---
                self.settings_manager.save_settings(current_settings)

                # --- Reload settings in the application ---
                if self.alert_manager and hasattr(self.alert_manager, 'threat_detector'):
                    self.alert_manager.threat_detector.reload_settings()

                messagebox.showinfo("Success", 
                                    "Settings have been reset to their recommended defaults. The window will now close (Please Restart Your App!)", 
                                    parent=self.window)
                self.window.destroy()

            except Exception as e:
                logging.error(f"Error resetting settings: {str(e)}")
                messagebox.showerror("Error", f"Could not reset settings: {e}", parent=self.window) 