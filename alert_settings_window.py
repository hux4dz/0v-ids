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
        self.window.geometry("900x600")
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
            ("Attack Patterns", self._show_patterns)
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

    def _create_thresholds_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create variables for thresholds
        self.threshold_vars = {}
        row = 0
        
        # Connection Flood Settings
        flood_frame = ttk.LabelFrame(frame, text="Connection Flood Detection", padding="5")
        flood_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Label(flood_frame, text="Threshold (connections):").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood'] = tk.StringVar(value=str(self.alert_manager.alert_settings['connection_flood']['threshold']))
        ttk.Entry(flood_frame, textvariable=self.threshold_vars['connection_flood'], width=10).grid(row=0, column=1, padx=5)
        
        ttk.Label(flood_frame, text="Cooldown (seconds):").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood_cooldown'] = tk.StringVar(value=str(self.alert_manager.alert_settings['connection_flood']['cooldown']))
        ttk.Entry(flood_frame, textvariable=self.threshold_vars['connection_flood_cooldown'], width=10).grid(row=0, column=3, padx=5)
        
        ttk.Label(flood_frame, text="Severity:").grid(row=0, column=4, sticky=tk.W, padx=5)
        self.threshold_vars['connection_flood_severity'] = tk.StringVar(value=self.alert_manager.alert_settings['connection_flood']['severity'])
        severity_combo = ttk.Combobox(flood_frame, textvariable=self.threshold_vars['connection_flood_severity'], 
                                    values=['low', 'medium', 'high'], width=10)
        severity_combo.grid(row=0, column=5, padx=5)
        
        row += 1
        
        # Port Scan Settings
        port_scan_frame = ttk.LabelFrame(frame, text="Port Scan Detection", padding="5")
        port_scan_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Label(port_scan_frame, text="Threshold (ports):").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan'] = tk.StringVar(value=str(self.alert_manager.alert_settings['port_scan']['threshold']))
        ttk.Entry(port_scan_frame, textvariable=self.threshold_vars['port_scan'], width=10).grid(row=0, column=1, padx=5)
        
        ttk.Label(port_scan_frame, text="Cooldown (seconds):").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan_cooldown'] = tk.StringVar(value=str(self.alert_manager.alert_settings['port_scan']['cooldown']))
        ttk.Entry(port_scan_frame, textvariable=self.threshold_vars['port_scan_cooldown'], width=10).grid(row=0, column=3, padx=5)
        
        ttk.Label(port_scan_frame, text="Severity:").grid(row=0, column=4, sticky=tk.W, padx=5)
        self.threshold_vars['port_scan_severity'] = tk.StringVar(value=self.alert_manager.alert_settings['port_scan']['severity'])
        severity_combo = ttk.Combobox(port_scan_frame, textvariable=self.threshold_vars['port_scan_severity'], 
                                    values=['low', 'medium', 'high'], width=10)
        severity_combo.grid(row=0, column=5, padx=5)
        
        row += 1
        
        # Data Transfer Settings
        data_frame = ttk.LabelFrame(frame, text="Data Transfer Detection", padding="5")
        data_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Label(data_frame, text="Threshold (bytes):").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.threshold_vars['data_transfer'] = tk.StringVar(value=str(self.alert_manager.alert_settings['data_transfer']['threshold']))
        ttk.Entry(data_frame, textvariable=self.threshold_vars['data_transfer'], width=15).grid(row=0, column=1, padx=5)
        
        ttk.Label(data_frame, text="Severity:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.threshold_vars['data_transfer_severity'] = tk.StringVar(value=self.alert_manager.alert_settings['data_transfer']['severity'])
        severity_combo = ttk.Combobox(data_frame, textvariable=self.threshold_vars['data_transfer_severity'], 
                                    values=['low', 'medium', 'high'], width=10)
        severity_combo.grid(row=0, column=3, padx=5)
        
        # Add help text
        help_text = """
        Threshold Settings Guide:
        - Connection Flood: Number of connections from a single source before alerting
        - Port Scan: Number of different ports scanned before alerting
        - Data Transfer: Size of data transfer in bytes before alerting
        
        Cooldown periods prevent alert spam by waiting before generating new alerts
        Severity levels determine how alerts are displayed and handled
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
        
        # Create notebook for different pattern types
        pattern_notebook = ttk.Notebook(frame)
        pattern_notebook.pack(fill=tk.BOTH, expand=True)
        
        self.pattern_text_widgets = {}
        self.pattern_types = [
            ("SQL Injection", "sql_injection"),
            ("XSS", "xss"),
            ("Command Injection", "command_injection"),
            ("Path Traversal", "path_traversal"),
            ("File Inclusion", "file_inclusion"),
            ("Deserialization", "deserialization")
        ]

        for label, key in self.pattern_types:
            tab = ttk.Frame(pattern_notebook)
            pattern_notebook.add(tab, text=label)
            # Text area for patterns
            text = tk.Text(tab, wrap=tk.WORD, height=12)
            text.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        # Add scrollbar
            scrollbar = ttk.Scrollbar(tab, command=text.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text.configure(yscrollcommand=scrollbar.set)
            self.pattern_text_widgets[key] = text
            # Restore defaults button
            btn = ttk.Button(tab, text="Restore Defaults", command=lambda k=key: self._restore_default_patterns(k))
            btn.pack(anchor=tk.E, padx=5, pady=2)

        self._populate_pattern_texts()

    def _populate_pattern_texts(self):
        # Populate each pattern type from the threat_detector
        patterns = getattr(self, 'threat_detector', None)
        if not patterns:
            print("[DEBUG] No threat_detector found.")
            return
        for label, key in self.pattern_types:
            widget = self.pattern_text_widgets.get(key)
            if widget:
                widget.delete(1.0, tk.END)
                pattern_list = self.threat_detector.attack_patterns.get(key, [])
                print(f"[DEBUG] Loading patterns for {key}: {pattern_list}")
                if pattern_list:
                    widget.insert(tk.END, "\n".join(pattern_list))
                else:
                    widget.insert(tk.END, f"No patterns defined for {label}. Please add patterns.")

    def _restore_default_patterns(self, key):
        # Restore default patterns for a given type
        from threat_detection import ThreatDetector
        defaults = ThreatDetector().attack_patterns.get(key, [])
        widget = self.pattern_text_widgets.get(key)
        if widget:
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, "\n".join(defaults))

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

    def _create_advanced_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create variables for advanced settings
        self.advanced_vars = {}
        
        # Alert Behavior Settings
        behavior_frame = ttk.LabelFrame(frame, text="Alert Behavior", padding="5")
        behavior_frame.pack(fill=tk.X, pady=5)
        
        # Alert Cooldown
        ttk.Label(behavior_frame, text="Default Alert Cooldown (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.advanced_vars['alert_cooldown'] = tk.StringVar(value=str(self.alert_manager.alert_settings['alert_cooldown']['default']))
        ttk.Entry(behavior_frame, textvariable=self.advanced_vars['alert_cooldown'], width=10).grid(row=0, column=1, padx=5)
        
        # Alert Aggregation
        ttk.Label(behavior_frame, text="Alert Aggregation Window (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.advanced_vars['alert_aggregation'] = tk.StringVar(value="60")
        ttk.Entry(behavior_frame, textvariable=self.advanced_vars['alert_aggregation'], width=10).grid(row=1, column=1, padx=5)
        
        # Alert Retention
        ttk.Label(behavior_frame, text="Alert Retention (days):").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.advanced_vars['alert_retention'] = tk.StringVar(value="30")
        ttk.Entry(behavior_frame, textvariable=self.advanced_vars['alert_retention'], width=10).grid(row=2, column=1, padx=5)
        
        # Detection Settings
        detection_frame = ttk.LabelFrame(frame, text="Detection Settings", padding="5")
        detection_frame.pack(fill=tk.X, pady=5)
        
        # Enable/Disable Detection Types
        self.advanced_vars['detection_types'] = {
            'sql_injection': tk.BooleanVar(value=True),
            'xss': tk.BooleanVar(value=True),
            'command_injection': tk.BooleanVar(value=True),
            'path_traversal': tk.BooleanVar(value=True)
        }
        
        row = 0
        for detection_type, var in self.advanced_vars['detection_types'].items():
            ttk.Checkbutton(detection_frame, text=detection_type.replace('_', ' ').title(), 
                          variable=var).grid(row=row, column=0, sticky=tk.W, padx=5)
            row += 1
        
        # Add help text
        help_text = """
        Advanced Settings Guide:
        - Alert Cooldown: Minimum time between repeated alerts
        - Alert Aggregation: Time window for grouping similar alerts
        - Alert Retention: How long to keep alert history
        - Detection Types: Enable/disable specific detection methods
        """
        help_label = ttk.Label(frame, text=help_text, wraplength=800)
        help_label.pack(fill=tk.X, pady=10)

    def _create_rules_tab(self, parent):
        frame = ttk.Frame(parent, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create text widget for rules help
        self.rules_text = tk.Text(frame, wrap=tk.WORD, height=20)
        self.rules_text.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.rules_text, command=self.rules_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rules_text.configure(yscrollcommand=scrollbar.set)
        
        # Add rules help content
        rules_help = """
Alert Rules and Configuration Guide
==================================

1. Threshold Settings
--------------------
- Connection Flood: Detects rapid connection attempts from a single source
- Port Scan: Identifies systematic port scanning behavior
- Data Transfer: Monitors for large data transfers
- Each threshold can be customized with severity levels and cooldown periods

2. Port Monitoring
-----------------
- Suspicious Ports: Define ports that should trigger alerts when accessed
- Ignored Ports: Specify ports to exclude from monitoring
- Each port can have custom risk levels and descriptions

3. Attack Pattern Detection
--------------------------
- SQL Injection: Detects common SQL injection attempts
- XSS: Identifies cross-site scripting patterns
- Command Injection: Monitors for command injection attempts
- Path Traversal: Detects directory traversal attempts

4. Advanced Settings
-------------------
- Alert Cooldown: Prevents alert spam
- Alert Aggregation: Groups similar alerts
- Alert Retention: Controls alert history duration
- Detection Types: Enable/disable specific detection methods

5. Best Practices
----------------
- Start with default settings and adjust based on your environment
- Monitor alert patterns and adjust thresholds accordingly
- Regularly review and update attack patterns
- Keep port lists up to date with your services

6. Customization
---------------
- Add custom detection patterns
- Define specific port monitoring rules
- Adjust severity levels based on your needs
- Configure alert behavior for your environment
"""
        self.rules_text.insert(tk.END, rules_help)
        self.rules_text.config(state=tk.DISABLED)

    def save_settings(self):
        try:
            # Update threshold settings
            self.alert_manager.alert_settings['connection_flood'].update({
                'threshold': int(self.threshold_vars['connection_flood'].get()),
                'cooldown': int(self.threshold_vars['connection_flood_cooldown'].get()),
                'severity': self.threshold_vars['connection_flood_severity'].get()
            })
            self.alert_manager.alert_settings['port_scan'].update({
                'threshold': int(self.threshold_vars['port_scan'].get()),
                'cooldown': int(self.threshold_vars['port_scan_cooldown'].get()),
                'severity': self.threshold_vars['port_scan_severity'].get()
            })
            self.alert_manager.alert_settings['data_transfer'].update({
                'threshold': int(self.threshold_vars['data_transfer'].get()),
                'severity': self.threshold_vars['data_transfer_severity'].get()
            })
            
            # --- Sync thresholds to threat_detector ---
            td = self.alert_manager.threat_detector
            td.thresholds['connection_flood']['count'] = self.alert_manager.alert_settings['connection_flood']['threshold']
            td.thresholds['connection_flood']['window'] = self.alert_manager.alert_settings['connection_flood']['cooldown']
            td.thresholds['port_scan']['count'] = self.alert_manager.alert_settings['port_scan']['threshold']
            td.thresholds['port_scan']['window'] = self.alert_manager.alert_settings['port_scan']['cooldown']
            td.thresholds['data_exfiltration']['size'] = self.alert_manager.alert_settings['data_transfer']['threshold']
            # If you have a window/cooldown for data transfer, sync it too if needed

            # Save attack patterns from text widgets
            if hasattr(self, 'pattern_text_widgets'):
                for label, key in self.pattern_types:
                    widget = self.pattern_text_widgets.get(key)
                    if widget:
                        patterns = [line.strip() for line in widget.get(1.0, tk.END).splitlines() if line.strip()]
                        self.threat_detector.attack_patterns[key] = patterns
            
            # Save settings to file
            settings = self.settings_manager.load_settings()
            settings['alert_settings'] = self.alert_manager.alert_settings
            settings['suspicious_ports'] = self.alert_manager.suspicious_ports
            settings['ignored_ports'] = self.alert_manager.ignored_ports
            self.settings_manager.save_settings(settings)

            # Reload threat detector settings to apply changes immediately
            self.threat_detector.reload_settings()
            
            messagebox.showinfo("Success", "Settings saved successfully!")
            self.window.destroy()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid value: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def reset_settings(self):
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all settings to default values?"):
            self.alert_manager.alert_settings = copy.deepcopy(self.alert_manager.default_alert_settings)
            self.alert_manager.suspicious_ports = {}
            self.alert_manager.ignored_ports = {}
            self._populate_port_trees()
            self._populate_pattern_texts()
            messagebox.showinfo("Success", "Settings reset to default values") 