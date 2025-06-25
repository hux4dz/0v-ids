import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
import json
from malicious_ip_manager import MaliciousIPManager

class MaliciousIPWindowList:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Malicious IP Manager")
        self.window.geometry("800x600")
        
        self.ip_manager = MaliciousIPManager()
        
        self._create_widgets()
        self._load_ip_list()
        
    def _create_widgets(self):
        # Create main container
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create top buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Add IP button with icon
        add_btn = ttk.Button(button_frame, text="➕ Add IP", command=self._show_add_ip_dialog)
        add_btn.pack(side=tk.LEFT, padx=5)
        
        # Import/Export buttons
        ttk.Button(button_frame, text="📥 Import List", command=self._import_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📤 Export List", command=self._export_list).pack(side=tk.LEFT, padx=5)
        
        # Refresh button
        ttk.Button(button_frame, text="🔄 Refresh", command=self._load_ip_list).pack(side=tk.LEFT, padx=5)
        
        # Stats button
        ttk.Button(button_frame, text="📊 Show Stats", command=self._show_stats).pack(side=tk.LEFT, padx=5)

        # Add search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self._on_search_change)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Add filter options
        ttk.Label(search_frame, text="Filter by:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(search_frame, textvariable=self.filter_var, width=15)
        filter_combo['values'] = ('all', 'category', 'severity')
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self._on_filter_change)
        
        # Create Treeview with better styling
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('TkDefaultFont', 9, 'bold'))
        
        columns = ("IP", "Added Date", "Category", "Severity", "Reason", "Expiry")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", style="Treeview")
        
        # Configure columns with better widths
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Added Date", text="Added Date")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("Reason", text="Reason")
        self.tree.heading("Expiry", text="Expiry")
        
        self.tree.column("IP", width=120, anchor=tk.CENTER)
        self.tree.column("Added Date", width=150, anchor=tk.CENTER)
        self.tree.column("Category", width=100, anchor=tk.CENTER)
        self.tree.column("Severity", width=80, anchor=tk.CENTER)
        self.tree.column("Reason", width=200, anchor=tk.W)
        self.tree.column("Expiry", width=120, anchor=tk.CENTER)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Pack scrollbars and tree
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add context menu with icons
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="✏️ Edit IP", command=self._edit_selected_ip)
        self.context_menu.add_command(label="❌ Remove IP", command=self._remove_selected_ip)
        self.tree.bind("<Button-3>", self._show_context_menu)
        
        # Add double-click to edit
        self.tree.bind("<Double-1>", lambda e: self._edit_selected_ip())
        
        # Add status bar
        self.status_bar = ttk.Label(main_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _load_ip_list(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Load IPs from manager
        ips = self.ip_manager.get_all_ips()
        
        # Add to treeview
        for ip_data in ips:
            values = (
                ip_data["ip"],
                ip_data["added_date"],
                ip_data["category"],
                ip_data["severity"],
                ip_data["reason"],
                ip_data.get("expiry", "Never")
            )
            self.tree.insert("", tk.END, values=values)
            
    def _show_add_ip_dialog(self):
        dialog = tk.Toplevel(self.window)
        dialog.title("Add Malicious IP")
        dialog.geometry("400x400")
        dialog.transient(self.window)
        dialog.grab_set()
        
        # Create form with better styling
        form_frame = ttk.Frame(dialog, padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # IP Address
        ttk.Label(form_frame, text="IP Address:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        ip_entry = ttk.Entry(form_frame, width=40)
        ip_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Reason
        ttk.Label(form_frame, text="Reason:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        reason_entry = ttk.Entry(form_frame, width=40)
        reason_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Category
        ttk.Label(form_frame, text="Category:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        category_var = tk.StringVar(value="custom")
        category_combo = ttk.Combobox(form_frame, textvariable=category_var, width=37)
        category_combo['values'] = ('custom', 'spam', 'attack', 'suspicious', 'other')
        category_combo.pack(fill=tk.X, pady=(0, 10))
        
        # Severity
        ttk.Label(form_frame, text="Severity:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        severity_var = tk.StringVar(value="medium")
        severity_combo = ttk.Combobox(form_frame, textvariable=severity_var, width=37)
        severity_combo['values'] = ('low', 'medium', 'high', 'critical')
        severity_combo.pack(fill=tk.X, pady=(0, 10))
        
        # Expiry
        ttk.Label(form_frame, text="Expiry (days, 0 for never):", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        expiry_entry = ttk.Entry(form_frame, width=40)
        expiry_entry.insert(0, "0")
        expiry_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons frame
        btn_frame = ttk.Frame(form_frame)
        btn_frame.pack(fill=tk.X, pady=(20, 0))
        
        def add_ip():
            ip = ip_entry.get().strip()
            reason = reason_entry.get().strip()
            category = category_var.get()
            severity = severity_var.get()
            
            try:
                expiry_days = int(expiry_entry.get())
                expiry = None
                if expiry_days > 0:
                    expiry = (datetime.now() + timedelta(days=expiry_days)).isoformat()
                
                success, message = self.ip_manager.add_ip(
                    ip, reason, category, severity, expiry
                )
                
                if success:
                    messagebox.showinfo("Success", message, parent=dialog)
                    dialog.destroy()
                    self._load_ip_list()
                    self.status_bar.config(text=f"Added IP: {ip}")
                else:
                    messagebox.showerror("Error", message, parent=dialog)
            except ValueError:
                messagebox.showerror("Error", "Invalid expiry days value", parent=dialog)
        
        ttk.Button(btn_frame, text="Add", command=add_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Set focus to IP entry
        ip_entry.focus_set()
        
    def _remove_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0])["values"]
        ip, added_date, category, severity, reason, expiry = values
        confirm_msg = (
            f"Remove the following IP from the malicious list?\n\n"
            f"IP: {ip}\n"
            f"Added: {added_date}\n"
            f"Category: {category}\n"
            f"Severity: {severity}\n"
            f"Reason: {reason}\n"
            f"Expiry: {expiry}"
        )
        if messagebox.askyesno("Confirm Remove", confirm_msg):
            success, message = self.ip_manager.remove_ip(ip)
            if success:
                self._load_ip_list()
                self.status_bar.config(text=f"Removed IP: {ip}")
            else:
                messagebox.showerror("Error", message)

    def _edit_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            return
        # Get current values
        values = self.tree.item(selected[0])["values"]
        current_ip, added_date, category, severity, reason, expiry = values
        # Create edit dialog
        dialog = tk.Toplevel(self.window)
        dialog.title(f"Edit IP {current_ip}")
        dialog.geometry("400x400")
        dialog.transient(self.window)
        dialog.grab_set()
        # Form
        form_frame = ttk.Frame(dialog, padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True)
        # IP (readonly)
        ttk.Label(form_frame, text="IP Address:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        ip_entry = ttk.Entry(form_frame, width=40)
        ip_entry.insert(0, current_ip)
        ip_entry.config(state='readonly')
        ip_entry.pack(fill=tk.X, pady=(0, 10))
        # Reason
        ttk.Label(form_frame, text="Reason:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        reason_entry = ttk.Entry(form_frame, width=40)
        reason_entry.insert(0, reason)
        reason_entry.pack(fill=tk.X, pady=(0, 10))
        # Category
        ttk.Label(form_frame, text="Category:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        category_var = tk.StringVar(value=category)
        category_combo = ttk.Combobox(form_frame, textvariable=category_var, width=37)
        category_combo['values'] = ('custom', 'spam', 'attack', 'suspicious', 'other')
        category_combo.pack(fill=tk.X, pady=(0, 10))
        # Severity
        ttk.Label(form_frame, text="Severity:", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        severity_var = tk.StringVar(value=severity)
        severity_combo = ttk.Combobox(form_frame, textvariable=severity_var, width=37)
        severity_combo['values'] = ('low', 'medium', 'high', 'critical')
        severity_combo.pack(fill=tk.X, pady=(0, 10))
        # Expiry
        ttk.Label(form_frame, text="Expiry (days, 0 for never):", font=('TkDefaultFont', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        expiry_entry = ttk.Entry(form_frame, width=40)
        if expiry == "Never":
            expiry_entry.insert(0, "0")
        else:
            try:
                expiry_dt = datetime.fromisoformat(expiry)
                days = (expiry_dt - datetime.now()).days
                expiry_entry.insert(0, str(max(days, 0)))
            except Exception:
                expiry_entry.insert(0, "0")
        expiry_entry.pack(fill=tk.X, pady=(0, 10))
        # Buttons
        btn_frame = ttk.Frame(form_frame)
        btn_frame.pack(fill=tk.X, pady=(20, 0))
        def save_changes():
            new_reason = reason_entry.get().strip()
            new_category = category_var.get()
            new_severity = severity_var.get()
            try:
                expiry_days = int(expiry_entry.get())
                new_expiry = None
                if expiry_days > 0:
                    new_expiry = (datetime.now() + timedelta(days=expiry_days)).isoformat()
                # Update in place: remove and re-add with same added_date
                self.ip_manager.remove_ip(current_ip)
                success, message = self.ip_manager.add_ip(
                    current_ip, new_reason, new_category, new_severity, new_expiry, added_date=added_date
                )
                if success:
                    dialog.destroy()
                    self._load_ip_list()
                    self.status_bar.config(text=f"Edited IP: {current_ip}")
                else:
                    messagebox.showerror("Error", message, parent=dialog)
            except ValueError:
                messagebox.showerror("Error", "Invalid expiry days value", parent=dialog)
        ttk.Button(btn_frame, text="Save", command=save_changes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
    def _show_context_menu(self, event):
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            self.context_menu.post(event.x_root, event.y_root)
            
    def _import_list(self):
        file_path = filedialog.askopenfilename(
            title="Select IP List File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            imported, failed, errors = self.ip_manager.import_from_file(file_path)
            message = f"Imported {imported} IPs"
            if failed > 0:
                message += f"\nFailed to import {failed} IPs"
                if errors:
                    message += "\n\nErrors:\n" + "\n".join(errors[:5])
                    if len(errors) > 5:
                        message += f"\n... and {len(errors) - 5} more errors"
            
            messagebox.showinfo("Import Results", message)
            self._load_ip_list()
            
    def _export_list(self):
        file_path = filedialog.asksaveasfilename(
            title="Save IP List",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            success, message = self.ip_manager.export_to_file(file_path)
            if success:
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)
                
    def _show_stats(self):
        stats = self.ip_manager.get_stats()
        
        # Create stats window
        stats_window = tk.Toplevel(self.window)
        stats_window.title("Malicious IP Statistics")
        stats_window.geometry("300x200")
        stats_window.transient(self.window)
        
        # Display stats
        ttk.Label(stats_window, text=f"Total IPs: {stats['total_ips']}").pack(pady=5)
        
        ttk.Label(stats_window, text="\nBy Category:").pack(pady=5)
        for category, count in stats['by_category'].items():
            ttk.Label(stats_window, text=f"{category}: {count}").pack()
            
        ttk.Label(stats_window, text="\nBy Severity:").pack(pady=5)
        for severity, count in stats['by_severity'].items():
            ttk.Label(stats_window, text=f"{severity}: {count}").pack()

    def _on_search_change(self, *args):
        """Handle search text changes"""
        search_text = self.search_var.get().lower()
        self._filter_treeview(search_text)

    def _on_filter_change(self, event=None):
        """Handle filter selection changes"""
        self._filter_treeview(self.search_var.get().lower())

    def _filter_treeview(self, search_text):
        """Filter treeview items based on search text and selected filter"""
        filter_type = self.filter_var.get()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Get all IPs
        ips = self.ip_manager.get_all_ips()
        
        # Filter and add matching items
        for ip_data in ips:
            values = (
                ip_data["ip"],
                ip_data["added_date"],
                ip_data["category"],
                ip_data["severity"],
                ip_data["reason"],
                ip_data.get("expiry", "Never")
            )
            
            # Apply search filter
            if search_text:
                if filter_type == "all":
                    if not any(search_text in str(v).lower() for v in values):
                        continue
                elif filter_type == "category":
                    if search_text not in ip_data["category"].lower():
                        continue
                elif filter_type == "severity":
                    if search_text not in ip_data["severity"].lower():
                        continue
            
            self.tree.insert("", tk.END, values=values)
            
        # Update status bar
        count = len(self.tree.get_children())
        self.status_bar.config(text=f"Showing {count} IPs") 