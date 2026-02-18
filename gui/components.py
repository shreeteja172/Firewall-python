"""
GUI Components Module (Tkinter Version)
========================================
Reusable Tkinter widgets and components for the firewall application.

This module provides custom-styled widgets that maintain a consistent
dark theme throughout the application.

TKINTER ARCHITECTURE:
=====================
Tkinter is Python's standard GUI library, bundled with Python.

Key concepts:
- Widgets: Visual elements (Button, Label, Listbox)
- Geometry Managers: Pack, Grid, Place for layout
- Event Binding: Connect functions to user actions
- ttk: Themed widgets for modern appearance

Author: Network Security Project
Date: February 2026
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Optional, Dict, List

from utils.constants import (
    COLORS, FONT_FAMILY, FONT_SIZE_NORMAL, FONT_SIZE_LARGE,
    FONT_SIZE_HEADER, MAX_LOG_ENTRIES
)


class DarkTheme:
    """Dark theme color scheme and styling utilities."""
    
    @staticmethod
    def apply_to_root(root: tk.Tk) -> None:
        """Apply dark theme to the root window."""
        root.configure(bg=COLORS["bg_primary"])
        
        # Configure ttk styles
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass  # Use default if clam not available
        
        # Configure common styles
        style.configure("Dark.TFrame", background=COLORS["bg_primary"])
        style.configure(
            "Dark.TLabel",
            background=COLORS["bg_primary"],
            foreground=COLORS["text_primary"],
            font=(FONT_FAMILY, FONT_SIZE_NORMAL)
        )
        style.configure(
            "Dark.TCombobox",
            fieldbackground=COLORS["bg_tertiary"],
            background=COLORS["bg_tertiary"],
            foreground=COLORS["text_primary"]
        )
        style.configure(
            "Dark.Treeview",
            background=COLORS["bg_secondary"],
            foreground=COLORS["text_primary"],
            fieldbackground=COLORS["bg_secondary"],
            font=(FONT_FAMILY, FONT_SIZE_NORMAL)
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=COLORS["bg_primary"],
            foreground=COLORS["accent_cyan"],
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold")
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", COLORS["button_primary"])]
        )
        style.configure(
            "Dark.TNotebook",
            background=COLORS["bg_primary"]
        )
        style.configure(
            "Dark.TNotebook.Tab",
            background=COLORS["bg_tertiary"],
            foreground=COLORS["text_secondary"],
            padding=(15, 8),
            font=(FONT_FAMILY, FONT_SIZE_NORMAL)
        )
        style.map(
            "Dark.TNotebook.Tab",
            background=[("selected", COLORS["button_primary"])],
            foreground=[("selected", COLORS["text_primary"])]
        )


class StyledFrame(tk.Frame):
    """Custom styled frame with dark theme."""
    
    def __init__(self, parent, **kwargs):
        bg = kwargs.pop("bg", COLORS["bg_primary"])
        super().__init__(parent, bg=bg, **kwargs)


class StyledLabelFrame(tk.LabelFrame):
    """Custom styled label frame with dark theme."""
    
    def __init__(self, parent, text: str = "", **kwargs):
        super().__init__(
            parent,
            text=text,
            bg=COLORS["bg_secondary"],
            fg=COLORS["accent_cyan"],
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            **kwargs
        )


class StyledLabel(tk.Label):
    """Custom styled label with dark theme."""
    
    def __init__(self, parent, text: str = "", style: str = "normal", **kwargs):
        styles = {
            "normal": {"fg": COLORS["text_primary"], "font": (FONT_FAMILY, FONT_SIZE_NORMAL)},
            "header": {"fg": COLORS["accent_cyan"], "font": (FONT_FAMILY, FONT_SIZE_HEADER, "bold")},
            "secondary": {"fg": COLORS["text_secondary"], "font": (FONT_FAMILY, FONT_SIZE_NORMAL)},
            "muted": {"fg": COLORS["text_muted"], "font": (FONT_FAMILY, FONT_SIZE_NORMAL)}
        }
        
        style_config = styles.get(style, styles["normal"])
        super().__init__(
            parent,
            text=text,
            bg=kwargs.pop("bg", COLORS["bg_primary"]),
            fg=style_config["fg"],
            font=style_config["font"],
            **kwargs
        )


class StyledButton(tk.Button):
    """Custom styled button with dark theme."""
    
    def __init__(self, parent, text: str, command: Callable = None, style: str = "primary", **kwargs):
        styles = {
            "primary": (COLORS["button_primary"], COLORS["button_hover"]),
            "success": (COLORS["button_success"], "#16a34a"),
            "danger": (COLORS["button_danger"], "#dc2626"),
            "secondary": (COLORS["bg_tertiary"], COLORS["border"]),
        }
        
        bg_color, hover_color = styles.get(style, styles["primary"])
        
        super().__init__(
            parent,
            text=text,
            command=command,
            bg=bg_color,
            fg=COLORS["text_primary"],
            activebackground=hover_color,
            activeforeground=COLORS["text_primary"],
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=15,
            pady=8,
            **kwargs
        )
        
        self._bg_color = bg_color
        self._hover_color = hover_color
        
        self.bind("<Enter>", lambda e: self.configure(bg=self._hover_color))
        self.bind("<Leave>", lambda e: self.configure(bg=self._bg_color))


class StyledEntry(tk.Entry):
    """Custom styled entry (text input) with dark theme."""
    
    def __init__(self, parent, placeholder: str = "", **kwargs):
        super().__init__(
            parent,
            bg=COLORS["bg_tertiary"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            relief=tk.FLAT,
            **kwargs
        )
        
        self._placeholder = placeholder
        self._placeholder_color = COLORS["text_muted"]
        self._normal_color = COLORS["text_primary"]
        
        if placeholder:
            self._show_placeholder()
            self.bind("<FocusIn>", self._on_focus_in)
            self.bind("<FocusOut>", self._on_focus_out)
    
    def _show_placeholder(self):
        self.delete(0, tk.END)
        self.insert(0, self._placeholder)
        self.configure(fg=self._placeholder_color)
    
    def _on_focus_in(self, event):
        if self.get() == self._placeholder:
            self.delete(0, tk.END)
            self.configure(fg=self._normal_color)
    
    def _on_focus_out(self, event):
        if not self.get():
            self._show_placeholder()
    
    def get_value(self) -> str:
        """Get value, returning empty string if placeholder is shown."""
        value = self.get()
        return "" if value == self._placeholder else value


class PacketLogPanel(tk.Frame):
    """
    Scrollable log panel for displaying captured packets.
    
    Features:
    - Auto-scroll to newest entries
    - Color-coded entries (green=allowed, red=blocked)
    - Maximum line limit to prevent memory issues
    """
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_primary"], **kwargs)
        
        self._max_lines = MAX_LOG_ENTRIES
        self._line_count = 0
        
        # Create text widget with scrollbar
        self._text = tk.Text(
            self,
            bg=COLORS["bg_primary"],
            fg=COLORS["text_primary"],
            font=("Consolas", FONT_SIZE_NORMAL),
            wrap=tk.WORD,
            state=tk.DISABLED,
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        
        scrollbar = tk.Scrollbar(self, command=self._text.yview, bg=COLORS["bg_secondary"])
        self._text.configure(yscrollcommand=scrollbar.set)
        
        # Configure tags for colors
        self._text.tag_configure("allowed", foreground=COLORS["allowed"])
        self._text.tag_configure("blocked", foreground=COLORS["blocked"])
        self._text.tag_configure("info", foreground=COLORS["info"])
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    def append_packet(self, text: str, status: str) -> None:
        """Append a packet log entry with color coding."""
        tag = "blocked" if status == "BLOCKED" else "allowed"
        
        self._text.configure(state=tk.NORMAL)
        self._text.insert(tk.END, text + "\n", tag)
        self._text.configure(state=tk.DISABLED)
        
        self._line_count += 1
        
        if self._line_count > self._max_lines:
            self._text.configure(state=tk.NORMAL)
            self._text.delete("1.0", f"{100}.0")
            self._text.configure(state=tk.DISABLED)
            self._line_count -= 100
        
        self._text.see(tk.END)
    
    def clear(self) -> None:
        """Clear all log entries."""
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.configure(state=tk.DISABLED)
        self._line_count = 0


class RulesTable(tk.Frame):
    """Table widget for displaying and managing firewall rules using Treeview."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_secondary"], **kwargs)
        
        columns = ("id", "type", "value", "action", "direction", "description", "enabled")
        
        self._tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            style="Dark.Treeview",
            selectmode="browse"
        )
        
        col_config = {
            "id": ("ID", 50),
            "type": ("Type", 80),
            "value": ("Value", 150),
            "action": ("Action", 80),
            "direction": ("Direction", 80),
            "description": ("Description", 200),
            "enabled": ("Enabled", 70)
        }
        
        for col, (heading, width) in col_config.items():
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=width, minwidth=50)
        
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self._tree.tag_configure("blocked", foreground=COLORS["blocked"])
        self._tree.tag_configure("allowed", foreground=COLORS["allowed"])
    
    def add_rule(self, rule) -> None:
        """Add a rule to the table."""
        tag = "blocked" if rule.action == "BLOCK" else "allowed"
        enabled_text = "Yes" if rule.enabled else "No"
        
        self._tree.insert("", tk.END, values=(
            rule.rule_id, rule.rule_type, rule.value, rule.action,
            rule.direction, rule.description, enabled_text
        ), tags=(tag,))
    
    def refresh_rules(self, rules: list) -> None:
        """Refresh table with new rule list."""
        for item in self._tree.get_children():
            self._tree.delete(item)
        for rule in rules:
            self.add_rule(rule)
    
    def get_selected_rule_id(self) -> int:
        """Get the ID of the currently selected rule."""
        selection = self._tree.selection()
        if selection:
            item = self._tree.item(selection[0])
            return int(item["values"][0])
        return -1


class StatisticsPanel(tk.Frame):
    """Panel displaying real-time traffic statistics."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_secondary"], **kwargs)
        
        title = StyledLabel(self, text="📊 Traffic Statistics", style="header", bg=COLORS["bg_secondary"])
        title.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self._stats_labels: Dict[str, tk.Label] = {}
        stats_items = [
            ("total", "Total Packets:", COLORS["text_primary"]),
            ("allowed", "Allowed:", COLORS["allowed"]),
            ("blocked", "Blocked:", COLORS["blocked"]),
            ("block_rate", "Block Rate:", COLORS["text_primary"]),
            ("pps", "Packets/sec:", COLORS["text_primary"]),
            ("tcp", "TCP:", COLORS["text_primary"]),
            ("udp", "UDP:", COLORS["text_primary"]),
            ("icmp", "ICMP:", COLORS["text_primary"]),
        ]
        
        for key, label_text, value_color in stats_items:
            row = tk.Frame(self, bg=COLORS["bg_secondary"])
            row.pack(fill=tk.X, padx=10, pady=2)
            
            tk.Label(row, text=label_text, bg=COLORS["bg_secondary"],
                    fg=COLORS["text_secondary"], font=(FONT_FAMILY, FONT_SIZE_NORMAL),
                    anchor=tk.W).pack(side=tk.LEFT)
            
            value = tk.Label(row, text="0", bg=COLORS["bg_secondary"],
                           fg=value_color, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
                           anchor=tk.E)
            value.pack(side=tk.RIGHT)
            self._stats_labels[key] = value
    
    def update_statistics(self, stats: dict, pps: float = 0.0) -> None:
        """Update displayed statistics."""
        self._stats_labels["total"].configure(text=str(stats.get("total_packets", 0)))
        self._stats_labels["allowed"].configure(text=str(stats.get("allowed_packets", 0)))
        self._stats_labels["blocked"].configure(text=str(stats.get("blocked_packets", 0)))
        self._stats_labels["block_rate"].configure(text=f"{stats.get('block_rate', 0):.1f}%")
        self._stats_labels["pps"].configure(text=f"{pps:.1f}")
        
        protocol_counts = stats.get("protocol_counts", {})
        self._stats_labels["tcp"].configure(text=str(protocol_counts.get("TCP", 0)))
        self._stats_labels["udp"].configure(text=str(protocol_counts.get("UDP", 0)))
        self._stats_labels["icmp"].configure(text=str(protocol_counts.get("ICMP", 0)))


class StatusBar(tk.Frame):
    """Status bar showing firewall state and system information."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_primary"], height=40, **kwargs)
        self.pack_propagate(False)
        
        self._status_label = tk.Label(self, text="🔴 Firewall Stopped",
                                      bg=COLORS["bg_primary"], fg=COLORS["blocked"],
                                      font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"))
        self._status_label.pack(side=tk.LEFT, padx=15)
        
        self._packet_label = tk.Label(self, text="Packets: 0",
                                      bg=COLORS["bg_primary"], fg=COLORS["text_secondary"],
                                      font=(FONT_FAMILY, FONT_SIZE_NORMAL))
        self._packet_label.pack(side=tk.RIGHT, padx=15)
        
        self._interface_label = tk.Label(self, text="Interface: None",
                                         bg=COLORS["bg_primary"], fg=COLORS["text_secondary"],
                                         font=(FONT_FAMILY, FONT_SIZE_NORMAL))
        self._interface_label.pack(side=tk.RIGHT, padx=15)
    
    def set_running(self, running: bool) -> None:
        if running:
            self._status_label.configure(text="🟢 Firewall Running", fg=COLORS["allowed"])
        else:
            self._status_label.configure(text="🔴 Firewall Stopped", fg=COLORS["blocked"])
    
    def set_interface(self, interface: str) -> None:
        self._interface_label.configure(text=f"Interface: {interface or 'All'}")
    
    def set_packet_count(self, count: int) -> None:
        self._packet_label.configure(text=f"Packets: {count:,}")


class RuleInputPanel(tk.Frame):
    """Panel for adding new firewall rules."""
    
    def __init__(self, parent, on_add_callback: Callable = None, **kwargs):
        super().__init__(parent, bg=COLORS["bg_secondary"], **kwargs)
        
        self._on_add = on_add_callback
        
        title = StyledLabel(self, text="➕ Add New Rule", style="header", bg=COLORS["bg_secondary"])
        title.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # Type selection
        type_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(type_frame, text="Type:", bg=COLORS["bg_secondary"],
                fg=COLORS["text_secondary"], font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(side=tk.LEFT)
        self._type_var = tk.StringVar(value="IP")
        ttk.Combobox(type_frame, textvariable=self._type_var,
                    values=["IP", "PORT", "PROTOCOL"], state="readonly", width=15).pack(side=tk.LEFT, padx=(10, 0))
        
        # Value input
        value_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        value_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(value_frame, text="Value:", bg=COLORS["bg_secondary"],
                fg=COLORS["text_secondary"], font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(side=tk.LEFT)
        self._value_entry = StyledEntry(value_frame, placeholder="Enter IP, port, or protocol")
        self._value_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Action selection
        action_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(action_frame, text="Action:", bg=COLORS["bg_secondary"],
                fg=COLORS["text_secondary"], font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(side=tk.LEFT)
        self._action_var = tk.StringVar(value="BLOCK")
        ttk.Combobox(action_frame, textvariable=self._action_var,
                    values=["BLOCK", "ALLOW"], state="readonly", width=15).pack(side=tk.LEFT, padx=(10, 0))
        
        # Direction selection
        dir_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        dir_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(dir_frame, text="Direction:", bg=COLORS["bg_secondary"],
                fg=COLORS["text_secondary"], font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(side=tk.LEFT)
        self._dir_var = tk.StringVar(value="both")
        ttk.Combobox(dir_frame, textvariable=self._dir_var,
                    values=["both", "src", "dst"], state="readonly", width=15).pack(side=tk.LEFT, padx=(10, 0))
        
        # Description input
        desc_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        desc_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(desc_frame, text="Description:", bg=COLORS["bg_secondary"],
                fg=COLORS["text_secondary"], font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(side=tk.LEFT)
        self._desc_entry = StyledEntry(desc_frame, placeholder="Optional description")
        self._desc_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        StyledButton(self, text="Add Rule", command=self._on_add_clicked, style="success").pack(pady=10)
    
    def _on_add_clicked(self) -> None:
        value = self._value_entry.get_value()
        if not value:
            messagebox.showwarning("Invalid Input", "Please enter a value for the rule.")
            return
        if self._on_add:
            self._on_add(self._type_var.get(), value, self._action_var.get(),
                        self._dir_var.get(), self._desc_entry.get_value())
        self._value_entry.delete(0, tk.END)
        self._desc_entry.delete(0, tk.END)


class QuickBlockPanel(tk.Frame):
    """Quick action panel for commonly used blocking actions."""
    
    def __init__(self, parent, on_block_ip: Callable = None, on_block_port: Callable = None, **kwargs):
        super().__init__(parent, bg=COLORS["bg_secondary"], **kwargs)
        
        self._on_block_ip = on_block_ip
        self._on_block_port = on_block_port
        
        title = StyledLabel(self, text="⚡ Quick Block", style="header", bg=COLORS["bg_secondary"])
        title.configure(fg=COLORS["accent_orange"])
        title.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # Block IP
        ip_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        self._ip_entry = StyledEntry(ip_frame, placeholder="IP Address")
        self._ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        StyledButton(ip_frame, text="Block IP", command=self._do_block_ip, style="danger").pack(side=tk.RIGHT, padx=(10, 0))
        
        # Block Port
        port_frame = tk.Frame(self, bg=COLORS["bg_secondary"])
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        self._port_entry = StyledEntry(port_frame, placeholder="Port Number")
        self._port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        StyledButton(port_frame, text="Block Port", command=self._do_block_port, style="danger").pack(side=tk.RIGHT, padx=(10, 0))
    
    def _do_block_ip(self) -> None:
        ip = self._ip_entry.get_value()
        if ip and self._on_block_ip:
            self._on_block_ip(ip)
            self._ip_entry.delete(0, tk.END)
    
    def _do_block_port(self) -> None:
        try:
            port = int(self._port_entry.get_value())
            if 0 <= port <= 65535 and self._on_block_port:
                self._on_block_port(port)
                self._port_entry.delete(0, tk.END)
            else:
                messagebox.showwarning("Invalid Port", "Port must be between 0 and 65535.")
        except ValueError:
            messagebox.showwarning("Invalid Port", "Please enter a valid port number.")


class ProtocolFilterPanel(tk.Frame):
    """Panel for quick protocol enable/disable toggles."""
    
    def __init__(self, parent, on_toggle: Callable = None, **kwargs):
        super().__init__(parent, bg=COLORS["bg_secondary"], **kwargs)
        
        self._on_toggle = on_toggle
        
        title = StyledLabel(self, text="🔧 Protocol Filters", style="header", bg=COLORS["bg_secondary"])
        title.configure(fg=COLORS["accent_purple"])
        title.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self._tcp_var = tk.BooleanVar(value=True)
        self._udp_var = tk.BooleanVar(value=True)
        self._icmp_var = tk.BooleanVar(value=True)
        
        for text, var, proto in [("Allow TCP", self._tcp_var, "TCP"),
                                  ("Allow UDP", self._udp_var, "UDP"),
                                  ("Allow ICMP", self._icmp_var, "ICMP")]:
            tk.Checkbutton(self, text=text, variable=var,
                          command=lambda p=proto, v=var: self._toggle(p, v.get()),
                          bg=COLORS["bg_secondary"], fg=COLORS["text_primary"],
                          selectcolor=COLORS["bg_tertiary"], activebackground=COLORS["bg_secondary"],
                          font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(anchor=tk.W, padx=10, pady=2)
    
    def _toggle(self, protocol: str, enabled: bool) -> None:
        if self._on_toggle:
            self._on_toggle(protocol, enabled)
    
    def set_states(self, filters: dict) -> None:
        self._tcp_var.set(filters.get("TCP", True))
        self._udp_var.set(filters.get("UDP", True))
        self._icmp_var.set(filters.get("ICMP", True))
