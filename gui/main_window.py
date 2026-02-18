"""
Main Window Module (Tkinter Version)
====================================
Main application window for the GUI-based firewall using Tkinter.

This module brings together all components and provides:
- Main application layout
- Integration of packet sniffer with GUI
- Real-time updates using tkinter's after() method
- Threading coordination

Author: Network Security Project
Date: February 2026
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, List
import threading
import queue

from utils.constants import (
    COLORS, WINDOW_TITLE, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT,
    FONT_FAMILY, FONT_SIZE_HEADER, LOG_UPDATE_INTERVAL,
    STATS_UPDATE_INTERVAL, APP_NAME, APP_VERSION
)
from utils.logger import PacketLogger, PacketRecord
from core.rule_engine import RuleEngine
from core.sniffer import PacketSniffer, check_privileges, get_default_interface

from .components import (
    DarkTheme, StyledFrame, StyledLabel, StyledButton, StyledEntry,
    PacketLogPanel, RulesTable, StatisticsPanel, StatusBar,
    RuleInputPanel, QuickBlockPanel, ProtocolFilterPanel
)


class MainWindow:
    """
    Main application window for the firewall GUI.
    
    Uses Tkinter for cross-platform compatibility.
    Implements threading for non-blocking packet capture.
    """
    
    def __init__(self, root: tk.Tk):
        """Initialize the main window and all components."""
        self._root = root
        
        # Check for admin privileges
        if not check_privileges():
            messagebox.showwarning(
                "Administrator Required",
                "This application requires Administrator privileges "
                "for packet capture.\n\n"
                "Please run as Administrator."
            )
        
        # Initialize core components
        self._rule_engine = RuleEngine()
        self._packet_logger = PacketLogger()
        
        # Packet queue for thread-safe communication
        self._packet_queue: queue.Queue = queue.Queue()
        
        # Initialize sniffer with callback
        self._sniffer = PacketSniffer(
            rule_engine=self._rule_engine,
            packet_logger=self._packet_logger,
            packet_callback=self._queue_packet
        )
        
        # Set up the UI
        self._setup_window()
        self._create_widgets()
        self._setup_layout()
        
        # Load initial state
        self._refresh_rules_table()
        self._update_interface_list()
        self._protocol_panel.set_states(self._rule_engine.get_protocol_filters())
        
        # Start update loops
        self._schedule_updates()
    
    def _setup_window(self) -> None:
        """Configure main window properties."""
        self._root.title(WINDOW_TITLE)
        self._root.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self._root.geometry(f"{WINDOW_MIN_WIDTH}x{WINDOW_MIN_HEIGHT}")
        
        # Apply dark theme
        DarkTheme.apply_to_root(self._root)
        
        # Handle close
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _create_widgets(self) -> None:
        """Create all UI widgets."""
        # Main container
        self._main_frame = StyledFrame(self._root)
        self._main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # Header
        header_frame = StyledFrame(self._main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        StyledLabel(header_frame, text=f"🛡️ {APP_NAME}", style="header").pack(side=tk.LEFT)
        StyledLabel(header_frame, text=f"v{APP_VERSION}", style="muted").pack(side=tk.LEFT, padx=10)
        
        # Interface selector
        interface_frame = StyledFrame(header_frame)
        interface_frame.pack(side=tk.RIGHT)
        
        StyledLabel(interface_frame, text="Interface:", style="secondary").pack(side=tk.LEFT)
        self._interface_var = tk.StringVar()
        self._interface_combo = ttk.Combobox(
            interface_frame,
            textvariable=self._interface_var,
            state="readonly",
            width=25
        )
        self._interface_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        # Control buttons
        control_frame = StyledFrame(self._main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self._start_button = StyledButton(
            control_frame, text="▶ Start Firewall",
            command=self._on_start_clicked, style="success"
        )
        self._start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self._stop_button = StyledButton(
            control_frame, text="⏹ Stop Firewall",
            command=self._on_stop_clicked, style="danger"
        )
        self._stop_button.pack(side=tk.LEFT, padx=(0, 5))
        self._stop_button.configure(state=tk.DISABLED)
        
        StyledButton(
            control_frame, text="🗑 Clear Logs",
            command=self._on_clear_clicked, style="secondary"
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        StyledButton(
            control_frame, text="💾 Export Logs",
            command=self._on_export_clicked, style="secondary"
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Protocol filters (in control row)
        self._protocol_panel = ProtocolFilterPanel(
            control_frame,
            on_toggle=self._on_protocol_toggled
        )
        self._protocol_panel.pack(side=tk.RIGHT)
        
        # Main content area with PanedWindow
        paned = tk.PanedWindow(
            self._main_frame,
            orient=tk.HORIZONTAL,
            bg=COLORS["bg_primary"],
            sashwidth=5,
            sashrelief=tk.FLAT
        )
        paned.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left panel: Packet log
        left_frame = StyledFrame(paned)
        
        StyledLabel(left_frame, text="📡 Live Packet Feed", style="header").pack(anchor=tk.W, pady=(0, 5))
        self._log_panel = PacketLogPanel(left_frame)
        self._log_panel.pack(fill=tk.BOTH, expand=True)
        
        # Quick block panel
        self._quick_block = QuickBlockPanel(
            left_frame,
            on_block_ip=self._on_quick_block_ip,
            on_block_port=self._on_quick_block_port
        )
        self._quick_block.pack(fill=tk.X, pady=(10, 0))
        
        paned.add(left_frame, width=700)
        
        # Right panel: Stats and rules
        right_frame = StyledFrame(paned)
        
        self._stats_panel = StatisticsPanel(right_frame)
        self._stats_panel.pack(fill=tk.X, pady=(0, 10))
        
        # Notebook for rules
        notebook = ttk.Notebook(right_frame, style="Dark.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Rules table tab
        rules_frame = StyledFrame(notebook, bg=COLORS["bg_secondary"])
        self._rules_table = RulesTable(rules_frame)
        self._rules_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        notebook.add(rules_frame, text="📋 Active Rules")
        
        # Add rule tab
        self._rule_input = RuleInputPanel(
            notebook,
            on_add_callback=self._on_rule_added
        )
        notebook.add(self._rule_input, text="➕ Add Rule")
        
        # Delete rule button
        StyledButton(
            right_frame, text="🗑 Delete Selected Rule",
            command=self._on_delete_rule, style="danger"
        ).pack(pady=10)
        
        paned.add(right_frame, width=400)
        
        # Status bar
        self._status_bar = StatusBar(self._main_frame)
        self._status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    def _setup_layout(self) -> None:
        """Additional layout configuration."""
        pass  # Layout is done in _create_widgets
    
    def _update_interface_list(self) -> None:
        """Populate interface dropdown with available interfaces."""
        interfaces = ["All Interfaces"] + self._sniffer.get_interfaces()
        self._interface_combo["values"] = interfaces
        
        if interfaces:
            default = get_default_interface()
            if default and default in interfaces:
                self._interface_combo.set(default)
            else:
                self._interface_combo.set(interfaces[0])
    
    def _queue_packet(self, record: PacketRecord) -> None:
        """
        Callback for sniffer - queues packet for GUI update.
        Called from sniffer thread, uses thread-safe queue.
        """
        self._packet_queue.put(record)
    
    def _schedule_updates(self) -> None:
        """Schedule periodic UI updates."""
        self._process_packet_queue()
        self._update_statistics()
    
    def _process_packet_queue(self) -> None:
        """Process queued packets and update log panel."""
        try:
            # Process up to 50 packets per cycle to avoid blocking
            for _ in range(50):
                try:
                    record = self._packet_queue.get_nowait()
                    self._log_panel.append_packet(
                        record.to_display_string(),
                        record.status
                    )
                except queue.Empty:
                    break
            
            # Update packet count
            stats = self._packet_logger.get_statistics()
            self._status_bar.set_packet_count(stats["total_packets"])
            
        except Exception as e:
            print(f"Error processing packets: {e}")
        
        # Schedule next update
        self._root.after(LOG_UPDATE_INTERVAL, self._process_packet_queue)
    
    def _update_statistics(self) -> None:
        """Update statistics panel."""
        try:
            stats = self._packet_logger.get_statistics()
            pps = self._packet_logger.get_recent_count(1.0)
            self._stats_panel.update_statistics(stats, pps)
        except Exception as e:
            print(f"Error updating stats: {e}")
        
        # Schedule next update
        self._root.after(STATS_UPDATE_INTERVAL, self._update_statistics)
    
    def _refresh_rules_table(self) -> None:
        """Refresh the rules table with current rules."""
        rules = self._rule_engine.get_rules()
        self._rules_table.refresh_rules(rules)
    
    # =========================================================================
    # Event Handlers
    # =========================================================================
    
    def _on_start_clicked(self) -> None:
        """Handle Start button click."""
        interface = self._interface_var.get()
        if interface == "All Interfaces":
            interface = None
        
        self._sniffer.set_interface(interface)
        
        if self._sniffer.start():
            self._start_button.configure(state=tk.DISABLED)
            self._stop_button.configure(state=tk.NORMAL)
            self._status_bar.set_running(True)
            self._status_bar.set_interface(interface or "All")
            
            self._log_panel.append_packet(
                ">>> Firewall started - monitoring network traffic",
                "ALLOWED"
            )
        else:
            messagebox.showerror(
                "Start Failed",
                "Failed to start packet capture.\n"
                "Make sure you have administrator privileges."
            )
    
    def _on_stop_clicked(self) -> None:
        """Handle Stop button click."""
        self._sniffer.stop()
        
        self._start_button.configure(state=tk.NORMAL)
        self._stop_button.configure(state=tk.DISABLED)
        self._status_bar.set_running(False)
        
        self._log_panel.append_packet(
            ">>> Firewall stopped",
            "BLOCKED"
        )
    
    def _on_clear_clicked(self) -> None:
        """Handle Clear Logs button click."""
        self._log_panel.clear()
        self._packet_logger.clear()
        self._status_bar.set_packet_count(0)
    
    def _on_export_clicked(self) -> None:
        """Handle Export Logs button click."""
        try:
            filepath = self._packet_logger.export_to_csv()
            messagebox.showinfo("Export Successful", f"Logs exported to:\n{filepath}")
        except IOError as e:
            messagebox.showerror("Export Failed", f"Failed to export logs:\n{e}")
    
    def _on_rule_added(
        self,
        rule_type: str,
        value: str,
        action: str,
        direction: str,
        description: str
    ) -> None:
        """Handle new rule added from input panel."""
        try:
            self._rule_engine.add_rule(
                rule_type=rule_type,
                value=value,
                action=action,
                direction=direction,
                description=description
            )
            self._refresh_rules_table()
            messagebox.showinfo(
                "Rule Added",
                f"Successfully added {action} rule for {rule_type}: {value}"
            )
        except ValueError as e:
            messagebox.showwarning("Invalid Rule", str(e))
    
    def _on_delete_rule(self) -> None:
        """Handle delete rule button click."""
        rule_id = self._rules_table.get_selected_rule_id()
        if rule_id < 0:
            messagebox.showwarning("No Selection", "Please select a rule to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete rule {rule_id}?"):
            self._rule_engine.remove_rule(rule_id)
            self._refresh_rules_table()
    
    def _on_quick_block_ip(self, ip: str) -> None:
        """Handle quick block IP action."""
        self._rule_engine.add_blocked_ip(ip)
        self._refresh_rules_table()
        self._log_panel.append_packet(f">>> Rule added: Block IP {ip}", "BLOCKED")
    
    def _on_quick_block_port(self, port: int) -> None:
        """Handle quick block port action."""
        self._rule_engine.add_blocked_port(port)
        self._refresh_rules_table()
        self._log_panel.append_packet(f">>> Rule added: Block Port {port}", "BLOCKED")
    
    def _on_protocol_toggled(self, protocol: str, enabled: bool) -> None:
        """Handle protocol filter toggle."""
        self._rule_engine.set_protocol_filter(protocol, enabled)
        status = "enabled" if enabled else "disabled"
        self._log_panel.append_packet(
            f">>> Protocol filter: {protocol} {status}",
            "ALLOWED" if enabled else "BLOCKED"
        )
    
    def _on_close(self) -> None:
        """Handle window close event."""
        if self._sniffer.is_running():
            self._sniffer.stop()
        self._root.destroy()


def run_application() -> int:
    """
    Main entry point for the GUI application.
    
    Returns:
        Application exit code
    """
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()
    return 0
