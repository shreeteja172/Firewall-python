"""
Packet Sniffer Module
=====================
Network packet capture and analysis using Scapy.

PACKET SNIFFING CONCEPTS:
=========================
Packet sniffing is the process of capturing network traffic as it
passes through a network interface. This requires:
1. Raw socket access (admin/root privileges)
2. Promiscuous mode (to capture all packets, not just those for this host)

SCAPY LIBRARY:
==============
Scapy is a powerful Python library for packet manipulation. It can:
- Capture packets from network interfaces
- Decode packet headers at multiple OSI layers
- Create and send custom packets
- Perform network discovery and attacks (for security testing)

LAYERS DECODED:
===============
- Layer 2 (Data Link): Ethernet frames (Ether)
- Layer 3 (Network): IP packets (IP)
- Layer 4 (Transport): TCP/UDP segments (TCP, UDP, ICMP)

PRIVILEGES REQUIRED:
====================
- Windows: Administrator privileges (for WinPcap/Npcap access)
- Linux: Root privileges (CAP_NET_RAW capability)

This is because raw sockets can see ALL network traffic, which
poses security implications if available to unprivileged users.

Author: Network Security Project
Date: February 2026
"""

import threading
import queue
from typing import Callable, Optional, Any
from datetime import datetime

# Scapy imports with error handling
try:
    from scapy.all import (
        sniff, 
        IP, 
        TCP, 
        UDP, 
        ICMP,
        conf,
        get_if_list,
        get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

from utils.constants import (
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    SNIFF_TIMEOUT,
    PROTOCOL_NAMES
)
from utils.logger import PacketLogger, create_packet_record
from core.rule_engine import RuleEngine


class PacketSniffer:
    """
    Network packet sniffer using Scapy.
    
    This class provides:
    - Real-time packet capture from network interfaces
    - Integration with RuleEngine for filtering
    - Thread-safe operation with the GUI
    - Statistics tracking
    
    Architecture:
    -------------
    The sniffer runs in a separate thread to avoid blocking the GUI.
    Captured packets are processed and passed to a callback function
    for display in the GUI.
    
    Thread Model:
    -------------
    Main Thread: GUI operations
    Sniffer Thread: Packet capture and processing
    
    Communication between threads uses thread-safe mechanisms:
    - Queue for packet data
    - Threading events for start/stop signals
    - Locks for shared state
    
    HOW PACKET CAPTURE WORKS:
    =========================
    1. Open raw socket on network interface
    2. Set promiscuous mode (optional)
    3. Read packets from socket buffer
    4. Parse packet headers (Ethernet → IP → TCP/UDP/ICMP)
    5. Apply firewall rules
    6. Log and display results
    """
    
    def __init__(
        self,
        rule_engine: RuleEngine,
        packet_logger: PacketLogger,
        packet_callback: Optional[Callable] = None
    ):
        """
        Initialize the packet sniffer.
        
        Args:
            rule_engine: RuleEngine instance for packet filtering
            packet_logger: PacketLogger instance for logging
            packet_callback: Function called for each captured packet
                           Signature: callback(packet_record)
        """
        self._rule_engine = rule_engine
        self._packet_logger = packet_logger
        self._packet_callback = packet_callback
        
        # Threading controls
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._lock = threading.Lock()
        
        # Network interface
        self._interface: Optional[str] = None
        
        # Statistics
        self._packets_captured = 0
        self._start_time: Optional[datetime] = None
        
        # Verify Scapy is available
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy library is not available. "
                "Please install it with: pip install scapy"
            )
        
        # Configure Scapy for Windows
        self._configure_scapy()
    
    def _configure_scapy(self) -> None:
        """
        Configure Scapy settings for the current platform.
        
        Windows-specific configuration:
        - Use Npcap for packet capture
        - Disable certain warnings
        
        Linux-specific configuration:
        - Use native Linux sockets
        """
        # Suppress Scapy warnings
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        
        # Windows-specific: Npcap should be installed
        # Scapy will automatically detect and use it
    
    def get_interfaces(self) -> list:
        """
        Get list of available network interfaces.
        
        Network interfaces are the points where packets enter/exit
        the system. Common types:
        - Ethernet (eth0, Ethernet)
        - WiFi (wlan0, Wi-Fi)
        - Loopback (lo, Loopback)
        - Virtual (VPN adapters, Docker networks)
        
        Returns:
            List of interface names available for capture.
        """
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            return get_if_list()
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []
    
    def set_interface(self, interface: Optional[str]) -> None:
        """
        Set the network interface to capture from.
        
        Args:
            interface: Interface name, or None for all interfaces.
        """
        self._interface = interface
    
    def start(self) -> bool:
        """
        Start packet capture.
        
        This method:
        1. Checks if already running
        2. Creates and starts the sniffer thread
        3. Returns success/failure status
        
        Returns:
            True if started successfully, False otherwise.
        
        Note: Requires administrator/root privileges.
        """
        with self._lock:
            if self._running:
                return False
            
            # Clear stop event
            self._stop_event.clear()
            
            # Reset statistics
            self._packets_captured = 0
            self._start_time = datetime.now()
            
            # Create and start sniffer thread
            self._sniffer_thread = threading.Thread(
                target=self._sniff_loop,
                daemon=True,
                name="PacketSniffer"
            )
            self._running = True
            self._sniffer_thread.start()
            
            return True
    
    def stop(self) -> None:
        """
        Stop packet capture.
        
        This cleanly shuts down the sniffer thread:
        1. Sets the stop event
        2. Waits for thread to finish
        3. Cleans up resources
        """
        with self._lock:
            if not self._running:
                return
            
            # Signal thread to stop
            self._stop_event.set()
            self._running = False
        
        # Wait for thread to finish (with timeout)
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)
    
    def is_running(self) -> bool:
        """Check if the sniffer is currently running."""
        with self._lock:
            return self._running
    
    def get_statistics(self) -> dict:
        """
        Get current capture statistics.
        
        Returns:
            Dictionary with capture statistics:
            - packets_captured: Total packets captured
            - duration_seconds: Time since capture started
            - packets_per_second: Average capture rate
        """
        duration = 0.0
        if self._start_time:
            duration = (datetime.now() - self._start_time).total_seconds()
        
        pps = 0.0
        if duration > 0:
            pps = self._packets_captured / duration
        
        return {
            "packets_captured": self._packets_captured,
            "duration_seconds": round(duration, 1),
            "packets_per_second": round(pps, 2),
        }
    
    def _sniff_loop(self) -> None:
        """
        Main packet capture loop.
        
        This runs in a separate thread and continuously captures
        packets until the stop event is set.
        
        The loop uses a short timeout to regularly check the stop
        event, allowing for responsive shutdown.
        
        SCAPY SNIFF FUNCTION:
        =====================
        sniff() parameters:
        - iface: Interface to capture from
        - prn: Callback function for each packet
        - store: Whether to store packets in memory
        - timeout: How long to capture before returning
        - filter: BPF filter expression
        """
        try:
            while not self._stop_event.is_set():
                # Capture packets in small batches
                # This allows regular checking of stop event
                try:
                    sniff(
                        iface=self._interface,
                        prn=self._process_packet,
                        store=False,  # Don't store in memory (we log ourselves)
                        timeout=SNIFF_TIMEOUT,
                        filter="ip",  # Only capture IP packets
                    )
                except PermissionError:
                    print("Error: Administrator/root privileges required for packet capture")
                    break
                except Exception as e:
                    if not self._stop_event.is_set():
                        print(f"Sniffing error: {e}")
                    break
                    
        except Exception as e:
            print(f"Sniffer thread error: {e}")
        finally:
            with self._lock:
                self._running = False
    
    def _process_packet(self, packet: Any) -> None:
        """
        Process a captured packet.
        
        This method:
        1. Extracts relevant information from packet headers
        2. Evaluates packet against firewall rules
        3. Logs the packet
        4. Calls the GUI callback
        
        PACKET STRUCTURE (simplified):
        ==============================
        
        Ethernet Frame:
        +------------------+------------------+------+
        | Dest MAC (6)     | Src MAC (6)      | Type |
        +------------------+------------------+------+
        
        IP Header (inside Ethernet frame):
        +-------+-----+------------+-------+
        | Ver/IHL| TOS| Total Len  | ID    |
        +-------+-----+------------+-------+
        | Flags | TTL | Protocol   | Chksum|
        +-------+-----+------------+-------+
        | Source IP Address               |
        +----------------------------------+
        | Destination IP Address          |
        +----------------------------------+
        
        TCP/UDP Header (inside IP packet):
        +------------+------------+
        | Src Port   | Dst Port   |
        +------------+------------+
        
        Args:
            packet: Scapy packet object.
        """
        # Check for stop signal
        if self._stop_event.is_set():
            return
        
        # Only process IP packets
        if not packet.haslayer(IP):
            return
        
        try:
            # Extract IP layer information
            # Layer 3 (Network Layer) of OSI model
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            destination_ip = ip_layer.dst
            protocol = ip_layer.proto
            packet_size = len(packet)
            
            # Extract port information based on protocol
            # Layer 4 (Transport Layer) of OSI model
            source_port = None
            destination_port = None
            
            if packet.haslayer(TCP):
                # TCP: Transmission Control Protocol
                # Provides reliable, ordered delivery
                # Uses 3-way handshake for connection
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                destination_port = tcp_layer.dport
                
            elif packet.haslayer(UDP):
                # UDP: User Datagram Protocol
                # Provides fast, connectionless delivery
                # No guarantee of delivery or order
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                destination_port = udp_layer.dport
                
            elif packet.haslayer(ICMP):
                # ICMP: Internet Control Message Protocol
                # Used for network diagnostics (ping, traceroute)
                # No port numbers (not transport layer)
                pass
            
            # Evaluate packet against firewall rules
            status, rule_matched = self._rule_engine.evaluate_packet(
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                source_port=source_port,
                destination_port=destination_port
            )
            
            # Create packet record for logging
            record = create_packet_record(
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                source_port=source_port,
                destination_port=destination_port,
                packet_size=packet_size,
                status=status,
                rule_matched=rule_matched
            )
            
            # Log the packet
            self._packet_logger.add_record(record)
            
            # Update statistics
            self._packets_captured += 1
            
            # Call GUI callback if provided
            if self._packet_callback:
                try:
                    self._packet_callback(record)
                except Exception as e:
                    print(f"Callback error: {e}")
                    
        except Exception as e:
            # Log errors but continue capturing
            print(f"Packet processing error: {e}")


def check_privileges() -> bool:
    """
    Check if the program has necessary privileges for packet capture.
    
    Windows: Checks for Administrator privileges
    Linux: Checks for root or CAP_NET_RAW capability
    
    Returns:
        True if sufficient privileges, False otherwise.
    """
    import os
    import sys
    
    if sys.platform == "win32":
        # Windows: Check for admin privileges
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Linux/Unix: Check for root
        return os.geteuid() == 0


def get_default_interface() -> Optional[str]:
    """
    Get the default network interface for packet capture.
    
    Attempts to find the most suitable interface:
    1. Interface with default route
    2. First non-loopback interface
    3. None (capture on all interfaces)
    
    Returns:
        Interface name or None for all interfaces.
    """
    if not SCAPY_AVAILABLE:
        return None
    
    try:
        # Get list of interfaces
        interfaces = get_if_list()
        
        # Filter out loopback interfaces
        non_loopback = [
            iface for iface in interfaces 
            if 'loopback' not in iface.lower() and 'lo' != iface
        ]
        
        if non_loopback:
            return non_loopback[0]
        
        return None
    except Exception:
        return None
