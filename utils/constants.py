"""
Constants Module
================
Contains all application-wide constants, configurations, and network-related definitions.

NETWORKING CONCEPTS EXPLAINED:
==============================

OSI MODEL (7 Layers):
---------------------
Layer 7 - Application    : HTTP, FTP, SMTP, DNS - User-facing protocols
Layer 6 - Presentation   : SSL/TLS, JPEG, ASCII - Data formatting
Layer 5 - Session        : NetBIOS, RPC - Session management
Layer 4 - Transport      : TCP, UDP - End-to-end communication
Layer 3 - Network        : IP, ICMP - Routing and addressing
Layer 2 - Data Link      : Ethernet, MAC - Frame transmission
Layer 1 - Physical       : Cables, Signals - Physical transmission

This firewall operates at Layer 3 (Network) and Layer 4 (Transport), 
inspecting IP addresses and port numbers.

TCP/IP MODEL (4 Layers):
------------------------
1. Application Layer  : Combines OSI layers 5-7
2. Transport Layer    : TCP/UDP (OSI Layer 4)
3. Internet Layer     : IP, ICMP (OSI Layer 3)
4. Network Access     : Ethernet (OSI Layers 1-2)

FIREWALL TYPES:
---------------
1. Packet Filter Firewall   : Inspects headers (this project implements this)
2. Stateful Firewall        : Tracks connection states
3. Application Firewall     : Deep packet inspection
4. Next-Gen Firewall (NGFW) : Combines multiple techniques

PORT NUMBER RANGES:
-------------------
0-1023       : Well-known ports (system services)
1024-49151   : Registered ports (user applications)
49152-65535  : Dynamic/private ports (ephemeral)

Author: Network Security Project
Date: February 2026
"""

# ==============================================================================
# APPLICATION INFORMATION
# ==============================================================================
APP_NAME = "Application Layer Firewall"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Network Security Project"
APP_DESCRIPTION = "GUI-Based Application Layer Firewall with Real-Time Packet Monitoring"

# ==============================================================================
# PROTOCOL DEFINITIONS
# ==============================================================================
# IP Protocol Numbers (as defined in IANA protocol numbers)
# Reference: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTOCOL_ICMP = 1   # Internet Control Message Protocol
PROTOCOL_TCP = 6    # Transmission Control Protocol  
PROTOCOL_UDP = 17   # User Datagram Protocol

# Protocol name mappings for display
PROTOCOL_NAMES = {
    PROTOCOL_ICMP: "ICMP",
    PROTOCOL_TCP: "TCP",
    PROTOCOL_UDP: "UDP",
}

# Reverse mapping: name to protocol number
PROTOCOL_NUMBERS = {
    "ICMP": PROTOCOL_ICMP,
    "TCP": PROTOCOL_TCP,
    "UDP": PROTOCOL_UDP,
}

# ==============================================================================
# WELL-KNOWN PORTS
# ==============================================================================
# Common port numbers and their services
# These ports are standardized by IANA and commonly targeted/monitored
WELL_KNOWN_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
}

# ==============================================================================
# GUI COLOR SCHEME (DARK MODE)
# ==============================================================================
# Modern dark theme colors for professional appearance
COLORS = {
    # Background colors
    "bg_primary": "#1e1e2e",      # Main background
    "bg_secondary": "#2d2d3f",    # Secondary panels
    "bg_tertiary": "#3d3d5c",     # Tertiary elements
    
    # Text colors
    "text_primary": "#ffffff",    # Primary text
    "text_secondary": "#b4b4b4",  # Secondary text
    "text_muted": "#6c6c8a",      # Muted text
    
    # Status colors
    "allowed": "#4ade80",         # Green for allowed packets
    "blocked": "#f87171",         # Red for blocked packets
    "warning": "#fbbf24",         # Yellow for warnings
    "info": "#60a5fa",            # Blue for info
    
    # UI elements
    "border": "#4a4a6a",          # Border color
    "button_primary": "#6366f1",  # Primary button
    "button_hover": "#818cf8",    # Button hover state
    "button_danger": "#ef4444",   # Danger/stop button
    "button_success": "#22c55e",  # Success/start button
    
    # Accent colors
    "accent_purple": "#a855f7",
    "accent_cyan": "#22d3d8",
    "accent_orange": "#fb923c",
}

# ==============================================================================
# GUI DIMENSIONS AND STYLING
# ==============================================================================
WINDOW_MIN_WIDTH = 1200
WINDOW_MIN_HEIGHT = 800
WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION}"

# Font configurations
FONT_FAMILY = "Segoe UI"
FONT_SIZE_SMALL = 10
FONT_SIZE_NORMAL = 11
FONT_SIZE_LARGE = 14
FONT_SIZE_HEADER = 18

# Packet log display settings
MAX_LOG_ENTRIES = 1000          # Maximum packets to display in log
LOG_UPDATE_INTERVAL = 100       # Milliseconds between GUI updates
STATS_UPDATE_INTERVAL = 1000    # Milliseconds between stats updates

# ==============================================================================
# SNIFFER CONFIGURATION
# ==============================================================================
# Default network interface (None = auto-detect)
DEFAULT_INTERFACE = None

# Packet capture filter (BPF syntax)
# Empty string captures all packets
DEFAULT_BPF_FILTER = ""

# Packet buffer size
PACKET_BUFFER_SIZE = 65535

# Sniffing timeout (seconds)
SNIFF_TIMEOUT = 0.1

# ==============================================================================
# RULE ENGINE DEFAULTS
# ==============================================================================
# Default action when no rule matches
DEFAULT_ACTION = "ALLOW"

# Rule types
RULE_TYPE_IP = "IP"
RULE_TYPE_PORT = "PORT"
RULE_TYPE_PROTOCOL = "PROTOCOL"

# ==============================================================================
# FILE PATHS
# ==============================================================================
LOG_DIRECTORY = "logs"
LOG_FILE_PREFIX = "firewall_log"
LOG_FILE_EXTENSION = ".csv"
RULES_FILE = "firewall_rules.json"

# ==============================================================================
# STATUS MESSAGES
# ==============================================================================
STATUS_RUNNING = "🟢 Firewall Running"
STATUS_STOPPED = "🔴 Firewall Stopped"
STATUS_INITIALIZING = "🟡 Initializing..."
STATUS_ERROR = "⚠️ Error"

# ==============================================================================
# PACKET STRUCTURE EXPLANATION (Comments for Educational Purposes)
# ==============================================================================
"""
IP PACKET STRUCTURE:
====================
+----------------+----------------+----------------+----------------+
|  Version (4)   |  IHL (4)      |  Type of Svc   |  Total Length  |
+----------------+----------------+----------------+----------------+
|       Identification           |  Flags |  Fragment Offset       |
+----------------+----------------+----------------+----------------+
|      TTL       |   Protocol    |      Header Checksum            |
+----------------+----------------+----------------+----------------+
|                      Source IP Address                           |
+----------------+----------------+----------------+----------------+
|                   Destination IP Address                         |
+----------------+----------------+----------------+----------------+
|                    Options (if IHL > 5)                          |
+----------------+----------------+----------------+----------------+

TCP SEGMENT STRUCTURE:
======================
+----------------+----------------+----------------+----------------+
|         Source Port            |        Destination Port         |
+----------------+----------------+----------------+----------------+
|                        Sequence Number                           |
+----------------+----------------+----------------+----------------+
|                     Acknowledgment Number                        |
+----------------+----------------+----------------+----------------+
| Data  |      |U|A|P|R|S|F|                                       |
|Offset | Res  |R|C|S|S|Y|I|          Window Size                  |
|       |      |G|K|H|T|N|N|                                       |
+----------------+----------------+----------------+----------------+
|         Checksum               |        Urgent Pointer           |
+----------------+----------------+----------------+----------------+

UDP DATAGRAM STRUCTURE:
=======================
+----------------+----------------+----------------+----------------+
|         Source Port            |        Destination Port         |
+----------------+----------------+----------------+----------------+
|            Length              |           Checksum              |
+----------------+----------------+----------------+----------------+

ICMP MESSAGE STRUCTURE:
=======================
+----------------+----------------+----------------+----------------+
|     Type       |     Code      |           Checksum              |
+----------------+----------------+----------------+----------------+
|                    Message-specific data                         |
+----------------+----------------+----------------+----------------+
"""
