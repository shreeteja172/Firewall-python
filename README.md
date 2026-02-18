# GUI-Based Application Layer Firewall with Real-Time Packet Monitoring

## Computer Networks Academic Project

**Author:** Network Security Project Team  
**Date:** February 2026  
**Language:** Python  
**Framework:** PyQt6, Scapy

---

## Table of Contents

1. [Abstract](#abstract)
2. [Introduction](#introduction)
3. [Problem Statement](#problem-statement)
4. [Objectives](#objectives)
5. [Methodology](#methodology)
6. [System Architecture](#system-architecture)
7. [Implementation Details](#implementation-details)
8. [Features](#features)
9. [Installation Guide](#installation-guide)
10. [User Manual](#user-manual)
11. [Screenshots](#screenshots)
12. [Conclusion](#conclusion)
13. [Future Enhancements](#future-enhancements)
14. [References](#references)

---

## Abstract

This project presents the design and implementation of a GUI-based application layer firewall with real-time packet monitoring capabilities using Python. The firewall provides network administrators and security researchers with a user-friendly interface to monitor network traffic, implement rule-based packet filtering, and analyze network behavior in real-time.

The application leverages PyQt6 for creating a modern, responsive graphical user interface and Scapy for low-level packet capture and analysis. The system operates at OSI Layers 3 (Network) and 4 (Transport), enabling filtering based on IP addresses, port numbers, and protocols (TCP, UDP, ICMP).

Key features include live packet visualization with color-coded status indicators, dynamic rule management, protocol filtering toggles, traffic statistics, and log export functionality. The implementation demonstrates practical application of networking concepts including the OSI model, TCP/IP protocol suite, packet structures, and firewall technologies.

The project serves as an educational tool for understanding network security fundamentals while providing practical functionality for network monitoring and basic traffic control.

---

## Introduction

### Background

In today's interconnected digital world, network security has become paramount. Firewalls serve as the first line of defense against unauthorized network access and malicious traffic. Understanding how firewalls work at a fundamental level is essential for anyone studying computer networks or pursuing a career in cybersecurity.

### What is a Firewall?

A firewall is a network security device or software that monitors incoming and outgoing network traffic and decides whether to allow or block specific traffic based on a defined set of security rules. Firewalls have been the foundational component of network security for over 25 years.

### Types of Firewalls

1. **Packet Filtering Firewall** - Examines packets in isolation and makes decisions based on header information (IP addresses, ports, protocols). This project implements this type.

2. **Stateful Firewall** - Tracks the state of network connections and makes decisions based on the context of the traffic.

3. **Application Layer Firewall** - Inspects the actual content of packets (deep packet inspection).

4. **Next-Generation Firewall (NGFW)** - Combines multiple security functions including intrusion prevention and application awareness.

### Project Scope

This project implements a packet filtering firewall with a graphical user interface, focusing on:

- Real-time packet capture and display
- Rule-based filtering (IP, Port, Protocol)
- Visual feedback for allowed/blocked traffic
- Educational content about networking concepts

---

## Problem Statement

### The Challenge

Traditional command-line packet sniffing tools like tcpdump and Wireshark have steep learning curves and can be overwhelming for beginners. There is a need for:

1. **Simplified Monitoring** - A tool that presents network traffic in an easy-to-understand format.

2. **Interactive Filtering** - Dynamic rule creation without editing configuration files.

3. **Visual Feedback** - Immediate visual indication of packet status (allowed/blocked).

4. **Educational Value** - A tool that helps users understand networking concepts through practical interaction.

### Target Users

- Computer Networks students
- Security researchers
- Network administrators (for quick diagnostics)
- Anyone learning about firewalls and packet filtering

### Requirements Addressed

| Requirement          | Solution                                         |
| -------------------- | ------------------------------------------------ |
| Real-time monitoring | Live packet feed with auto-scroll                |
| Easy filtering       | GUI-based rule management                        |
| Visual clarity       | Color-coded packets (green=allowed, red=blocked) |
| Learning support     | Comprehensive code comments explaining concepts  |

---

## Objectives

### Primary Objectives

1. **Develop a functional packet filtering firewall** with real-time capture capabilities.

2. **Create an intuitive graphical interface** that simplifies network monitoring.

3. **Implement dynamic rule management** for blocking/allowing traffic based on IP, port, and protocol.

4. **Provide visual feedback** through color-coded log entries and statistics.

### Secondary Objectives

1. Document networking concepts thoroughly in code comments.
2. Ensure cross-platform compatibility (Windows primary, Linux secondary).
3. Implement log export functionality for further analysis.
4. Create a professional, dark-themed UI for extended use.

---

## Methodology

### Development Approach

The project follows a modular, object-oriented design with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Development Methodology                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Requirements Analysis                                    │
│     └── Define features, constraints, and deliverables       │
│                                                              │
│  2. Architecture Design                                      │
│     └── Design modular structure with clear interfaces       │
│                                                              │
│  3. Implementation (Bottom-Up)                               │
│     ├── Utils Layer (constants, logging)                     │
│     ├── Core Layer (rule engine, sniffer)                    │
│     └── GUI Layer (components, main window)                  │
│                                                              │
│  4. Integration                                              │
│     └── Connect components with Qt signals/slots             │
│                                                              │
│  5. Testing                                                  │
│     └── Verify functionality on target platforms             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Technology Selection

| Component      | Technology       | Justification                                        |
| -------------- | ---------------- | ---------------------------------------------------- |
| Language       | Python 3.8+      | Cross-platform, extensive libraries, readable syntax |
| GUI            | PyQt6            | Modern, professional look, excellent documentation   |
| Packet Capture | Scapy            | Powerful packet manipulation, Python-native          |
| Threading      | Python threading | Built-in, sufficient for GUI responsiveness          |

### Design Patterns Used

1. **Observer Pattern** - Qt signals/slots for event handling
2. **Factory Pattern** - PacketRecord creation
3. **Singleton-like** - RuleEngine instance management
4. **MVC Pattern** - Separation of GUI from business logic

---

## System Architecture

### High-Level Architecture (ASCII Diagram)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         APPLICATION ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         PRESENTATION LAYER                          │ │
│  │                         (gui/ package)                              │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │ │
│  │  │   MainWindow     │  │   Components     │  │   StatusBar      │  │ │
│  │  │   (main_window)  │  │   (components)   │  │                  │  │ │
│  │  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │ │
│  └───────────┼─────────────────────┼─────────────────────┼────────────┘ │
│              │                     │                     │              │
│              │     Qt Signals/Slots (Thread-Safe)        │              │
│              ▼                     ▼                     ▼              │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         BUSINESS LOGIC LAYER                        │ │
│  │                         (core/ package)                             │ │
│  │  ┌──────────────────┐       ┌──────────────────┐                   │ │
│  │  │   PacketSniffer  │◄─────►│   RuleEngine     │                   │ │
│  │  │   (sniffer.py)   │       │   (rule_engine)  │                   │ │
│  │  └────────┬─────────┘       └────────┬─────────┘                   │ │
│  └───────────┼──────────────────────────┼─────────────────────────────┘ │
│              │                          │                               │
│              ▼                          ▼                               │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         DATA/UTILITY LAYER                          │ │
│  │                         (utils/ package)                            │ │
│  │  ┌──────────────────┐       ┌──────────────────┐                   │ │
│  │  │   PacketLogger   │       │   Constants      │                   │ │
│  │  │   (logger.py)    │       │   (constants.py) │                   │ │
│  │  └──────────────────┘       └──────────────────┘                   │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│              │                                                           │
│              ▼                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         EXTERNAL INTERFACES                         │ │
│  │  ┌──────────────────┐       ┌──────────────────┐                   │ │
│  │  │   Network Card   │       │   File System    │                   │ │
│  │  │   (via Scapy)    │       │   (JSON, CSV)    │                   │ │
│  │  └──────────────────┘       └──────────────────┘                   │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Thread Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           THREADING MODEL                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────┐         ┌─────────────────────────┐        │
│  │      MAIN THREAD        │         │    SNIFFER THREAD       │        │
│  │    (Qt Event Loop)      │         │   (Background Capture)  │        │
│  ├─────────────────────────┤         ├─────────────────────────┤        │
│  │ • GUI rendering         │         │ • Packet capture        │        │
│  │ • User input handling   │◄───────►│ • Packet parsing        │        │
│  │ • Statistics display    │ Signals │ • Rule evaluation       │        │
│  │ • Rule management       │         │ • Logger updates        │        │
│  └─────────────────────────┘         └─────────────────────────┘        │
│                                                                          │
│  Communication: Qt Signals (thread-safe, queued connections)            │
│  Synchronization: Threading locks for shared resources                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            DATA FLOW DIAGRAM                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│    Network Interface                                                     │
│          │                                                               │
│          ▼                                                               │
│    ┌─────────────┐                                                       │
│    │ Raw Packets │                                                       │
│    └──────┬──────┘                                                       │
│           │                                                              │
│           ▼                                                              │
│    ┌─────────────────────┐                                               │
│    │  Scapy Capture      │                                               │
│    │  (sniff function)   │                                               │
│    └──────────┬──────────┘                                               │
│               │                                                          │
│               ▼                                                          │
│    ┌─────────────────────┐     ┌─────────────────────┐                  │
│    │  Packet Parser      │────►│  Extract:           │                  │
│    │  (IP/TCP/UDP/ICMP)  │     │  • Source IP        │                  │
│    └──────────┬──────────┘     │  • Dest IP          │                  │
│               │                │  • Protocol         │                  │
│               │                │  • Ports            │                  │
│               ▼                └─────────────────────┘                  │
│    ┌─────────────────────┐                                               │
│    │  Rule Engine        │◄──── Rules Database                          │
│    │  (Evaluate packet)  │                                               │
│    └──────────┬──────────┘                                               │
│               │                                                          │
│        ┌──────┴──────┐                                                   │
│        ▼             ▼                                                   │
│    ┌───────┐    ┌─────────┐                                              │
│    │ALLOWED│    │ BLOCKED │                                              │
│    │(Green)│    │  (Red)  │                                              │
│    └───┬───┘    └────┬────┘                                              │
│        │             │                                                   │
│        └──────┬──────┘                                                   │
│               ▼                                                          │
│    ┌─────────────────────┐     ┌─────────────────────┐                  │
│    │  PacketRecord       │────►│  PacketLogger       │──► CSV Export    │
│    │  (Data Structure)   │     │  (Storage)          │                  │
│    └──────────┬──────────┘     └─────────────────────┘                  │
│               │                                                          │
│               ▼                                                          │
│    ┌─────────────────────┐                                               │
│    │  Qt Signal          │                                               │
│    │  (Thread-safe)      │                                               │
│    └──────────┬──────────┘                                               │
│               │                                                          │
│               ▼                                                          │
│    ┌─────────────────────┐                                               │
│    │  GUI Log Panel      │                                               │
│    │  (Display)          │                                               │
│    └─────────────────────┘                                               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
firewall-python/
│
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This documentation
├── firewall_rules.json    # Persisted rules (auto-generated)
│
├── core/                   # Core business logic
│   ├── __init__.py
│   ├── rule_engine.py     # Firewall rule processing
│   └── sniffer.py         # Packet capture with Scapy
│
├── gui/                    # Graphical user interface
│   ├── __init__.py
│   ├── components.py      # Reusable UI widgets
│   └── main_window.py     # Main application window
│
├── utils/                  # Utilities and helpers
│   ├── __init__.py
│   ├── constants.py       # Configuration and constants
│   └── logger.py          # Packet logging and export
│
└── logs/                   # Exported logs directory
    └── (CSV files)
```

---

## Implementation Details

### OSI Model Relevance

This firewall operates at the following OSI layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                         OSI MODEL                                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 7 - Application    │                                     │
│  Layer 6 - Presentation   │  NOT inspected by this firewall     │
│  Layer 5 - Session        │                                     │
├───────────────────────────┼─────────────────────────────────────┤
│  Layer 4 - Transport      │  ✓ TCP/UDP filtering                │
│                           │  ✓ Port-based rules                 │
├───────────────────────────┼─────────────────────────────────────┤
│  Layer 3 - Network        │  ✓ IP filtering                     │
│                           │  ✓ ICMP handling                    │
├───────────────────────────┼─────────────────────────────────────┤
│  Layer 2 - Data Link      │  Handled by Scapy (Ethernet)        │
│  Layer 1 - Physical       │  Handled by NIC driver              │
└─────────────────────────────────────────────────────────────────┘
```

### TCP/IP Model Mapping

```
┌─────────────────────────────────────────────────────────────────┐
│                     TCP/IP vs OSI MODEL                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TCP/IP Model          OSI Model           This Firewall        │
│  ───────────          ─────────           ───────────────        │
│                                                                  │
│  Application    ──►   Application                                │
│                       Presentation        (Not inspected)        │
│                       Session                                    │
│                                                                  │
│  Transport      ──►   Transport           ✓ TCP/UDP ports        │
│                                                                  │
│  Internet       ──►   Network             ✓ IP addresses         │
│                                           ✓ ICMP protocol        │
│                                                                  │
│  Network        ──►   Data Link           (Scapy handles)        │
│  Access               Physical            (NIC driver)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Classes

#### RuleEngine (core/rule_engine.py)

```python
class RuleEngine:
    """
    Manages firewall rules and packet evaluation.

    Methods:
    - add_rule(): Add new filtering rule
    - remove_rule(): Delete a rule
    - evaluate_packet(): Check packet against rules
    - set_protocol_filter(): Toggle protocol categories
    """
```

#### PacketSniffer (core/sniffer.py)

```python
class PacketSniffer:
    """
    Captures and processes network packets.

    Uses Scapy's sniff() function in a background thread.
    Extracts IP, TCP, UDP, ICMP information.
    Integrates with RuleEngine for filtering decisions.
    """
```

#### PacketLogger (utils/logger.py)

```python
class PacketLogger:
    """
    Thread-safe packet logging and statistics.

    Features:
    - In-memory record storage
    - CSV export functionality
    - Real-time statistics calculation
    """
```

---

## Features

### Core Features

| Feature                | Description                                           |
| ---------------------- | ----------------------------------------------------- |
| **Real-time Capture**  | Live packet monitoring with auto-scroll               |
| **IP Blocking**        | Block specific IP addresses (source/destination/both) |
| **Port Blocking**      | Block specific ports (source/destination/both)        |
| **Protocol Filtering** | Toggle TCP, UDP, ICMP on/off                          |
| **Visual Status**      | Green for allowed, red for blocked packets            |
| **Statistics**         | Live packet counts and rates                          |
| **Log Export**         | Export captured packets to CSV                        |
| **Rule Persistence**   | Rules saved across sessions                           |

### GUI Features

| Feature                 | Description                           |
| ----------------------- | ------------------------------------- |
| **Dark Theme**          | Modern dark UI for reduced eye strain |
| **Responsive Design**   | Resizable panels and splitters        |
| **Status Bar**          | Running/stopped status, packet count  |
| **Quick Block**         | One-click IP/port blocking            |
| **Rules Table**         | Sortable, selectable rule display     |
| **Interface Selection** | Choose network interface to monitor   |

---

## Installation Guide

### Prerequisites

1. **Python 3.8+** - Download from [python.org](https://python.org)
2. **Npcap** (Windows only) - Download from [npcap.com](https://npcap.com)
   - During installation, check "WinPcap API-compatible Mode"

### Installation Steps

```bash
# 1. Clone or download the project
cd firewall-python

# 2. Create virtual environment (recommended)
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### Running the Application

**Windows:**

```bash
# Run as Administrator (required for packet capture)
# Right-click Command Prompt → "Run as administrator"
python main.py
```

**Linux:**

```bash
# Run as root
sudo python main.py
```

---

## User Manual

### Starting the Firewall

1. Launch the application (as Administrator)
2. Select network interface from dropdown (or "All Interfaces")
3. Click "▶ Start Firewall" button
4. Packets will appear in the live feed

### Adding Rules

**Method 1: Add Rule Panel**

1. Go to "➕ Add Rule" tab
2. Select rule type (IP, PORT, PROTOCOL)
3. Enter the value to match
4. Select action (BLOCK/ALLOW)
5. Select direction (both/src/dst)
6. Click "Add Rule"

**Method 2: Quick Block**

1. Enter IP address or port in Quick Block section
2. Click "Block IP" or "Block Port"

### Managing Rules

- View active rules in "📋 Active Rules" tab
- Select a rule and click "🗑 Delete Selected Rule" to remove
- Rules are automatically saved

### Exporting Logs

1. Click "💾 Export Logs"
2. Logs are saved to `logs/` directory as CSV

---

## Screenshots

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 🛡️ Application Layer Firewall                            v1.0.0        │
├─────────────────────────────────────────────────────────────────────────┤
│ Interface: [Ethernet ▼]                                                 │
│ [▶ Start] [⏹ Stop] [🗑 Clear] [💾 Export]    ☑TCP ☑UDP ☑ICMP          │
├─────────────────────────────────────────────────────────────────────────┤
│ 📡 Live Packet Feed                    │ 📊 Traffic Statistics         │
│ ─────────────────────────────────────  │ ────────────────────          │
│ [09:15:23] ALLOWED TCP 192.168.1.100   │ Total Packets: 1,234         │
│ [09:15:23] ALLOWED UDP 192.168.1.100   │ Allowed: 1,200               │
│ [09:15:24] BLOCKED TCP 10.0.0.50       │ Blocked: 34                  │
│ [09:15:24] ALLOWED TCP 192.168.1.100   │ Block Rate: 2.8%             │
│ [09:15:25] BLOCKED UDP 10.0.0.50       │ Packets/sec: 45.2            │
│ ...                                    │ TCP: 890  UDP: 320  ICMP: 24 │
├────────────────────────────────────────┼────────────────────────────────┤
│ ⚡ Quick Block                         │ ┌─ 📋 Active Rules ──────────┐ │
│ IP: [___________] [Block IP]           │ │ ID │ Type │ Value │ Action │ │
│ Port: [_______] [Block Port]           │ │  1 │ IP   │ 10.0..│ BLOCK  │ │
│                                        │ │  2 │ PORT │ 445   │ BLOCK  │ │
│                                        │ └──────────────────────────────┤
├─────────────────────────────────────────────────────────────────────────┤
│ 🟢 Firewall Running | Interface: Ethernet | Packets: 1,234             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Conclusion

This project successfully demonstrates the implementation of a GUI-based application layer firewall with the following achievements:

### Accomplishments

1. **Functional Packet Capture** - Real-time network traffic monitoring using Scapy
2. **Rule-Based Filtering** - Dynamic rule creation and evaluation for IP, port, and protocol filtering
3. **Modern GUI** - Professional dark-themed interface using PyQt6
4. **Thread Safety** - Non-blocking GUI with background packet capture
5. **Educational Value** - Comprehensive code documentation explaining networking concepts

### Technical Highlights

- Clean, modular architecture with separation of concerns
- Thread-safe communication using Qt signals/slots
- Persistent rule storage using JSON
- Export functionality for external analysis

### Learning Outcomes

Students working with this project will gain understanding of:

- OSI model and TCP/IP protocol suite
- Packet structure and header fields
- Firewall types and filtering strategies
- Python GUI programming with PyQt6
- Network packet capture with Scapy
- Multi-threaded application design

---

## Future Enhancements

### Short-Term Improvements

1. **CIDR Support** - Allow IP ranges like 192.168.1.0/24
2. **Port Ranges** - Support port ranges like 8000-9000
3. **Rule Import/Export** - Share rules between installations
4. **Search/Filter** - Search through packet logs
5. **Rule Priority Editing** - Drag-and-drop rule ordering

### Medium-Term Features

1. **Stateful Inspection** - Track connection states
2. **Application Detection** - Identify applications by traffic patterns
3. **Bandwidth Monitoring** - Display traffic rates per IP/port
4. **Alerts/Notifications** - System notifications for blocked traffic
5. **Scheduled Rules** - Time-based rule activation

### Long-Term Goals

1. **Deep Packet Inspection** - Analyze packet payloads
2. **Intrusion Detection** - Pattern-based attack detection
3. **Machine Learning** - Anomaly detection
4. **Remote Management** - Web interface for remote administration
5. **Multi-Platform Installer** - One-click installation packages

### Research Extensions

1. **Performance Analysis** - Benchmark packet processing speed
2. **Security Testing** - Penetration testing feedback
3. **Comparison Study** - Compare with commercial firewalls
4. **User Study** - Evaluate usability with target users

---

## References

### Technical References

1. **Scapy Documentation** - https://scapy.readthedocs.io/
2. **PyQt6 Documentation** - https://www.riverbankcomputing.com/static/Docs/PyQt6/
3. **RFC 791 - Internet Protocol** - https://tools.ietf.org/html/rfc791
4. **RFC 793 - TCP** - https://tools.ietf.org/html/rfc793
5. **RFC 768 - UDP** - https://tools.ietf.org/html/rfc768
6. **RFC 792 - ICMP** - https://tools.ietf.org/html/rfc792

### Educational Resources

1. **Computer Networking: A Top-Down Approach** - Kurose & Ross
2. **TCP/IP Illustrated** - W. Richard Stevens
3. **Network Security Essentials** - William Stallings

### Tools and Libraries

1. **Python** - https://python.org
2. **Qt Framework** - https://qt.io
3. **Npcap** - https://npcap.com

---

## License

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

**End of Documentation**
#   F i r e w a l l - p y t h o n  
 