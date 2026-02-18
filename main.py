"""
GUI-Based Application Layer Firewall with Real-Time Packet Monitoring
=====================================================================

Main Entry Point
----------------
This is the main entry point for the firewall application.

PROJECT OVERVIEW:
=================
This project implements a GUI-based application layer firewall that provides:
1. Real-time packet sniffing and monitoring
2. Rule-based packet filtering (IP, Port, Protocol)
3. Visual packet log with color-coded status
4. Live traffic statistics
5. Export functionality for analysis

TECHNICAL STACK:
================
- Python 3.8+
- PyQt6: Modern Qt-based GUI framework
- Scapy: Packet manipulation and sniffing
- Threading: Non-blocking packet capture

SYSTEM REQUIREMENTS:
====================
- Operating System: Windows (primary), Linux (supported)
- Python: 3.8 or higher
- Administrator/Root privileges for packet capture
- Npcap (Windows) or libpcap (Linux) for raw socket access

INSTALLATION:
=============
1. Create virtual environment:
   python -m venv venv
   venv\\Scripts\\activate  (Windows)
   source venv/bin/activate (Linux)

2. Install dependencies:
   pip install -r requirements.txt

3. Install Npcap (Windows only):
   Download from https://npcap.com/
   Install with "WinPcap API-compatible Mode" enabled

RUNNING THE APPLICATION:
========================
Windows:
   - Right-click and "Run as Administrator"
   - Or from elevated command prompt: python main.py

Linux:
   - sudo python main.py

NETWORKING CONCEPTS COVERED:
============================
1. OSI Model Layers (7 layers and their functions)
2. TCP/IP Protocol Suite
3. Packet Structure (IP, TCP, UDP, ICMP headers)
4. Port Numbers and Services
5. Firewall Types and Filtering

Author: Network Security Project
Date: February 2026
License: MIT
"""

import sys
import os
import ctypes


def check_admin_windows() -> bool:
    """
    Check if running with Administrator privileges on Windows.
    
    Packet capture on Windows requires admin rights because:
    1. Npcap/WinPcap uses kernel-mode drivers
    2. Raw socket access is restricted
    3. Promiscuous mode requires elevated privileges
    
    Returns:
        True if running as Administrator, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_admin_linux() -> bool:
    """
    Check if running with root privileges on Linux.
    
    Packet capture on Linux requires either:
    1. Root (UID 0)
    2. CAP_NET_RAW capability
    
    Returns:
        True if running as root, False otherwise.
    """
    return os.geteuid() == 0


def is_admin() -> bool:
    """
    Check if the application has required privileges.
    
    Returns:
        True if sufficient privileges, False otherwise.
    """
    if sys.platform == "win32":
        return check_admin_windows()
    else:
        return check_admin_linux()


def elevate_windows() -> None:
    """
    Attempt to restart the application with elevated privileges (Windows).
    
    Uses ShellExecute with 'runas' verb to trigger UAC prompt.
    """
    if sys.platform != "win32":
        return
    
    import subprocess
    
    # Get current script path
    script = os.path.abspath(sys.argv[0])
    
    # Use PowerShell to restart with elevation
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            sys.executable, 
            f'"{script}"',
            None, 
            1  # SW_SHOWNORMAL
        )
        sys.exit(0)
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")


def check_dependencies() -> bool:
    """
    Verify all required dependencies are installed.
    
    Returns:
        True if all dependencies available, False otherwise.
    """
    missing = []
    
    # Check Tkinter (should be built-in with Python)
    try:
        import tkinter
    except ImportError:
        missing.append("tkinter (usually built into Python)")
    
    # Check Scapy
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    
    if missing:
        print("=" * 60)
        print("MISSING DEPENDENCIES")
        print("=" * 60)
        print(f"The following packages are required but not installed:")
        for pkg in missing:
            print(f"  - {pkg}")
        print()
        print("Install them using:")
        print(f"  pip install {' '.join(missing)}")
        print()
        print("Or install all dependencies:")
        print("  pip install -r requirements.txt")
        print("=" * 60)
        return False
    
    return True


def main() -> int:
    """
    Main entry point for the firewall application.
    
    Flow:
    1. Check dependencies
    2. Verify admin privileges
    3. Show warning if not admin
    4. Launch GUI application
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    print("=" * 60)
    print("GUI-Based Application Layer Firewall")
    print("Real-Time Packet Monitoring Using Python")
    print("=" * 60)
    print()
    
    # Check dependencies first
    if not check_dependencies():
        return 1
    
    # Check for admin privileges
    if not is_admin():
        print("WARNING: Not running with Administrator privileges!")
        print()
        print("Packet capture requires elevated privileges.")
        print("The application will start, but capture may fail.")
        print()
        
        # On Windows, offer to elevate
        if sys.platform == "win32":
            print("Attempting to restart with Administrator privileges...")
            print()
            
            # Try to restart elevated
            # If successful, this will exit and restart the process
            elevate_windows()
            
            # If we get here, elevation was cancelled or failed
            print("Please run this application as Administrator.")
    
    else:
        print("✓ Running with Administrator privileges")
    
    print()
    print("Starting GUI...")
    print()
    
    # Import and run the GUI
    try:
        from gui.main_window import run_application
        return run_application()
    
    except Exception as e:
        print(f"ERROR: Failed to start application: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    """
    Entry point when script is run directly.
    
    Example:
        python main.py
        
    On Windows (as Admin):
        - Open Command Prompt as Administrator
        - Navigate to project directory
        - Run: python main.py
    
    On Linux (as root):
        sudo python main.py
    """
    sys.exit(main())
