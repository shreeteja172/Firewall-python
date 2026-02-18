"""
Core Package
============
Core functionality for the Application Layer Firewall.

This package contains:
- rule_engine.py: Rule-based packet filtering engine
- sniffer.py: Network packet capture using Scapy

Author: Network Security Project
Date: February 2026
"""

from .rule_engine import RuleEngine, FirewallRule
from .sniffer import PacketSniffer
