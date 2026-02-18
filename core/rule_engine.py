"""
Rule Engine Module
==================
Implements the core firewall rule-based filtering logic.

FIREWALL RULE PROCESSING:
=========================
A firewall processes packets using rules that specify:
1. Match Criteria  : What packets to match (IP, port, protocol)
2. Action          : What to do when matched (ALLOW/BLOCK)
3. Priority        : Order in which rules are evaluated

Rule Evaluation Order:
----------------------
Rules are evaluated in order from highest to lowest priority.
The first matching rule determines the packet's fate.
If no rules match, the DEFAULT_ACTION is applied.

This implements a simple but effective packet filter firewall,
operating at OSI Layers 3 (Network) and 4 (Transport).

PACKET FILTERING STRATEGIES:
============================
1. Allowlist (Default Deny)  : Only explicitly allowed traffic passes
2. Blocklist (Default Allow) : Only explicitly blocked traffic is stopped
3. Hybrid                    : Combination of both approaches

This implementation uses a Blocklist strategy by default.

Author: Network Security Project
Date: February 2026
"""

import json
import os
import threading
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum

from utils.constants import (
    RULE_TYPE_IP,
    RULE_TYPE_PORT,
    RULE_TYPE_PROTOCOL,
    DEFAULT_ACTION,
    RULES_FILE,
    PROTOCOL_NUMBERS
)


class RuleAction(Enum):
    """
    Enumeration of possible rule actions.
    
    ALLOW: Permit the packet to pass
    BLOCK: Drop/reject the packet
    """
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class RuleType(Enum):
    """
    Enumeration of rule types.
    
    IP: Match based on IP address (source or destination)
    PORT: Match based on port number (source or destination)
    PROTOCOL: Match based on protocol (TCP/UDP/ICMP)
    """
    IP = "IP"
    PORT = "PORT"
    PROTOCOL = "PROTOCOL"


@dataclass
class FirewallRule:
    """
    Data class representing a single firewall rule.
    
    A firewall rule defines criteria for matching packets and
    the action to take when a match occurs.
    
    Attributes:
        rule_id: Unique identifier for the rule
        rule_type: Type of rule (IP, PORT, PROTOCOL)
        value: The value to match (IP address, port number, or protocol name)
        action: Action to take when matched (ALLOW/BLOCK)
        direction: Traffic direction ('src', 'dst', 'both')
        description: Human-readable description of the rule
        enabled: Whether the rule is active
        priority: Rule evaluation priority (higher = evaluated first)
    """
    rule_id: int
    rule_type: str
    value: str
    action: str
    direction: str = "both"  # 'src', 'dst', or 'both'
    description: str = ""
    enabled: bool = True
    priority: int = 100
    
    def matches_packet(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: int,
        source_port: Optional[int],
        destination_port: Optional[int]
    ) -> bool:
        """
        Check if this rule matches the given packet.
        
        The matching logic depends on the rule type:
        - IP rules: Compare against source/destination IP
        - PORT rules: Compare against source/destination port
        - PROTOCOL rules: Compare against protocol number
        
        Args:
            source_ip: Packet's source IP address
            destination_ip: Packet's destination IP address
            protocol: Packet's protocol number
            source_port: Packet's source port (None for ICMP)
            destination_port: Packet's destination port (None for ICMP)
        
        Returns:
            True if the rule matches the packet, False otherwise.
        """
        if not self.enabled:
            return False
        
        # IP-based matching
        if self.rule_type == RULE_TYPE_IP:
            return self._match_ip(source_ip, destination_ip)
        
        # Port-based matching
        elif self.rule_type == RULE_TYPE_PORT:
            return self._match_port(source_port, destination_port)
        
        # Protocol-based matching
        elif self.rule_type == RULE_TYPE_PROTOCOL:
            return self._match_protocol(protocol)
        
        return False
    
    def _match_ip(self, source_ip: str, destination_ip: str) -> bool:
        """
        Match rule against IP addresses.
        
        IP Address Matching:
        - Exact match: "192.168.1.100"
        - Network match: "192.168.1.0/24" (future enhancement)
        
        Args:
            source_ip: Source IP to check
            destination_ip: Destination IP to check
        
        Returns:
            True if IP matches based on direction setting.
        """
        target_ip = self.value.strip()
        
        if self.direction == "src":
            return source_ip == target_ip
        elif self.direction == "dst":
            return destination_ip == target_ip
        else:  # both
            return source_ip == target_ip or destination_ip == target_ip
    
    def _match_port(
        self, 
        source_port: Optional[int], 
        destination_port: Optional[int]
    ) -> bool:
        """
        Match rule against port numbers.
        
        Port Matching:
        - Exact match: "80"
        - Range match: "8000-9000" (future enhancement)
        
        Args:
            source_port: Source port to check
            destination_port: Destination port to check
        
        Returns:
            True if port matches based on direction setting.
        """
        try:
            target_port = int(self.value)
        except ValueError:
            return False
        
        if self.direction == "src":
            return source_port == target_port
        elif self.direction == "dst":
            return destination_port == target_port
        else:  # both
            return source_port == target_port or destination_port == target_port
    
    def _match_protocol(self, protocol: int) -> bool:
        """
        Match rule against protocol.
        
        Protocol Matching:
        - By name: "TCP", "UDP", "ICMP"
        - By number: 6 (TCP), 17 (UDP), 1 (ICMP)
        
        Args:
            protocol: Protocol number to check
        
        Returns:
            True if protocol matches.
        """
        value_upper = self.value.upper().strip()
        
        # Check if matching by name
        if value_upper in PROTOCOL_NUMBERS:
            return protocol == PROTOCOL_NUMBERS[value_upper]
        
        # Check if matching by number
        try:
            return protocol == int(self.value)
        except ValueError:
            return False


class RuleEngine:
    """
    Core firewall rule processing engine.
    
    The RuleEngine maintains a collection of firewall rules and
    provides methods to:
    - Add/remove rules dynamically
    - Evaluate packets against rules
    - Persist rules to disk
    - Load rules from disk
    
    Thread Safety:
    --------------
    All operations are thread-safe using locking.
    This is important because rules may be modified from the GUI
    while packets are being processed in the sniffer thread.
    
    Rule Processing Algorithm:
    --------------------------
    1. Sort rules by priority (descending)
    2. For each rule, check if it matches the packet
    3. If match found, return the rule's action
    4. If no match, return DEFAULT_ACTION
    """
    
    def __init__(self):
        """Initialize the rule engine with empty rule set."""
        self._rules: Dict[int, FirewallRule] = {}
        self._next_rule_id = 1
        self._lock = threading.Lock()
        
        # Protocol filter flags (for quick toggling)
        self._tcp_enabled = True
        self._udp_enabled = True
        self._icmp_enabled = True
        
        # Load persisted rules if available
        self._load_rules()
    
    def add_rule(
        self,
        rule_type: str,
        value: str,
        action: str = "BLOCK",
        direction: str = "both",
        description: str = "",
        priority: int = 100
    ) -> FirewallRule:
        """
        Add a new firewall rule.
        
        This method creates a new rule and adds it to the engine.
        The rule is assigned a unique ID automatically.
        
        Args:
            rule_type: Type of rule (IP, PORT, PROTOCOL)
            value: Value to match
            action: Action to take (ALLOW/BLOCK)
            direction: Direction to match (src/dst/both)
            description: Human-readable description
            priority: Rule priority (higher = first)
        
        Returns:
            The created FirewallRule instance.
        
        Raises:
            ValueError: If rule_type is invalid.
        """
        # Validate rule type
        valid_types = [RULE_TYPE_IP, RULE_TYPE_PORT, RULE_TYPE_PROTOCOL]
        if rule_type not in valid_types:
            raise ValueError(f"Invalid rule type: {rule_type}. Must be one of {valid_types}")
        
        with self._lock:
            rule = FirewallRule(
                rule_id=self._next_rule_id,
                rule_type=rule_type,
                value=value,
                action=action.upper(),
                direction=direction,
                description=description,
                priority=priority
            )
            
            self._rules[rule.rule_id] = rule
            self._next_rule_id += 1
            
            # Persist rules to disk
            self._save_rules()
            
            return rule
    
    def remove_rule(self, rule_id: int) -> bool:
        """
        Remove a rule by its ID.
        
        Args:
            rule_id: ID of the rule to remove.
        
        Returns:
            True if rule was removed, False if not found.
        """
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._save_rules()
                return True
            return False
    
    def toggle_rule(self, rule_id: int) -> bool:
        """
        Toggle a rule's enabled state.
        
        Args:
            rule_id: ID of the rule to toggle.
        
        Returns:
            New enabled state, or False if rule not found.
        """
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = not self._rules[rule_id].enabled
                self._save_rules()
                return self._rules[rule_id].enabled
            return False
    
    def get_rules(self) -> List[FirewallRule]:
        """
        Get all rules sorted by priority.
        
        Returns:
            List of FirewallRule instances, sorted by priority descending.
        """
        with self._lock:
            rules = list(self._rules.values())
            return sorted(rules, key=lambda r: r.priority, reverse=True)
    
    def clear_rules(self) -> None:
        """Remove all rules."""
        with self._lock:
            self._rules.clear()
            self._save_rules()
    
    def evaluate_packet(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: int,
        source_port: Optional[int],
        destination_port: Optional[int]
    ) -> Tuple[str, str]:
        """
        Evaluate a packet against all rules.
        
        This is the core packet filtering function. It checks the packet
        against all enabled rules in priority order and returns the
        appropriate action.
        
        Evaluation Process:
        1. Check protocol toggle filters first
        2. Iterate through rules by priority
        3. Return first matching rule's action
        4. If no match, return DEFAULT_ACTION
        
        Args:
            source_ip: Packet's source IP address
            destination_ip: Packet's destination IP address
            protocol: Packet's protocol number
            source_port: Packet's source port
            destination_port: Packet's destination port
        
        Returns:
            Tuple of (action, rule_description)
            - action: "ALLOWED" or "BLOCKED"
            - rule_description: Description of matched rule (empty if default)
        """
        # Check protocol filters first
        # These act as quick toggles for entire protocol categories
        if protocol == 6 and not self._tcp_enabled:  # TCP
            return ("BLOCKED", "TCP protocol disabled")
        if protocol == 17 and not self._udp_enabled:  # UDP
            return ("BLOCKED", "UDP protocol disabled")
        if protocol == 1 and not self._icmp_enabled:  # ICMP
            return ("BLOCKED", "ICMP protocol disabled")
        
        with self._lock:
            # Get rules sorted by priority
            sorted_rules = sorted(
                self._rules.values(),
                key=lambda r: r.priority,
                reverse=True
            )
            
            # Check each rule
            for rule in sorted_rules:
                if rule.matches_packet(
                    source_ip, destination_ip, protocol,
                    source_port, destination_port
                ):
                    action = "BLOCKED" if rule.action == "BLOCK" else "ALLOWED"
                    desc = rule.description or f"{rule.rule_type}: {rule.value}"
                    return (action, desc)
        
        # No rule matched, return default action
        return ("ALLOWED" if DEFAULT_ACTION == "ALLOW" else "BLOCKED", "")
    
    def set_protocol_filter(self, protocol: str, enabled: bool) -> None:
        """
        Enable or disable filtering for a specific protocol.
        
        This provides a quick way to toggle entire protocol categories
        without creating individual rules.
        
        Args:
            protocol: Protocol name ("TCP", "UDP", "ICMP")
            enabled: Whether to allow this protocol
        """
        protocol = protocol.upper()
        if protocol == "TCP":
            self._tcp_enabled = enabled
        elif protocol == "UDP":
            self._udp_enabled = enabled
        elif protocol == "ICMP":
            self._icmp_enabled = enabled
    
    def get_protocol_filters(self) -> Dict[str, bool]:
        """
        Get current protocol filter states.
        
        Returns:
            Dictionary mapping protocol names to enabled state.
        """
        return {
            "TCP": self._tcp_enabled,
            "UDP": self._udp_enabled,
            "ICMP": self._icmp_enabled,
        }
    
    def add_blocked_ip(self, ip_address: str, description: str = "") -> FirewallRule:
        """
        Convenience method to block an IP address.
        
        Args:
            ip_address: IP address to block
            description: Optional description
        
        Returns:
            Created FirewallRule instance.
        """
        desc = description or f"Block IP: {ip_address}"
        return self.add_rule(
            rule_type=RULE_TYPE_IP,
            value=ip_address,
            action="BLOCK",
            direction="both",
            description=desc
        )
    
    def add_blocked_port(
        self, 
        port: int, 
        direction: str = "both",
        description: str = ""
    ) -> FirewallRule:
        """
        Convenience method to block a port.
        
        Args:
            port: Port number to block
            direction: Direction to match
            description: Optional description
        
        Returns:
            Created FirewallRule instance.
        """
        desc = description or f"Block Port: {port}"
        return self.add_rule(
            rule_type=RULE_TYPE_PORT,
            value=str(port),
            action="BLOCK",
            direction=direction,
            description=desc
        )
    
    def _save_rules(self) -> None:
        """
        Persist rules to disk in JSON format.
        
        Rules are saved to allow persistence between sessions.
        This method is called automatically when rules change.
        """
        try:
            rules_data = {
                "rules": [asdict(rule) for rule in self._rules.values()],
                "next_id": self._next_rule_id,
                "protocol_filters": {
                    "tcp": self._tcp_enabled,
                    "udp": self._udp_enabled,
                    "icmp": self._icmp_enabled,
                }
            }
            
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(rules_data, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save rules: {e}")
    
    def _load_rules(self) -> None:
        """
        Load rules from disk.
        
        This method is called during initialization to restore
        previously saved rules.
        """
        if not os.path.exists(RULES_FILE):
            return
        
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                rules_data = json.load(f)
            
            # Restore rules
            for rule_dict in rules_data.get("rules", []):
                rule = FirewallRule(**rule_dict)
                self._rules[rule.rule_id] = rule
            
            # Restore next ID
            self._next_rule_id = rules_data.get("next_id", 1)
            
            # Restore protocol filters
            filters = rules_data.get("protocol_filters", {})
            self._tcp_enabled = filters.get("tcp", True)
            self._udp_enabled = filters.get("udp", True)
            self._icmp_enabled = filters.get("icmp", True)
            
        except (IOError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load rules: {e}")
