"""
Logger Module
=============
Handles logging of packet data and system events.

This module provides:
- File-based logging for packet data
- Export functionality for captured packets
- Timestamp management
- CSV format export for further analysis

LOGGING IN NETWORK SECURITY:
============================
Logging is crucial for:
1. Forensic Analysis  : Investigating security incidents
2. Compliance         : Meeting regulatory requirements
3. Troubleshooting    : Diagnosing network issues
4. Auditing           : Tracking network activity

Author: Network Security Project
Date: February 2026
"""

import os
import csv
import threading
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict

from .constants import (
    LOG_DIRECTORY, 
    LOG_FILE_PREFIX, 
    LOG_FILE_EXTENSION,
    PROTOCOL_NAMES
)


@dataclass
class PacketRecord:
    """
    Data class representing a captured packet record.
    
    This structure contains all relevant information extracted from
    network packets at OSI Layers 3 (Network) and 4 (Transport).
    
    Attributes:
        timestamp: Time when packet was captured
        source_ip: Source IP address (Network Layer)
        destination_ip: Destination IP address (Network Layer)
        protocol: Protocol number/name (Transport Layer)
        source_port: Source port number (Transport Layer)
        destination_port: Destination port number (Transport Layer)
        packet_size: Size of the packet in bytes
        status: ALLOWED or BLOCKED based on firewall rules
        rule_matched: Description of the rule that matched (if blocked)
    """
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int]
    destination_port: Optional[int]
    packet_size: int
    status: str
    rule_matched: str = ""
    
    def to_display_string(self) -> str:
        """
        Convert packet record to a formatted display string for GUI.
        
        Returns:
            Formatted string representation of the packet.
        """
        src_port = self.source_port if self.source_port else "-"
        dst_port = self.destination_port if self.destination_port else "-"
        
        return (
            f"[{self.timestamp}] {self.status:7} | "
            f"{self.protocol:4} | "
            f"{self.source_ip:15}:{str(src_port):5} → "
            f"{self.destination_ip:15}:{str(dst_port):5} | "
            f"{self.packet_size} bytes"
            f"{' | Rule: ' + self.rule_matched if self.rule_matched else ''}"
        )


class PacketLogger:
    """
    Thread-safe packet logger for capturing and exporting network traffic data.
    
    This class manages:
    - In-memory storage of packet records
    - Thread-safe access to packet data
    - Export functionality to CSV files
    - Statistics calculation
    
    Thread Safety:
    --------------
    All public methods use locking to ensure thread-safe access,
    as packets are captured in a separate sniffing thread while
    the GUI accesses the data from the main thread.
    """
    
    def __init__(self, max_records: int = 10000):
        """
        Initialize the packet logger.
        
        Args:
            max_records: Maximum number of records to keep in memory.
                        Older records are removed when limit is reached.
        """
        self._records: List[PacketRecord] = []
        self._max_records = max_records
        self._lock = threading.Lock()
        
        # Statistics counters
        self._total_packets = 0
        self._blocked_packets = 0
        self._allowed_packets = 0
        self._protocol_counts: Dict[str, int] = {}
        
        # Ensure log directory exists
        self._ensure_log_directory()
    
    def _ensure_log_directory(self) -> None:
        """Create log directory if it doesn't exist."""
        if not os.path.exists(LOG_DIRECTORY):
            try:
                os.makedirs(LOG_DIRECTORY)
            except OSError as e:
                print(f"Warning: Could not create log directory: {e}")
    
    def add_record(self, record: PacketRecord) -> None:
        """
        Add a packet record to the log.
        
        This method is thread-safe and automatically manages
        the record limit by removing oldest records when full.
        
        Args:
            record: PacketRecord instance to add.
        """
        with self._lock:
            # Add the new record
            self._records.append(record)
            
            # Update statistics
            self._total_packets += 1
            if record.status == "BLOCKED":
                self._blocked_packets += 1
            else:
                self._allowed_packets += 1
            
            # Update protocol counts
            protocol = record.protocol
            self._protocol_counts[protocol] = self._protocol_counts.get(protocol, 0) + 1
            
            # Remove oldest records if limit exceeded
            if len(self._records) > self._max_records:
                self._records.pop(0)
    
    def get_records(self, count: Optional[int] = None) -> List[PacketRecord]:
        """
        Get packet records from the log.
        
        Args:
            count: Number of most recent records to return.
                   If None, returns all records.
        
        Returns:
            List of PacketRecord instances.
        """
        with self._lock:
            if count is None:
                return self._records.copy()
            return self._records[-count:].copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current packet statistics.
        
        Returns:
            Dictionary containing:
            - total_packets: Total packets captured
            - blocked_packets: Number of blocked packets
            - allowed_packets: Number of allowed packets
            - protocol_counts: Dictionary of packets per protocol
            - block_rate: Percentage of blocked packets
        """
        with self._lock:
            block_rate = 0.0
            if self._total_packets > 0:
                block_rate = (self._blocked_packets / self._total_packets) * 100
            
            return {
                "total_packets": self._total_packets,
                "blocked_packets": self._blocked_packets,
                "allowed_packets": self._allowed_packets,
                "protocol_counts": self._protocol_counts.copy(),
                "block_rate": round(block_rate, 2),
            }
    
    def clear(self) -> None:
        """
        Clear all records and reset statistics.
        
        This method is thread-safe.
        """
        with self._lock:
            self._records.clear()
            self._total_packets = 0
            self._blocked_packets = 0
            self._allowed_packets = 0
            self._protocol_counts.clear()
    
    def export_to_csv(self, filename: Optional[str] = None) -> str:
        """
        Export all records to a CSV file.
        
        The CSV format is chosen for compatibility with:
        - Spreadsheet applications (Excel, Google Sheets)
        - Data analysis tools (Pandas, R)
        - Security information systems (SIEM)
        
        Args:
            filename: Custom filename. If None, generates timestamp-based name.
        
        Returns:
            Full path to the exported file.
        
        Raises:
            IOError: If file cannot be written.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{LOG_FILE_PREFIX}_{timestamp}{LOG_FILE_EXTENSION}"
        
        filepath = os.path.join(LOG_DIRECTORY, filename)
        
        with self._lock:
            records_copy = self._records.copy()
        
        # Define CSV columns
        fieldnames = [
            "timestamp", "source_ip", "destination_ip", "protocol",
            "source_port", "destination_port", "packet_size", "status", "rule_matched"
        ]
        
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for record in records_copy:
                    writer.writerow(asdict(record))
            
            return filepath
        
        except IOError as e:
            raise IOError(f"Failed to export logs: {e}")
    
    def get_recent_count(self, seconds: float = 1.0) -> int:
        """
        Get the count of packets received in the last N seconds.
        
        Useful for calculating packets-per-second (PPS) rate.
        
        Args:
            seconds: Time window in seconds.
        
        Returns:
            Number of packets in the time window.
        """
        with self._lock:
            if not self._records:
                return 0
            
            cutoff_time = datetime.now()
            count = 0
            
            # Iterate backwards through records (most recent first)
            for record in reversed(self._records):
                try:
                    record_time = datetime.strptime(
                        record.timestamp, 
                        "%Y-%m-%d %H:%M:%S.%f"
                    )
                    delta = (cutoff_time - record_time).total_seconds()
                    
                    if delta <= seconds:
                        count += 1
                    else:
                        break  # Records are chronological, so we can stop
                except ValueError:
                    continue
            
            return count


def create_packet_record(
    source_ip: str,
    destination_ip: str,
    protocol: int,
    source_port: Optional[int],
    destination_port: Optional[int],
    packet_size: int,
    status: str,
    rule_matched: str = ""
) -> PacketRecord:
    """
    Factory function to create a PacketRecord with current timestamp.
    
    This function simplifies record creation by automatically:
    - Adding the current timestamp
    - Converting protocol number to name
    
    Args:
        source_ip: Source IP address
        destination_ip: Destination IP address
        protocol: Protocol number (6=TCP, 17=UDP, 1=ICMP)
        source_port: Source port (None for ICMP)
        destination_port: Destination port (None for ICMP)
        packet_size: Size in bytes
        status: "ALLOWED" or "BLOCKED"
        rule_matched: Description of matched rule
    
    Returns:
        PacketRecord instance ready for logging.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    protocol_name = PROTOCOL_NAMES.get(protocol, f"Unknown({protocol})")
    
    return PacketRecord(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol_name,
        source_port=source_port,
        destination_port=destination_port,
        packet_size=packet_size,
        status=status,
        rule_matched=rule_matched
    )
