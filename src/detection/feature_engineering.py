"""
Feature Engineering Module for SentinelAI
Extracts 40+ features from network traffic and endpoint data
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any
from collections import defaultdict
import hashlib


class FeatureEngineer:
    """Feature extraction and engineering"""
    
    def __init__(self):
        self.feature_names = []
    
    def extract_network_flow_features(self, packets: List[Dict]) -> np.ndarray:
        """
        Extract 40+ features from network packets
        Returns: Feature matrix
        """
        if not packets:
            return np.zeros((1, 40))
        
        features = []
        
        # Flow-level features
        flow_duration = self._calculate_flow_duration(packets)
        flow_packets = len(packets)
        flow_bytes = self._calculate_total_bytes(packets)
        
        # Protocol features
        protocol_dist = self._get_protocol_distribution(packets)
        
        # Packet statistics
        packet_sizes = [p.get('packet_size', 0) for p in packets]
        packet_stats = self._calculate_stats(packet_sizes)
        
        # Flag analysis
        flag_stats = self._analyze_flags(packets)
        
        # Flow statistics
        flow_rate = flow_packets / (flow_duration or 1)
        byte_rate = flow_bytes / (flow_duration or 1)
        
        # Port analysis
        src_ports = [p.get('src_port', 0) for p in packets]
        dst_ports = [p.get('dst_port', 0) for p in packets]
        port_stats = self._analyze_ports(src_ports, dst_ports)
        
        # Payload analysis
        payload_stats = self._analyze_payloads(packets)
        
        # Build feature vector (40+ features)
        feature_vector = [
            flow_duration,
            flow_packets,
            flow_bytes,
            flow_rate,
            byte_rate,
            packet_stats['mean'],
            packet_stats['std'],
            packet_stats['max'],
            packet_stats['min'],
            protocol_dist.get('TCP', 0),
            protocol_dist.get('UDP', 0),
            protocol_dist.get('ICMP', 0),
            flag_stats['SYN'],
            flag_stats['ACK'],
            flag_stats['FIN'],
            flag_stats['RST'],
            flag_stats['PSH'],
            flag_stats['URG'],
            flag_stats['CWR'],
            flag_stats['ECE'],
            port_stats['unique_src_ports'],
            port_stats['unique_dst_ports'],
            port_stats['privileged_port_count'],
            payload_stats['mean_payload_size'],
            payload_stats['max_payload_size'],
            payload_stats['encryption_indicators'],
            payload_stats['ascii_packet_ratio'],
            protocol_dist.get('HTTP', 0),
            protocol_dist.get('HTTPS', 0),
            protocol_dist.get('DNS', 0),
            port_stats['port_diversity_score'],
            len(set([p.get('src_ip', '') for p in packets])),
            len(set([p.get('dst_ip', '') for p in packets])),
            self._calculate_packet_entropy(packet_sizes),
            self._calculate_iat_mean(packets),
            self._calculate_iat_std(packets),
            self._calculate_iat_max(packets),
            self._calculate_iat_min(packets),
            self._detect_dos_patterns(packets),
            self._detect_scan_patterns(packets),
            self._calculate_protocol_variance(packets),
        ]
        
        self.feature_names = [
            'flow_duration', 'flow_packets', 'flow_bytes', 'flow_rate', 'byte_rate',
            'packet_mean_size', 'packet_std_size', 'packet_max_size', 'packet_min_size',
            'tcp_count', 'udp_count', 'icmp_count',
            'syn_flag_count', 'ack_flag_count', 'fin_flag_count', 'rst_flag_count',
            'psh_flag_count', 'urg_flag_count', 'cwr_flag_count', 'ece_flag_count',
            'unique_src_ports', 'unique_dst_ports', 'privileged_port_count',
            'mean_payload_size', 'max_payload_size', 'encryption_indicators',
            'ascii_packet_ratio', 'http_count', 'https_count', 'dns_count',
            'port_diversity_score', 'unique_src_ips', 'unique_dst_ips',
            'packet_entropy', 'iat_mean', 'iat_std', 'iat_max', 'iat_min',
            'dos_pattern_score', 'scan_pattern_score', 'protocol_variance'
        ]
        
        return np.array([feature_vector])
    
    def extract_endpoint_features(self, events: List[Dict]) -> np.ndarray:
        """Extract features from endpoint events"""
        if not events:
            return np.zeros((1, 20))
        
        features = []
        
        # File system events
        file_events = [e for e in events if e.get('type') == 'file']
        file_creates = len([e for e in file_events if e.get('action') == 'create'])
        file_modifies = len([e for e in file_events if e.get('action') == 'modify'])
        file_deletes = len([e for e in file_events if e.get('action') == 'delete'])
        
        # Process events
        process_events = [e for e in events if e.get('type') == 'process']
        new_processes = len([e for e in process_events if e.get('action') == 'create'])
        
        # Registry events
        registry_events = [e for e in events if e.get('type') == 'registry']
        registry_writes = len([e for e in registry_events if e.get('action') == 'write'])
        
        # Extension analysis (for ransomware)
        extensions = [e.get('extension', '') for e in file_events if e.get('action') == 'create']
        unique_extensions = len(set(extensions))
        
        # File entropy analysis
        entropies = [e.get('entropy', 0) for e in file_events if e.get('entropy')]
        mean_entropy = np.mean(entropies) if entropies else 0
        
        features = [
            len(events),
            file_creates,
            file_modifies,
            file_deletes,
            new_processes,
            registry_writes,
            unique_extensions,
            mean_entropy,
            file_creates / (len(file_events) or 1),  # file_create_ratio
            file_modifies / (len(file_events) or 1),  # file_modify_ratio
            file_deletes / (len(file_events) or 1),   # file_delete_ratio
            self._detect_ransomware_pattern(events),
            self._detect_privilege_escalation(events),
            self._detect_lateral_movement(events),
            self._detect_persistence_mechanism(events),
            file_deletes / (file_creates or 1),
            len([e for e in events if 'system32' in str(e.get('path', '')).lower()]),
            len([e for e in events if 'temp' in str(e.get('path', '')).lower()]),
            len([e for e in process_events if e.get('parent_process_id')]),  # child_process_count
            self._calculate_event_concentration(events),
        ]
        
        return np.array([features])
    
    def _calculate_flow_duration(self, packets: List[Dict]) -> float:
        """Calculate flow duration"""
        if len(packets) < 2:
            return 0.0
        timestamps = [p.get('timestamp', 0) for p in packets]
        return max(timestamps) - min(timestamps)
    
    def _calculate_total_bytes(self, packets: List[Dict]) -> int:
        """Calculate total bytes in flow"""
        return sum([p.get('packet_size', 0) for p in packets])
    
    def _get_protocol_distribution(self, packets: List[Dict]) -> Dict:
        """Get protocol distribution"""
        dist = defaultdict(int)
        for packet in packets:
            protocol = packet.get('protocol', 'OTHER')
            dist[protocol] += 1
        return dict(dist)
    
    def _calculate_stats(self, values: List[float]) -> Dict:
        """Calculate statistics on values"""
        if not values:
            return {'mean': 0, 'std': 0, 'max': 0, 'min': 0}
        
        arr = np.array(values)
        return {
            'mean': np.mean(arr),
            'std': np.std(arr),
            'max': np.max(arr),
            'min': np.min(arr),
        }
    
    def _analyze_flags(self, packets: List[Dict]) -> Dict:
        """Analyze TCP flags"""
        flags = defaultdict(int)
        for packet in packets:
            flag_set = packet.get('flags', set())
            for flag in flag_set:
                flags[flag] += 1
        
        return {
            'SYN': flags.get('SYN', 0),
            'ACK': flags.get('ACK', 0),
            'FIN': flags.get('FIN', 0),
            'RST': flags.get('RST', 0),
            'PSH': flags.get('PSH', 0),
            'URG': flags.get('URG', 0),
            'CWR': flags.get('CWR', 0),
            'ECE': flags.get('ECE', 0),
        }
    
    def _analyze_ports(self, src_ports: List[int], dst_ports: List[int]) -> Dict:
        """Analyze port usage"""
        return {
            'unique_src_ports': len(set(src_ports)),
            'unique_dst_ports': len(set(dst_ports)),
            'privileged_port_count': len([p for p in dst_ports if p < 1024]),
            'port_diversity_score': len(set(dst_ports)) / (len(dst_ports) or 1),
        }
    
    def _analyze_payloads(self, packets: List[Dict]) -> Dict:
        """Analyze payload characteristics"""
        payload_sizes = [p.get('payload_size', 0) for p in packets if p.get('payload_size', 0) > 0]
        
        return {
            'mean_payload_size': np.mean(payload_sizes) if payload_sizes else 0,
            'max_payload_size': max(payload_sizes) if payload_sizes else 0,
            'encryption_indicators': len([p for p in packets if self._is_encrypted_payload(p)]),
            'ascii_packet_ratio': self._calculate_ascii_ratio(packets),
        }
    
    def _is_encrypted_payload(self, packet: Dict) -> bool:
        """Check if packet payload appears encrypted"""
        # Simple heuristic: high entropy
        payload = packet.get('payload', b'')
        if not payload:
            return False
        return self._calculate_entropy(payload) > 7.0
    
    def _calculate_ascii_ratio(self, packets: List[Dict]) -> float:
        """Calculate ratio of ASCII packets"""
        ascii_count = 0
        for packet in packets:
            payload = packet.get('payload', b'')
            if payload and self._is_ascii(payload):
                ascii_count += 1
        return ascii_count / (len(packets) or 1)
    
    def _is_ascii(self, data: bytes) -> bool:
        """Check if data is ASCII"""
        try:
            data.decode('ascii')
            return True
        except:
            return False
    
    def _calculate_packet_entropy(self, packet_sizes: List[int]) -> float:
        """Calculate entropy of packet sizes"""
        if not packet_sizes:
            return 0.0
        
        data = np.array(packet_sizes)
        # Normalize to distribution
        hist, _ = np.histogram(data, bins=10)
        hist = hist / hist.sum()
        entropy = -np.sum(hist[hist > 0] * np.log2(hist[hist > 0]))
        return entropy
    
    def _calculate_iat_mean(self, packets: List[Dict]) -> float:
        """Calculate mean inter-arrival time"""
        if len(packets) < 2:
            return 0.0
        timestamps = [p.get('timestamp', 0) for p in packets]
        iats = np.diff(timestamps)
        return np.mean(iats) if len(iats) > 0 else 0.0
    
    def _calculate_iat_std(self, packets: List[Dict]) -> float:
        """Calculate std inter-arrival time"""
        if len(packets) < 2:
            return 0.0
        timestamps = [p.get('timestamp', 0) for p in packets]
        iats = np.diff(timestamps)
        return np.std(iats) if len(iats) > 0 else 0.0
    
    def _calculate_iat_max(self, packets: List[Dict]) -> float:
        """Calculate max inter-arrival time"""
        if len(packets) < 2:
            return 0.0
        timestamps = [p.get('timestamp', 0) for p in packets]
        iats = np.diff(timestamps)
        return np.max(iats) if len(iats) > 0 else 0.0
    
    def _calculate_iat_min(self, packets: List[Dict]) -> float:
        """Calculate min inter-arrival time"""
        if len(packets) < 2:
            return 0.0
        timestamps = [p.get('timestamp', 0) for p in packets]
        iats = np.diff(timestamps)
        return np.min(iats) if len(iats) > 0 else 0.0
    
    def _detect_dos_patterns(self, packets: List[Dict]) -> float:
        """Detect DoS attack patterns"""
        if len(packets) < 10:
            return 0.0
        
        syn_count = sum([1 for p in packets if 'SYN' in p.get('flags', set())])
        syn_ratio = syn_count / len(packets)
        return 1.0 if syn_ratio > 0.8 else syn_ratio
    
    def _detect_scan_patterns(self, packets: List[Dict]) -> float:
        """Detect port scanning patterns"""
        dst_ports = [p.get('dst_port', 0) for p in packets]
        unique_ports = len(set(dst_ports))
        port_ratio = unique_ports / max(len(dst_ports), 1)
        return port_ratio
    
    def _calculate_protocol_variance(self, packets: List[Dict]) -> float:
        """Calculate protocol variety"""
        protocols = [p.get('protocol', 'OTHER') for p in packets]
        unique_protocols = len(set(protocols))
        return unique_protocols
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate entropy"""
        if not data:
            return 0.0
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0.0
        data_length = len(data)
        
        for count in byte_counts.values():
            probability = count / data_length
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _detect_ransomware_pattern(self, events: List[Dict]) -> float:
        """Detect ransomware-like behavior"""
        file_events = [e for e in events if e.get('type') == 'file']
        if not file_events:
            return 0.0
        
        creates = len([e for e in file_events if e.get('action') == 'create'])
        deletes = len([e for e in file_events if e.get('action') == 'delete'])
        
        # High delete ratio is suspicious
        delete_ratio = deletes / (creates or 1)
        return min(delete_ratio, 1.0)
    
    def _detect_privilege_escalation(self, events: List[Dict]) -> float:
        """Detect privilege escalation attempts"""
        registry_events = [e for e in events if 'admin' in str(e).lower()]
        return len(registry_events) / max(len(events), 1)
    
    def _detect_lateral_movement(self, events: List[Dict]) -> float:
        """Detect lateral movement patterns"""
        network_events = [e for e in events if e.get('type') == 'network']
        unique_targets = len(set([e.get('target', '') for e in network_events]))
        return min(unique_targets / 10.0, 1.0)
    
    def _detect_persistence_mechanism(self, events: List[Dict]) -> float:
        """Detect persistence mechanisms"""
        startup_files = len([e for e in events if 'startup' in str(e.get('path', '')).lower()])
        services = len([e for e in events if 'service' in str(e).lower()])
        return min((startup_files + services) / 10.0, 1.0)
    
    def _calculate_event_concentration(self, events: List[Dict]) -> float:
        """Measure how concentrated events are in time"""
        if len(events) < 2:
            return 0.0
        
        timestamps = [e.get('timestamp', 0) for e in events]
        time_span = max(timestamps) - min(timestamps)
        
        if time_span == 0:
            return 1.0  # All events at same time is suspicious
        
        # Higher concentration (shorter time span) is more suspicious
        return 1.0 / (1.0 + time_span)


# Global feature engineer
feature_engineer = FeatureEngineer()
