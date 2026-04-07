"""
Network Analyzer Module for SentinelAI
Real-time network intrusion detection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import time
from datetime import datetime
from collections import deque, defaultdict

from ..core.logger import logger
from ..core.utils import generate_alert_id, normalize_alert, is_private_ip
from .feature_engineering import feature_engineer


class NetworkAnalyzer:
    """Network traffic analysis and intrusion detection"""
    
    def __init__(self):
        self.flow_cache = defaultdict(lambda: deque(maxlen=1000))
        self.ml_model = None
        self.lstm_model = None
        self.anomaly_threshold = 0.75
        self.confidence_threshold = 0.85
        self.initialize_models()
    
    def initialize_models(self):
        """Initialize ML models"""
        # These would be pre-trained models in production
        # For now, we use placeholder
        self.ml_model = self._create_ensemble_model()
        self.lstm_model = self._create_lstm_model()
    
    def _create_ensemble_model(self):
        """Create ensemble classifier"""
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.preprocessing import StandardScaler
        
        # Placeholder ensemble
        return {
            'rf': RandomForestClassifier(n_estimators=100, random_state=42),
            'gb': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'scaler': StandardScaler()
        }
    
    def _create_lstm_model(self):
        """Create LSTM model for sequence analysis"""
        # Placeholder for LSTM - would be actual TensorFlow model in production
        return {
            'sequence_length': 10,
            'encoding_size': 64
        }
    
    def analyze_packet_flow(self, packets: List[Dict]) -> Dict:
        """
        Analyze packet flow and detect anomalies
        Returns: Detection results with alert data
        """
        if not packets:
            return {'is_attack': False, 'confidence': 0.0}
        
        try:
            # Extract features
            features = feature_engineer.extract_network_flow_features(packets)
            
            # Get predictions from ensemble
            ensemble_prediction = self._ensemble_predict(features)
            
            # LSTM temporal analysis
            lstm_score = self._lstm_temporal_analysis(packets)
            
            # Combine predictions
            final_score = 0.6 * ensemble_prediction['confidence'] + 0.4 * lstm_score
            
            # Determine attack type
            attack_type = self._classify_attack_type(packets, features)
            
            result = {
                'is_attack': final_score > self.confidence_threshold,
                'attack_type': attack_type,
                'confidence': float(final_score),
                'risk_score': int(final_score * 100),
                'ensemble_confidence': ensemble_prediction['confidence'],
                'lstm_score': lstm_score,
                'features_extracted': len(features[0]),
                'packet_count': len(packets),
                'details': {
                    'flow_duration': self._get_flow_duration(packets),
                    'packet_rate': len(packets) / max(self._get_flow_duration(packets), 0.1),
                    'attack_indicators': self._extract_attack_indicators(packets)
                }
            }
            
            return result
            
        except Exception as e:
            logger.log_error("NetworkAnalyzer.analyze_packet_flow", e)
            return {'is_attack': False, 'confidence': 0.0, 'error': str(e)}
    
    def _ensemble_predict(self, features: np.ndarray) -> Dict:
        """Get ensemble prediction"""
        # Placeholder prediction logic
        # In production, this would use trained models
        
        # Simple heuristic-based scoring
        score = 0.0
        
        # Check for DoS patterns
        if features[0][3] > 1000:  # High packet rate
            score += 0.3
        
        # Check for port scanning
        if features[0][31] > 50:  # Many unique dest ports
            score += 0.3
        
        # Check for abnormal bytes
        if features[0][2] > 1000000:  # Large byte volume
            score += 0.2
        
        return {
            'is_attack': score > 0.5,
            'confidence': min(score, 1.0)
        }
    
    def _lstm_temporal_analysis(self, packets: List[Dict]) -> float:
        """Analyze temporal patterns with LSTM"""
        # Extract inter-arrival times
        timestamps = [p.get('timestamp', 0) for p in packets]
        
        if len(timestamps) < 2:
            return 0.0
        
        iats = np.diff(timestamps)
        
        # High variance in inter-arrival times can indicate attacks
        iat_variance = np.var(iats) if len(iats) > 0 else 0
        
        # Score based on variance (normalized)
        score = min(iat_variance / 1000.0, 1.0)
        
        return score
    
    def _classify_attack_type(self, packets: List[Dict], features: np.ndarray) -> str:
        """Classify type of attack"""
        if not packets:
            return "unknown"
        
        # Check for DoS/DDoS
        packet_rate = len(packets) / max(self._get_flow_duration(packets), 0.1)
        if packet_rate > 1000:
            return "dos_ddos"
        
        # Check for port scanning
        dest_ports = [p.get('dst_port', 0) for p in packets]
        if len(set(dest_ports)) > 50:
            return "port_scan"
        
        # Check for brute force (many failed connections)
        rst_count = sum([1 for p in packets if 'RST' in p.get('flags', set())])
        if rst_count > len(packets) * 0.5:
            return "brute_force"
        
        # Check for data exfiltration
        src_ips = [p.get('src_ip', '') for p in packets]
        if len(src_ips) > 0 and sum([1 for ip in src_ips if not is_private_ip(ip)]) > len(src_ips) * 0.8:
            total_bytes = sum([p.get('packet_size', 0) for p in packets])
            if total_bytes > 100000:
                return "data_exfiltration"
        
        return "unknown_attack"
    
    def _extract_attack_indicators(self, packets: List[Dict]) -> List[str]:
        """Extract attack indicators"""
        indicators = []
        
        # Check for suspicious flags
        syn_count = sum([1 for p in packets if 'SYN' in p.get('flags', set())])
        fin_count = sum([1 for p in packets if 'FIN' in p.get('flags', set())])
        rst_count = sum([1 for p in packets if 'RST' in p.get('flags', set())])
        
        if syn_count > len(packets) * 0.7:
            indicators.append("high_syn_rate")
        if fin_count == 0 and len(packets) > 100:
            indicators.append("no_graceful_close")
        if rst_count > len(packets) * 0.5:
            indicators.append("high_reset_rate")
        
        # Check for low TTL
        ttls = [p.get('ttl', 64) for p in packets]
        if any(ttl < 10 for ttl in ttls):
            indicators.append("suspicious_ttl")
        
        return indicators
    
    def _get_flow_duration(self, packets: List[Dict]) -> float:
        """Get flow duration in seconds"""
        if len(packets) < 2:
            return 0.0
        
        timestamps = [p.get('timestamp', 0) for p in packets]
        return max(timestamps) - min(timestamps)
    
    def update_threat_intelligence(self, iocs: List[Dict]):
        """Update threat intelligence IOCs"""
        self.known_malicious_ips = set([ioc['value'] for ioc in iocs if ioc['type'] == 'ip'])
        self.known_malicious_domains = set([ioc['value'] for ioc in iocs if ioc['type'] == 'domain'])
        self.known_malicious_hashes = set([ioc['value'] for ioc in iocs if ioc['type'] == 'hash'])
        logger.log_info(f"Updated threat intelligence: {len(iocs)} IOCs loaded")
    
    def check_against_ioc(self, packet: Dict) -> Optional[str]:
        """Check if packet matches known IOCs"""
        src_ip = packet.get('src_ip', '')
        dst_ip = packet.get('dst_ip', '')
        
        if hasattr(self, 'known_malicious_ips'):
            if src_ip in self.known_malicious_ips:
                return f"malicious_source_ip: {src_ip}"
            if dst_ip in self.known_malicious_ips:
                return f"malicious_dest_ip: {dst_ip}"
        
        return None


# Global network analyzer
network_analyzer = NetworkAnalyzer()
