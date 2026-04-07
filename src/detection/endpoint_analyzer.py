"""
Endpoint Threat Detection Module for SentinelAI
Monitors file system and process behavior for threats
"""

import os
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import psutil
import subprocess

from ..core.logger import logger
from ..core.utils import generate_alert_id, calculate_entropy
from .feature_engineering import feature_engineer


class EndpointAnalyzer:
    """Endpoint behavior analysis and threat detection"""
    
    def __init__(self):
        self.baseline_processes = set()
        self.suspicious_extensions = {'.exe', '.dll', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1'}
        self.ransomware_threshold = 0.75
        self.privilege_escalation_threshold = 0.7
        self.initialize_baseline()
    
    def initialize_baseline(self):
        """Initialize baseline of trusted processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    self.baseline_processes.add(proc.info['name'].lower())
                except:
                    pass
            logger.log_info(f"Baseline initialized with {len(self.baseline_processes)} trusted processes")
        except Exception as e:
            logger.log_error("EndpointAnalyzer.initialize_baseline", e)
    
    def analyze_file_events(self, file_events: List[Dict]) -> Dict:
        """Analyze file system events for threats"""
        if not file_events:
            return {
                'is_ransomware': False,
                'is_suspicious': False,
                'confidence': 0.0
            }
        
        try:
            # Extract features
            features = feature_engineer.extract_endpoint_features(file_events)
            
            # Ransomware detection
            ransomware_score = self._detect_ransomware_behavior(file_events)
            is_ransomware = ransomware_score > self.ransomware_threshold
            
            # Suspicious activity detection
            suspicious_files = self._identify_suspicious_files(file_events)
            suspicious_score = len(suspicious_files) / max(len(file_events), 1)
            
            # Privilege escalation
            priv_esc_score = self._detect_privilege_escalation(file_events)
            
            # Combine scores
            final_score = max(ransomware_score, suspicious_score, priv_esc_score)
            
            result = {
                'is_ransomware': is_ransomware,
                'ransomware_score': ransomware_score,
                'is_suspicious': final_score > 0.5,
                'suspicious_score': suspicious_score,
                'privilege_escalation_score': priv_esc_score,
                'confidence': final_score,
                'risk_score': int(final_score * 100),
                'suspicious_files': suspicious_files,
                'affected_file_count': len(file_events),
                'details': {
                    'entropy_analysis': self._analyze_file_entropy(file_events),
                    'extension_changes': len(set([e.get('extension', '') for e in file_events])),
                    'indicators': self._extract_indicators(file_events)
                }
            }
            
            return result
            
        except Exception as e:
            logger.log_error("EndpointAnalyzer.analyze_file_events", e)
            return {
                'is_ransomware': False,
                'is_suspicious': False,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _detect_ransomware_behavior(self, file_events: List[Dict]) -> float:
        """Detect ransomware-specific behaviors"""
        file_creates = len([e for e in file_events if e.get('action') == 'create'])
        file_modifies = len([e for e in file_events if e.get('action') == 'modify'])
        file_deletes = len([e for e in file_events if e.get('action') == 'delete'])
        
        # Calculate ratios
        total_events = len(file_events)
        
        # Ransomware typically: creates files with different extensions, modifies existing files, deletes originals
        modify_ratio = file_modifies / total_events if total_events > 0 else 0
        delete_ratio = file_deletes / total_events if total_events > 0 else 0
        
        # Check for extension changes
        extensions = {}
        for event in file_events:
            path = event.get('path', '')
            if '.' in path:
                ext = path.split('.')[-1]
                extensions[ext] = extensions.get(ext, 0) + 1
        
        unique_extensions = len(extensions)
        
        # Calculate entropy of files being modified
        high_entropy_files = len([e for e in file_events if e.get('entropy', 0) > 7.5])
        entropy_ratio = high_entropy_files / max(file_modifies, 1)
        
        # Score
        score = 0.0
        if modify_ratio > 0.6:
            score += 0.3
        if delete_ratio > 0.2:
            score += 0.3
        if unique_extensions > 10 or (unique_extensions > 5 and modify_ratio > 0.5):
            score += 0.2
        if entropy_ratio > 0.7:
            score += 0.2
        
        return min(score, 1.0)
    
    def _identify_suspicious_files(self, file_events: List[Dict]) -> List[str]:
        """Identify suspicious file operations"""
        suspicious = []
        
        for event in file_events:
            path = event.get('path', '').lower()
            action = event.get('action', '')
            
            # Check for suspicious locations
            suspicious_locations = ['temp', 'appdata', 'programfiles', 'system32', 'windows']
            is_suspicious_location = any(loc in path for loc in suspicious_locations)
            
            # Check for suspicious extensions
            if any(path.endswith(ext) for ext in self.suspicious_extensions):
                is_suspicious_extension = True
            else:
                is_suspicious_extension = False
            
            # Check for hidden files
            is_hidden = '.' in os.path.basename(path) or path.startswith('.')
            
            if (is_suspicious_location and is_suspicious_extension) or (action == 'create' and is_suspicious_extension):
                suspicious.append(path)
        
        return suspicious
    
    def _detect_privilege_escalation(self, file_events: List[Dict]) -> float:
        """Detect privilege escalation attempts"""
        score = 0.0
        
        # Check for modifications in system directories
        system_mods = len([e for e in file_events if 'system32' in e.get('path', '').lower() and e.get('action') == 'modify'])
        registry_mods = len([e for e in file_events if 'registry' in e.get('type', '').lower()])
        
        if system_mods > 0:
            score += 0.4
        if registry_mods > 5:
            score += 0.4
        
        # Check for new service creation
        service_creates = len([e for e in file_events if 'services' in e.get('path', '').lower() and e.get('action') == 'create'])
        if service_creates > 0:
            score += 0.2
        
        return min(score, 1.0)
    
    def _analyze_file_entropy(self, file_events: List[Dict]) -> Dict:
        """Analyze entropy of files"""
        entropies = [e.get('entropy', 0) for e in file_events if e.get('entropy', 0) > 0]
        
        if not entropies:
            return {'mean': 0, 'max': 0, 'high_entropy_count': 0}
        
        import numpy as np
        
        mean_entropy = np.mean(entropies)
        max_entropy = max(entropies)
        high_entropy_count = len([e for e in entropies if e > 7.5])
        
        return {
            'mean': float(mean_entropy),
            'max': float(max_entropy),
            'high_entropy_count': high_entropy_count
        }
    
    def _extract_indicators(self, file_events: List[Dict]) -> List[str]:
        """Extract threat indicators"""
        indicators = []
        
        # Check for bulk file operations
        if len(file_events) > 100:
            indicators.append("bulk_file_operations")
        
        # Check for file extensions changing
        extensions_before = set()
        extensions_after = set()
        for event in file_events:
            if event.get('action') in ['modify', 'delete']:
                path = event.get('path', '')
                if '.' in path:
                    extensions_before.add(path.split('.')[-1])
            elif event.get('action') == 'create':
                path = event.get('path', '')
                if '.' in path:
                    extensions_after.add(path.split('.')[-1])
        
        if len(extensions_after - extensions_before) > 0:
            indicators.append("new_file_extensions")
        
        # Check for system file modifications
        if any('system32' in e.get('path', '').lower() for e in file_events):
            indicators.append("system_file_modification")
        
        # Check for hidden file operations
        if any(os.path.basename(e.get('path', '')).startswith('.') for e in file_events):
            indicators.append("hidden_file_operations")
        
        return indicators
    
    def analyze_process_behavior(self, process_events: List[Dict]) -> Dict:
        """Analyze process behavior"""
        try:
            suspicious_processes = []
            
            for event in process_events:
                process_name = event.get('process_name', '').lower()
                
                # Check if process is baseline
                if process_name not in self.baseline_processes:
                    suspicious_processes.append(event)
            
            score = len(suspicious_processes) / max(len(process_events), 1)
            
            return {
                'is_suspicious_process': score > 0.3,
                'suspicious_processes': suspicious_processes,
                'suspicion_score': score,
                'total_processes': len(process_events)
            }
        except Exception as e:
            logger.log_error("EndpointAnalyzer.analyze_process_behavior", e)
            return {
                'is_suspicious_process': False,
                'suspicious_processes': [],
                'suspicion_score': 0.0
            }


# Global endpoint analyzer
endpoint_analyzer = EndpointAnalyzer()
