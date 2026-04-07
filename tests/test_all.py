"""
Comprehensive Test Suite for SentinelAI
Unit and integration tests for all major components
"""

import pytest
import numpy as np
import pandas as pd
from datetime import datetime
from unittest.mock import Mock, patch

# Import modules to test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.database import DatabaseManager
from src.core.logger import SecurityEventLogger
from src.core.config_manager import ConfigManager
from src.core import utils
from src.detection.feature_engineering import FeatureEngineer
from src.detection.network_analyzer import NetworkAnalyzer
from src.detection.endpoint_analyzer import EndpointAnalyzer
from src.defense.response_engine import ResponseEngine
from src.prediction.risk_forecaster import RiskForecaster


# ============ CORE TESTS ============

class TestUtils:
    """Test utility functions"""
    
    def test_generate_alert_id(self):
        alert_id = utils.generate_alert_id()
        assert alert_id.startswith('alert_')
        assert len(alert_id) > 6
    
    def test_generate_incident_id(self):
        incident_id = utils.generate_incident_id()
        assert incident_id.startswith('incident_')
    
    def test_calculate_entropy(self):
        # High entropy data
        data = bytes(range(256))
        entropy = utils.calculate_entropy(data)
        assert entropy > 7.9  # Should be close to 8 for uniform distribution
    
    def test_is_private_ip(self):
        assert utils.is_private_ip('192.168.1.1') == True
        assert utils.is_private_ip('10.0.0.1') == True
        assert utils.is_private_ip('172.16.0.1') == True
        assert utils.is_private_ip('8.8.8.8') == False
    
    def test_normalize_alert(self):
        alert_data = {
            'type': 'dos',
            'severity': 'high',
            'confidence': 0.95
        }
        normalized = utils.normalize_alert(alert_data)
        assert normalized['type'] == 'dos'
        assert normalized['severity'] == 'high'
        assert normalized['confidence'] == 0.95
        assert 'timestamp' in normalized


class TestConfigManager:
    """Test configuration management"""
    
    def test_config_load(self):
        config = ConfigManager()
        assert config.config is not None
    
    def test_get_config_value(self):
        config = ConfigManager()
        system_name = config.get('system.name')
        # Should get value or default to None
        assert system_name is None or isinstance(system_name, str)


class TestLogger:
    """Test logging functionality"""
    
    def test_logger_creation(self):
        logger = SecurityEventLogger(log_file="test.log")
        assert logger.logger is not None
    
    def test_log_security_event(self):
        logger = SecurityEventLogger(log_file="test.log")
        logger.log_security_event(
            "TEST_EVENT",
            "high",
            {"test": "data"}
        )
        # Should not raise exception


# ============ DETECTION TESTS ============

class TestFeatureEngineer:
    """Test feature engineering"""
    
    @pytest.fixture
    def engineer(self):
        return FeatureEngineer()
    
    @pytest.fixture
    def sample_packets(self):
        return [
            {
                'timestamp': i,
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 50000 + i,
                'dst_port': 443,
                'packet_size': 1500,
                'protocol': 'TCP',
                'flags': {'SYN'} if i == 0 else {'ACK'},
                'payload': b'x' * 100,
                'ttl': 64
            }
            for i in range(10)
        ]
    
    def test_extract_network_features(self, engineer, sample_packets):
        features = engineer.extract_network_flow_features(sample_packets)
        assert features.shape[0] == 1
        assert features.shape[1] >= 35  # At least 35 features
        assert not np.isnan(features).any()
    
    def test_feature_names(self, engineer):
        sample_packets = [{
            'timestamp': 0,
            'src_ip': '192.168.1.1',
            'dst_ip': '8.8.8.8',
            'src_port': 50000,
            'dst_port': 443,
            'packet_size': 1500,
            'protocol': 'TCP',
            'flags': set(),
            'payload': b''
        }]
        
        engineer.extract_network_flow_features(sample_packets)
        assert len(engineer.feature_names) > 30
    
    def test_extract_endpoint_features(self, engineer):
        events = [
            {'type': 'file', 'action': 'create', 'path': '/tmp/file1.txt', 'extension': 'txt', 'entropy': 5.5},
            {'type': 'file', 'action': 'modify', 'path': '/tmp/file1.txt'},
            {'type': 'process', 'action': 'create', 'process_name': 'svchost.exe'},
        ]
        
        features = engineer.extract_endpoint_features(events)
        assert features.shape[0] == 1
        assert features.shape[1] >= 15


class TestNetworkAnalyzer:
    """Test network threat detection"""
    
    @pytest.fixture
    def analyzer(self):
        return NetworkAnalyzer()
    
    @pytest.fixture
    def dos_packets(self):
        return [
            {
                'timestamp': i * 0.01,
                'src_ip': '203.0.113.1',
                'dst_ip': '192.168.1.1',
                'src_port': 50000 + i,
                'dst_port': 80,
                'packet_size': 100,
                'protocol': 'TCP',
                'flags': {'SYN'},
                'ttl': 64
            }
            for i in range(200)  # Flood of packets
        ]
    
    def test_analyze_normal_traffic(self, analyzer):
        normal_packets = [
            {
                'timestamp': i,
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 50000,
                'dst_port': 443,
                'packet_size': 1500,
                'protocol': 'TCP',
                'flags': {'ACK'},
                'ttl': 64
            }
            for i in range(5)
        ]
        
        result = analyzer.analyze_packet_flow(normal_packets)
        assert 'is_attack' in result
        assert 'confidence' in result
    
    def test_detect_dos_attack(self, analyzer, dos_packets):
        result = analyzer.analyze_packet_flow(dos_packets)
        assert 'is_attack' in result
        assert 'attack_type' in result
        assert result['attack_type'] in ['dos_ddos', 'unknown_attack']


class TestEndpointAnalyzer:
    """Test endpoint threat detection"""
    
    @pytest.fixture
    def analyzer(self):
        return EndpointAnalyzer()
    
    @pytest.fixture
    def ransomware_events(self):
        return [
            {'type': 'file', 'action': 'modify', 'path': f'/user/docs/file{i}.doc', 'entropy': 7.8}
            for i in range(50)
        ] + [
            {'type': 'file', 'action': 'delete', 'path': f'/user/docs/file_bak{i}.doc'}
            for i in range(10)
        ]
    
    def test_analyze_normal_files(self, analyzer):
        normal_events = [
            {'type': 'file', 'action': 'create', 'path': '/tmp/test.txt'},
            {'type': 'file', 'action': 'modify', 'path': '/tmp/test.txt'},
        ]
        
        result = analyzer.analyze_file_events(normal_events)
        assert 'is_ransomware' in result
        assert 'confidence' in result
    
    def test_detect_ransomware(self, analyzer, ransomware_events):
        result = analyzer.analyze_file_events(ransomware_events)
        assert 'ransomware_score' in result
        assert result['ransomware_score'] > 0


# ============ DEFENSE TESTS ============

class TestResponseEngine:
    """Test defense response"""
    
    @pytest.fixture
    def engine(self):
        return ResponseEngine()
    
    def test_evaluate_critical_threat(self, engine):
        alert_data = {
            'id': 'test1',
            'confidence': 0.95,
            'type': 'ransomware',
            'severity': 'critical'
        }
        
        evaluation = engine.evaluate_threat(alert_data)
        assert evaluation['threat_level'] == 'critical'
        assert evaluation['confidence'] == 0.95
        assert len(evaluation['recommended_actions']) > 0
    
    def test_evaluate_medium_threat(self, engine):
        alert_data = {
            'id': 'test2',
            'confidence': 0.55,
            'type': 'port_scan',
            'severity': 'medium'
        }
        
        evaluation = engine.evaluate_threat(alert_data)
        assert evaluation['threat_level'] == 'medium'
    
    def test_execute_defense_action(self, engine):
        action_plan = {
            'threat_type': 'dos_attack',
            'threat_level': 'high',
            'affected_assets': ['192.168.1.100'],
            'actions': [
                {'type': 'block_ip', 'target': '203.0.113.1'},
            ]
        }
        
        result = engine.execute_defense_action(action_plan)
        assert 'incident_id' in result
        assert 'actions_executed' in result


# ============ PREDICTION TESTS ============

class TestRiskForecaster:
    """Test risk prediction"""
    
    @pytest.fixture
    def forecaster(self):
        return RiskForecaster()
    
    def test_forecast_risk(self, forecaster):
        forecast = forecaster.forecast_attack_probability('asset_001')
        assert 'risk_score' in forecast
        assert 0 <= forecast['risk_score'] <= 100
        assert 'risk_level' in forecast
        assert forecast['risk_level'] in ['critical', 'high', 'medium', 'low']
    
    def test_predict_vulnerable_assets(self, forecaster):
        assets = [
            {'id': 'asset1', 'patch_level': 30, 'exposure_score': 80, 'historical_target_count': 5},
            {'id': 'asset2', 'patch_level': 90, 'exposure_score': 20, 'historical_target_count': 0},
        ]
        
        predictions = forecaster.predict_vulnerable_assets(assets)
        assert len(predictions) == 2
        assert predictions[0]['vulnerability_score'] > predictions[1]['vulnerability_score']


# ============ DATABASE TESTS ============

class TestDatabase:
    """Test database operations"""
    
    @pytest.fixture
    def db(self):
        return DatabaseManager(":memory:")  # Use in-memory DB for testing
    
    def test_add_alert(self, db):
        alert_data = {
            'alert_type': 'dos',
            'severity': 'high',
            'confidence': 0.92,
            'description': 'Test alert'
        }
        
        alert_id = db.add_alert(alert_data)
        assert alert_id is not None
    
    def test_get_alerts(self, db):
        alert_data = {
            'alert_type': 'test',
            'severity': 'low',
            'confidence': 0.5,
            'description': 'Test'
        }
        
        db.add_alert(alert_data)
        alerts = db.get_alerts()
        assert len(alerts) >= 1
    
    def test_update_alert_status(self, db):
        alert_data = {
            'alert_type': 'test',
            'severity': 'low',
            'confidence': 0.5,
            'description': 'Test'
        }
        
        alert_id = db.add_alert(alert_data)
        db.update_alert_status(alert_id, 'closed')
        
        alerts = db.get_alerts(status='closed')
        assert len(alerts) > 0


# ============ INTEGRATION TESTS ============

class TestIntegration:
    """Integration tests for full workflow"""
    
    def test_full_detection_workflow(self):
        """Test complete detection flow"""
        # Create sample attack packets
        attack_packets = [
            {
                'timestamp': i * 0.01,
                'src_ip': f'203.0.113.{i}',
                'dst_ip': '192.168.1.1',
                'src_port': 50000 + i,
                'dst_port': 80,
                'packet_size': 60,  # Small packets
                'protocol': 'TCP',
                'flags': {'SYN'},  # Only SYN packets
                'ttl': 64
            }
            for i in range(100)
        ]
        
        # Run detection
        analyzer = NetworkAnalyzer()
        result = analyzer.analyze_packet_flow(attack_packets)
        
        # Should detect attack
        assert 'is_attack' in result
        assert result['confidence'] > 0
    
    def test_full_response_workflow(self):
        """Test complete response flow"""
        engine = ResponseEngine()
        db = DatabaseManager()
        
        # Create alert
        alert_data = {
            'id': 'test_alert',
            'confidence': 0.95,
            'type': 'dos_ddos',
            'severity': 'critical'
        }
        
        # Evaluate
        evaluation = engine.evaluate_threat(alert_data)
        assert evaluation['threat_level'] == 'critical'
        
        # Execute response
        action_plan = {
            'threat_type': 'dos_ddos',
            'threat_level': 'critical',
            'affected_assets': [],
            'actions': []
        }
        
        result = engine.execute_defense_action(action_plan)
        assert 'incident_id' in result


# ============ PERFORMANCE TESTS ============

class TestPerformance:
    """Performance tests"""
    
    def test_feature_extraction_speed(self):
        """Test feature extraction performance"""
        engineer = FeatureEngineer()
        
        packets = [
            {
                'timestamp': i * 0.001,
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 50000,
                'dst_port': 443,
                'packet_size': 1500,
                'protocol': 'TCP',
                'flags': {'ACK'},
                'ttl': 64
            }
            for i in range(1000)
        ]
        
        import time
        start = time.time()
        features = engineer.extract_network_flow_features(packets)
        elapsed = (time.time() - start) * 1000
        
        # Should extract features quickly (< 100ms)
        assert elapsed < 100, f"Feature extraction took {elapsed}ms, expected < 100ms"
    
    def test_analysis_speed(self):
        """Test analysis speed"""
        analyzer = NetworkAnalyzer()
        
        packets = [{'timestamp': i, 'packet_size': 1500} for i in range(100)]
        
        import time
        start = time.time()
        result = analyzer.analyze_packet_flow(packets)
        elapsed = (time.time() - start) * 1000
        
        # Should analyze within timeout (< 50ms)
        assert elapsed < 50, f"Analysis took {elapsed}ms, expected < 50ms"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
