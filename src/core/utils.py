"""
Utility functions for SentinelAI
Common helper functions used across the platform
"""

import uuid
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List
import numpy as np
from pathlib import Path


def generate_alert_id() -> str:
    """Generate unique alert ID"""
    return f"alert_{uuid.uuid4().hex[:12]}"


def generate_incident_id() -> str:
    """Generate unique incident ID"""
    return f"incident_{uuid.uuid4().hex[:12]}"


def generate_action_id() -> str:
    """Generate unique action ID"""
    return f"action_{uuid.uuid4().hex[:12]}"


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Calculate file hash"""
    hash_obj = hashlib.new(algorithm)
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        return None


def calculate_entropy(data: bytes) -> float:
    """Calculate entropy of data (for ransomware detection)"""
    if not data:
        return 0
    
    # Calculate frequency of each byte
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_length = len(data)
    
    for count in byte_counts.values():
        probability = count / data_length
        entropy -= probability * np.log2(probability)
    
    return entropy


def timestamp_to_datetime(timestamp: float) -> datetime:
    """Convert Unix timestamp to datetime"""
    return datetime.fromtimestamp(timestamp)


def datetime_to_timestamp(dt: datetime) -> float:
    """Convert datetime to Unix timestamp"""
    return dt.timestamp()


def is_within_timeframe(timestamp: float, minutes: int) -> bool:
    """Check if timestamp is within last N minutes"""
    now = datetime.utcnow()
    target_time = datetime.fromtimestamp(timestamp)
    time_diff = (now - target_time).total_seconds() / 60
    return time_diff <= minutes


def parse_ip_address(ip_str: str) -> str:
    """Validate and parse IP address"""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return None
    
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return None
        return ip_str
    except ValueError:
        return None


def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
    ]
    
    ip_num = int(''.join([f'{int(x):08b}' for x in ip.split('.')]), 2)
    
    for start, end in private_ranges:
        start_num = int(''.join([f'{int(x):08b}' for x in start.split('.')]), 2)
        end_num = int(''.join([f'{int(x):08b}' for x in end.split('.')]), 2)
        
        if start_num <= ip_num <= end_num:
            return True
    
    return False


def normalize_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize alert data"""
    normalized = {
        'id': alert_data.get('id', generate_alert_id()),
        'timestamp': datetime.utcnow().isoformat(),
        'type': alert_data.get('type', 'unknown'),
        'severity': alert_data.get('severity', 'medium'),
        'confidence': float(alert_data.get('confidence', 0.0)),
        'source': alert_data.get('source'),
        'target': alert_data.get('target'),
        'description': alert_data.get('description', ''),
        'metadata': alert_data.get('metadata', {}),
    }
    return normalized


def merge_alerts(alerts: List[Dict]) -> Dict:
    """Merge multiple alerts into correlation"""
    if not alerts:
        return None
    
    merged = {
        'id': generate_incident_id(),
        'timestamp': datetime.utcnow().isoformat(),
        'alert_count': len(alerts),
        'max_severity': max([a.get('severity', 'low') for a in alerts]),
        'avg_confidence': np.mean([a.get('confidence', 0) for a in alerts]),
        'involved_sources': list(set([a.get('source') for a in alerts if a.get('source')])),
        'involved_targets': list(set([a.get('target') for a in alerts if a.get('target')])),
    }
    return merged


def ensure_directory(path: str) -> Path:
    """Ensure directory exists"""
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def cleanup_old_files(directory: str, days: int = 30):
    """Delete files older than N days"""
    dir_path = Path(directory)
    if not dir_path.exists():
        return
    
    now = datetime.utcnow()
    cutoff = now - timedelta(days=days)
    
    for file_path in dir_path.iterdir():
        if file_path.is_file():
            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            if file_mtime < cutoff:
                file_path.unlink()


def save_json(data: Dict, file_path: str):
    """Save data to JSON file"""
    ensure_directory(Path(file_path).parent)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def load_json(file_path: str) -> Dict:
    """Load data from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except:
        return {}


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"


def get_system_info() -> Dict:
    """Get system information"""
    import platform
    import psutil
    
    return {
        'platform': platform.system(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'cpu_count': psutil.cpu_count(),
        'total_memory_gb': psutil.virtual_memory().total / (1024**3),
        'available_memory_gb': psutil.virtual_memory().available / (1024**3),
    }
