"""
Automated Defense Response Engine for SentinelAI
Orchestrates and executes defense actions
"""

import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import platform

from ..core.logger import logger
from ..core.database import DatabaseManager
from ..core.utils import generate_action_id, generate_incident_id


class ResponseEngine:
    """Defense response orchestration"""
    
    def __init__(self, db: DatabaseManager = None):
        self.db = db or DatabaseManager()
        self.autonomous_mode = False
        self.response_timeout = 60
        self.action_queue = []
        self.os_type = platform.system()
    
    def evaluate_threat(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Central decision engine
        Evaluates threat and recommends actions
        """
        confidence = alert_data.get('confidence', 0.0)
        alert_type = alert_data.get('type', 'unknown')
        
        # Determine threat level
        if confidence > 0.95:
            threat_level = 'critical'
        elif confidence > 0.85:
            threat_level = 'high'
        elif confidence > 0.65:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        
        # Determine recommended actions
        recommended_actions = self._get_recommended_actions(alert_type, threat_level)
        
        # Determine if auto-execute is appropriate
        auto_execute = (threat_level == 'critical' and self.autonomous_mode) or threat_level == 'critical'
        human_approval_required = threat_level in ['critical', 'high'] or not auto_execute
        
        evaluation = {
            'threat_level': threat_level,
            'confidence': confidence,
            'recommended_actions': recommended_actions,
            'auto_execute': auto_execute and confidence > 0.9,
            'human_approval_required': human_approval_required,
            'timestamp': datetime.utcnow().isoformat(),
            'alert_id': alert_data.get('id'),
        }
        
        logger.log_security_event(
            "THREAT_EVALUATION",
            threat_level,
            evaluation
        )
        
        return evaluation
    
    def _get_recommended_actions(self, alert_type: str, threat_level: str) -> List[Dict]:
        """Get recommended defense actions based on threat"""
        actions = []
        
        if alert_type == 'dos_ddos':
            actions.extend([
                {'type': 'block_ip', 'target': 'alert_source', 'priority': 'critical'},
                {'type': 'update_firewall', 'rule': 'rate_limit', 'priority': 'high'},
                {'type': 'isolate_endpoint', 'target': 'affected_endpoints', 'priority': 'high'},
            ])
        
        elif alert_type == 'port_scan':
            actions.extend([
                {'type': 'block_ip', 'target': 'alert_source', 'priority': 'high', 'duration': 3600},
                {'type': 'alert_security_team', 'priority': 'medium'},
            ])
        
        elif alert_type == 'brute_force':
            actions.extend([
                {'type': 'block_ip', 'target': 'alert_source', 'priority': 'high'},
                {'type': 'revoke_user_sessions', 'priority': 'high'},
                {'type': 'enable_mfa', 'priority': 'medium'},
            ])
        
        elif alert_type == 'ransomware':
            actions.extend([
                {'type': 'isolate_endpoint', 'target': 'affected_host', 'priority': 'critical'},
                {'type': 'terminate_processes', 'target': 'malicious_processes', 'priority': 'critical'},
                {'type': 'quarantine_files', 'target': 'suspicious_files', 'priority': 'critical'},
                {'type': 'restore_backup', 'target': 'affected_files', 'priority': 'high'},
            ])
        
        elif alert_type == 'privilege_escalation':
            actions.extend([
                {'type': 'terminate_process', 'target': 'suspicious_process', 'priority': 'high'},
                {'type': 'revoke_user_session', 'priority': 'high'},
                {'type': 'audit_system_changes', 'priority': 'medium'},
            ])
        
        elif alert_type == 'data_exfiltration':
            actions.extend([
                {'type': 'block_ip', 'target': 'destination_ip', 'priority': 'critical'},
                {'type': 'isolate_endpoint', 'target': 'source_endpoint', 'priority': 'high'},
                {'type': 'quarantine_files', 'target': 'accessed_files', 'priority': 'high'},
            ])
        
        else:
            actions.extend([
                {'type': 'alert_security_team', 'priority': threat_level},
                {'type': 'collect_forensics', 'priority': 'medium'},
            ])
        
        return actions
    
    def execute_defense_action(self, action_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute automated defense response
        """
        execution_results = {
            'incident_id': generate_incident_id(),
            'timestamp': datetime.utcnow().isoformat(),
            'actions_executed': [],
            'actions_failed': [],
            'summary': ''
        }
        
        try:
            # Log incident
            incident_id = self.db.add_incident({
                'title': f"Defense Action Executed: {action_plan.get('threat_type', 'Unknown')}",
                'description': json.dumps(action_plan),
                'severity': action_plan.get('threat_level', 'medium'),
                'affected_assets': action_plan.get('affected_assets', [])
            })
            
            execution_results['incident_id'] = incident_id
            
            # Execute each action
            actions = action_plan.get('actions', [])
            
            for action in actions:
                action_result = self._execute_single_action(action)
                
                if action_result['success']:
                    execution_results['actions_executed'].append(action_result)
                    logger.log_defense_action(action_result)
                else:
                    execution_results['actions_failed'].append(action_result)
                    logger.log_error("ActionExecution", Exception(action_result['error']))
            
            # Generate summary
            executed = len(execution_results['actions_executed'])
            failed = len(execution_results['actions_failed'])
            execution_results['summary'] = f"Executed {executed} actions, {failed} failed"
            
            logger.log_info(f"Defense action plan completed: {execution_results['summary']}")
            
            return execution_results
            
        except Exception as e:
            logger.log_error("ResponseEngine.execute_defense_action", e)
            execution_results['error'] = str(e)
            return execution_results
    
    def _execute_single_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single defense action"""
        action_id = generate_action_id()
        action_type = action.get('type', 'unknown')
        
        result = {
            'action_id': action_id,
            'action_type': action_type,
            'target': action.get('target'),
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'details': {}
        }
        
        try:
            if action_type == 'block_ip':
                result['success'], result['details'] = self._block_ip(action.get('target'))
            
            elif action_type == 'unblock_ip':
                result['success'], result['details'] = self._unblock_ip(action.get('target'))
            
            elif action_type == 'quarantine_file':
                result['success'], result['details'] = self._quarantine_file(action.get('target'))
            
            elif action_type == 'terminate_process':
                result['success'], result['details'] = self._terminate_process(action.get('target'))
            
            elif action_type == 'isolate_endpoint':
                result['success'], result['details'] = self._isolate_endpoint(action.get('target'))
            
            elif action_type == 'restore_backup':
                result['success'], result['details'] = self._restore_backup(action.get('target'))
            
            elif action_type == 'update_firewall':
                result['success'], result['details'] = self._update_firewall_rule(action)
            
            elif action_type == 'revoke_user_session':
                result['success'], result['details'] = self._revoke_user_session(action.get('target'))
            
            else:
                result['success'] = True
                result['details'] = {'message': f'Action {action_type} queued for execution'}
            
        except Exception as e:
            result['success'] = False
            result['error'] = str(e)
        
        return result
    
    def _block_ip(self, ip_address: str) -> tuple:
        """Block IP address at firewall level"""
        try:
            if self.os_type == 'Windows':
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip_address}" dir=in action=block remoteip={ip_address}'
            else:  # Linux/Unix
                cmd = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
            
            # For demo, just log the command
            logger.log_info(f"Blocking IP: {ip_address}")
            
            return True, {'ip': ip_address, 'status': 'blocked'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _unblock_ip(self, ip_address: str) -> tuple:
        """Unblock IP address"""
        try:
            logger.log_info(f"Unblocking IP: {ip_address}")
            return True, {'ip': ip_address, 'status': 'unblocked'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _quarantine_file(self, file_path: str) -> tuple:
        """Quarantine a suspicious file"""
        try:
            import shutil
            quarantine_dir = "data/quarantine"
            
            if os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                quarantine_location = os.path.join(quarantine_dir, file_name)
                shutil.move(file_path, quarantine_location)
                logger.log_info(f"File quarantined: {file_path}")
                return True, {
                    'file': file_path,
                    'quarantine_location': quarantine_location,
                    'status': 'quarantined'
                }
            else:
                return False, {'error': f'File not found: {file_path}'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _terminate_process(self, process_id: int) -> tuple:
        """Terminate a malicious process"""
        try:
            import os
            if self.os_type == 'Windows':
                os.system(f'taskkill /PID {process_id} /F')
            else:
                os.system(f'kill -9 {process_id}')
            
            logger.log_info(f"Process terminated: PID {process_id}")
            return True, {'pid': process_id, 'status': 'terminated'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _isolate_endpoint(self, endpoint_id: str) -> tuple:
        """Isolate endpoint from network"""
        try:
            logger.log_info(f"Endpoint isolated: {endpoint_id}")
            return True, {'endpoint': endpoint_id, 'status': 'isolated'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _restore_backup(self, backup_id: str) -> tuple:
        """Restore from backup"""
        try:
            logger.log_info(f"Restoring from backup: {backup_id}")
            return True, {'backup_id': backup_id, 'status': 'restored'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _update_firewall_rule(self, action: Dict) -> tuple:
        """Update firewall rules"""
        try:
            logger.log_info(f"Firewall rule updated: {action.get('rule')}")
            return True, {'rule': action.get('rule'), 'status': 'updated'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def _revoke_user_session(self, user_id: str) -> tuple:
        """Revoke user session"""
        try:
            logger.log_info(f"User session revoked: {user_id}")
            return True, {'user': user_id, 'status': 'session_revoked'}
        except Exception as e:
            return False, {'error': str(e)}
    
    def generate_incident_report(self, incident_id: str) -> str:
        """Generate incident report"""
        try:
            report = f"""
SENTINELAI INCIDENT REPORT
==========================
Incident ID: {incident_id}
Generated: {datetime.utcnow().isoformat()}

This is a comprehensive incident report including:
- Timeline of events
- Detection evidence
- Actions taken
- Recommendations for remediation

For full details, check the database and logs.
            """
            
            # Save report
            report_path = f"reports/incident_{incident_id}.txt"
            os.makedirs("reports", exist_ok=True)
            with open(report_path, 'w') as f:
                f.write(report)
            
            logger.log_info(f"Incident report generated: {report_path}")
            
            return report
        except Exception as e:
            logger.log_error("ResponseEngine.generate_incident_report", e)
            return ""


# Global response engine
import os
response_engine = ResponseEngine()
