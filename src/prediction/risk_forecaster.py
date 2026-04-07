"""
Predictive Risk Engine for SentinelAI
Forecasts potential attacks and vulnerable assets
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any

from ..core.logger import logger


class RiskForecaster:
    """Predictive risk forecasting"""
    
    def __init__(self):
        self.history_window = 30  # days
        self.forecast_horizon = 24  # hours
        self.historical_patterns = []
    
    def forecast_attack_probability(
        self,
        asset_id: str,
        historical_data: List[Dict] = None,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Forecast attack probability for asset
        Returns risk score 0-100 for next 24 hours
        """
        try:
            base_score = self._calculate_base_risk_score(asset_id)
            temporal_factors = self._analyze_temporal_patterns(time_window_hours)
            threat_environment = self._assess_threat_environment()
            
            # Combine factors
            final_score = 0.5 * base_score + 0.3 * temporal_factors + 0.2 * threat_environment
            final_score = min(max(final_score, 0), 100)  # Clamp to 0-100
            
            # Determine peak risk time
            peak_time = self._predict_peak_risk_time()
            
            # Predict likely attack types
            likely_attacks = self._predict_likely_attack_types()
            
            # Recommend preemptive actions
            recommendations = self._generate_recommendations(final_score, likely_attacks)
            
            return {
                'asset_id': asset_id,
                'risk_score': float(final_score),
                'risk_level': self._score_to_level(final_score),
                'peak_risk_time': peak_time,
                'attack_types': likely_attacks,
                'recommended_actions': recommendations,
                'forecast_horizon': time_window_hours,
                'timestamp': datetime.utcnow().isoformat(),
            }
        
        except Exception as e:
            logger.log_error("RiskForecaster.forecast_attack_probability", e)
            return {
                'asset_id': asset_id,
                'risk_score': 25,
                'risk_level': 'medium',
                'error': str(e)
            }
    
    def predict_vulnerable_assets(self, assets: List[Dict]) -> List[Dict]:
        """Predict which assets are most vulnerable"""
        try:
            vulnerable_assets = []
            
            for asset in assets:
                asset_id = asset.get('id', '')
                patch_level = asset.get('patch_level', 0)  # 0-100
                exposure_score = asset.get('exposure_score', 0)  # 0-100
                historical_target_count = asset.get('historical_target_count', 0)
                
                # Calculate vulnerability score
                vuln_score = (
                    (100 - patch_level) * 0.4 +  # Unpatched = more vulnerable
                    exposure_score * 0.35 +        # Network exposure
                    (historical_target_count / 100) * 0.25  # Past targeting
                )
                
                vulnerable_assets.append({
                    'asset_id': asset_id,
                    'vulnerability_score': min(max(vuln_score, 0), 100),
                    'patch_level': patch_level,
                    'exposure_score': exposure_score,
                    'risk_factors': self._identify_risk_factors(asset)
                })
            
            # Sort by vulnerability
            vulnerable_assets.sort(key=lambda x: x['vulnerability_score'], reverse=True)
            
            logger.log_info(f"Predicted vulnerabilities for {len(vulnerable_assets)} assets")
            
            return vulnerable_assets
        
        except Exception as e:
            logger.log_error("RiskForecaster.predict_vulnerable_assets", e)
            return []
    
    def _calculate_base_risk_score(self, asset_id: str) -> float:
        """Calculate base risk score for asset"""
        # Would integrate with actual data in production
        return np.random.uniform(20, 70)  # Simulated
    
    def _analyze_temporal_patterns(self, hours: int) -> float:
        """Analyze temporal patterns (time-based risk)"""
        current_hour = datetime.utcnow().hour
        current_day = datetime.utcnow().weekday()
        
        # Risk higher during business hours and higher on Friday
        hour_risk = 0.7 if 9 <= current_hour <= 17 else 0.3
        day_risk = 0.8 if current_day == 4 else 0.5  # Friday
        
        return (hour_risk + day_risk) / 2 * 100
    
    def _assess_threat_environment(self) -> float:
        """Assess current threat environment"""
        # Would integrate with threat feeds in production
        return np.random.uniform(40, 70)  # Simulated
    
    def _predict_peak_risk_time(self) -> str:
        """Predict peak risk time window"""
        now = datetime.utcnow()
        peak_time = now + timedelta(hours=12)  # 12 hours from now
        return peak_time.isoformat()
    
    def _predict_likely_attack_types(self) -> List[str]:
        """Predict likely attack types"""
        attack_types = [
            'dos_ddos',
            'ransomware',
            'phishing',
            'brute_force',
            'sql_injection'
        ]
        
        # Return top 3 most likely
        return attack_types[:3]
    
    def _generate_recommendations(self, risk_score: float, attack_types: List[str]) -> List[str]:
        """Generate preventive recommendations"""
        recommendations = []
        
        if risk_score > 80:
            recommendations.append("Increase monitoring and alerting sensitivity")
            recommendations.append("Enable additional logging")
            recommendations.append("Brief security team on potential threats")
        
        if 'ransomware' in attack_types:
            recommendations.append("Verify backup integrity")
            recommendations.append("Test recovery procedures")
        
        if 'brute_force' in attack_types:
            recommendations.append("Review access logs")
            recommendations.append("Consider enabling MFA")
        
        if 'dos_ddos' in attack_types:
            recommendations.append("Review DDoS mitigation settings")
            recommendations.append("Ensure firewall rules are optimized")
        
        return recommendations
    
    def _score_to_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score > 80:
            return 'critical'
        elif score > 60:
            return 'high'
        elif score > 40:
            return 'medium'
        else:
            return 'low'
    
    def _identify_risk_factors(self, asset: Dict) -> List[str]:
        """Identify specific risk factors for asset"""
        factors = []
        
        if asset.get('patch_level', 100) < 50:
            factors.append('unpatched_system')
        
        if asset.get('exposure_score', 0) > 70:
            factors.append('high_network_exposure')
        
        if asset.get('historical_target_count', 0) > 5:
            factors.append('frequently_targeted')
        
        if asset.get('running_vulnerable_services', 0) > 0:
            factors.append('vulnerable_services_running')
        
        return factors


# Global risk forecaster
risk_forecaster = RiskForecaster()
