"""
Quick Start and Testing Guide for SentinelAI
Run this script to test all system components
"""

import requests
import json
import time
from typing import Dict, Any

BASE_URL = "http://localhost:8000"

def print_header(text: str):
    """Print formatted header"""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

def test_health() -> bool:
    """Test health endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Health Check PASSED")
            print(f"   Status: {data.get('status')}")
            print(f"   Statistics: {json.dumps(data.get('statistics'), indent=2)}")
            return True
        else:
            print(f"❌ Health Check FAILED: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health Check ERROR: {str(e)}")
        return False

def test_create_alert() -> Dict[str, Any]:
    """Create test alert"""
    try:
        alert_data = {
            "type": "dos_ddos",
            "severity": "high",
            "confidence": 0.92,
            "source_ip": "203.0.113.42",
            "destination_ip": "192.168.1.100",
            "description": "Detected DDoS attack pattern with high confidence"
        }
        
        response = requests.post(f"{BASE_URL}/alerts", json=alert_data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            alert_id = result.get('alert_id')
            print(f"✅ Alert Created Successfully")
            print(f"   Alert ID: {alert_id}")
            print(f"   Response: {json.dumps(result, indent=2)}")
            return result
        else:
            print(f"❌ Alert Creation FAILED: {response.status_code}")
            return {}
    except Exception as e:
        print(f"❌ Alert Creation ERROR: {str(e)}")
        return {}

def test_get_alerts() -> bool:
    """Retrieve alerts"""
    try:
        response = requests.get(f"{BASE_URL}/alerts?limit=10", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Alerts Retrieved")
            print(f"   Count: {data.get('count')}")
            if data.get('alerts'):
                print(f"   Sample Alert: {json.dumps(data['alerts'][0], indent=2)}")
            return True
        else:
            print(f"❌ Get Alerts FAILED: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Get Alerts ERROR: {str(e)}")
        return False

def test_evaluate_threat() -> bool:
    """Test threat evaluation"""
    try:
        threat_data = {
            "type": "ransomware",
            "severity": "critical",
            "confidence": 0.98,
            "source_ip": "198.51.100.5",
            "destination_ip": "10.0.0.50",
            "description": "Ransomware detection: Mass file encryption pattern detected"
        }
        
        response = requests.post(f"{BASE_URL}/defense/evaluate", json=threat_data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            evaluation = result.get('evaluation', {})
            print(f"✅ Threat Evaluation Completed")
            print(f"   Threat Level: {evaluation.get('threat_level')}")
            print(f"   Confidence: {evaluation.get('confidence'):.2%}")
            print(f"   Auto-Execute: {evaluation.get('auto_execute')}")
            print(f"   Recommended Actions: {len(evaluation.get('recommended_actions', []))} actions")
            return True
        else:
            print(f"❌ Threat Evaluation FAILED: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Threat Evaluation ERROR: {str(e)}")
        return False

def test_risk_forecast() -> bool:
    """Test risk forecast"""
    try:
        response = requests.get(f"{BASE_URL}/prediction/risk/asset_001?hours=24", timeout=5)
        if response.status_code == 200:
            result = response.json()
            forecast = result.get('forecast', {})
            print(f"✅ Risk Forecast Generated")
            print(f"   Asset: {forecast.get('asset_id')}")
            print(f"   Risk Score: {forecast.get('risk_score'):.1f}/100")
            print(f"   Risk Level: {forecast.get('risk_level')}")
            print(f"   Peak Risk Time: {forecast.get('peak_risk_time')}")
            print(f"   Likely Attacks: {', '.join(forecast.get('attack_types', []))}")
            return True
        else:
            print(f"❌ Risk Forecast FAILED: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Risk Forecast ERROR: {str(e)}")
        return False

def test_statistics() -> bool:
    """Get system statistics"""
    try:
        response = requests.get(f"{BASE_URL}/statistics", timeout=5)
        if response.status_code == 200:
            result = response.json()
            stats = result.get('statistics', {})
            print(f"✅ Statistics Retrieved")
            print(f"   Total Alerts: {stats.get('total_alerts', 0)}")
            print(f"   Open Alerts: {stats.get('open_alerts', 0)}")
            print(f"   Critical Alerts: {stats.get('critical_alerts', 0)}")
            print(f"   Total Incidents: {stats.get('total_incidents', 0)}")
            print(f"   Open Incidents: {stats.get('open_incidents', 0)}")
            return True
        else:
            print(f"❌ Statistics FAILED: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Statistics ERROR: {str(e)}")
        return False

def test_status() -> bool:
    """Test system status"""
    try:
        response = requests.get(f"{BASE_URL}/status", timeout=5)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ System Status")
            print(f"   Status: {result.get('status')}")
            print(f"   Version: {result.get('version')}")
            modules = result.get('modules', {})
            for module, status in modules.items():
                print(f"   {module}: {status}")
            return True
        else:
            print(f"❌ Status FAILED: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Status ERROR: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("""
    ╔════════════════════════════════════════════╗
    ║   🛡️  SentinelAI - API Testing Suite      ║
    ║   Unified Threat Defense & Detection      ║
    ╚════════════════════════════════════════════╝
    """)
    
    print(f"📡 Testing API Server: {BASE_URL}")
    print("⏳ Connecting...")
    
    # Give server time to start
    time.sleep(2)
    
    results = []
    
    # Test 1: Health
    print_header("TEST 1: System Health Check")
    results.append(("Health Check", test_health()))
    
    # Test 2: Create Alert
    print_header("TEST 2: Create Alert")
    alert_result = test_create_alert()
    results.append(("Create Alert", bool(alert_result.get('alert_id'))))
    
    # Test 3: Get Alerts
    print_header("TEST 3: Retrieve Alerts")
    results.append(("Get Alerts", test_get_alerts()))
    
    # Test 4: Threat Evaluation
    print_header("TEST 4: Threat Evaluation")
    results.append(("Threat Evaluation", test_evaluate_threat()))
    
    # Test 5: Risk Forecast
    print_header("TEST 5: Risk Forecast")
    results.append(("Risk Forecast", test_risk_forecast()))
    
    # Test 6: Statistics
    print_header("TEST 6: System Statistics")
    results.append(("Statistics", test_statistics()))
    
    # Test 7: Status
    print_header("TEST 7: System Status")
    results.append(("Status", test_status()))
    
    # Summary
    print_header("TEST SUMMARY")
    passed = sum([1 for _, result in results if result])
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\n📊 Results: {passed}/{total} tests passed ({passed*100//total}%)")
    
    if passed == total:
        print("\n🎉 All tests passed! SentinelAI is operational.\n")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Check the output above.\n")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
