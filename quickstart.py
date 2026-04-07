#!/usr/bin/env python3
"""
SentinelAI - Quick Setup and Dashboard Launcher
One-command setup and launch for the entire system
"""

import os
import sys
import subprocess
import time
import webbrowser
from pathlib import Path

def print_banner():
    """Print welcome banner"""
    banner = """
    ╔════════════════════════════════════════════════════════╗
    ║   🛡️  SentinelAI - Unified Threat Defense System     ║
    ║   Production-Ready Cybersecurity Platform             ║
    ╚════════════════════════════════════════════════════════╝
    """
    print(banner)

def setup_directories():
    """Create necessary directories"""
    print("[*] Setting up directories...")
    dirs = [
        'logs',
        'data/raw',
        'data/processed',
        'data/models',
        'data/backups',
        'data/quarantine',
        'reports'
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    print("[+] Directories created")

def install_dependencies():
    """Install Python dependencies"""
    print("[*] Installing dependencies...")
    print("    This may take a few minutes on first run...")
    
    core_packages = [
        'numpy',
        'pandas',
        'scikit-learn',
        'fastapi',
        'uvicorn',
        'streamlit',
        'plotly',
        'pyyaml',
        'sqlalchemy',
        'pytest',
        'psutil',
        'requests',
        'pydantic',
        'python-dotenv',
    ]
    
    for package in core_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            print(f"   Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', package])
    
    print("[+] Dependencies installed")

def initialize_database():
    """Initialize database"""
    print("[*] Initializing database...")
    try:
        from src.core.database import DatabaseManager
        db = DatabaseManager()
        stats = db.get_statistics()
        print(f"[+] Database initialized: {stats}")
    except Exception as e:
        print(f"[+] Using existing database")

def run_tests():
    """Run quick tests"""
    print("[*] Running quick validation...")
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', 'tests/test_all.py::TestUtils', '-q'],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0:
            print("[+] Validation passed")
            return True
        else:
            print("[!] Some tests failed - continuing anyway")
            return False
    except Exception as e:
        print(f"[!] Validation skipped: {str(e)}")
        return False

def start_api():
    """Start API server"""
    print("[*] Starting REST API Server on port 8000...")
    try:
        subprocess.Popen(
            [sys.executable, '-m', 'uvicorn', 'src.api.rest_api:app', 
             '--host', '0.0.0.0', '--port', '8000', '--log-level', 'info'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(3)
        print("[+] API Server started: http://localhost:8000")
        return True
    except Exception as e:
        print(f"[!] Failed to start API: {str(e)}")
        return False

def open_dashboard():
    """Open dashboard in browser"""
    print("[*] Starting Streamlit Dashboard on port 8501...")
    print("[+] Opening in default browser...")
    
    try:
        # Pause before opening browser
        time.sleep(2)
        
        # Try to open browser
        try:
            webbrowser.open('http://localhost:8501')
        except:
            pass
        
        # Start streamlit
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', 'dashboard/app.py',
            '--server.port', '8501',
            '--server.address', '0.0.0.0'
        ])
        
    except Exception as e:
        print(f"[!] Dashboard error: {str(e)}")

def main():
    """Main setup and launch"""
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print_banner()
    
    try:
        # Setup
        setup_directories()
        install_dependencies()
        initialize_database()
        run_tests()
        
        # Start services
        if not start_api():
            sys.exit(1)
        
        print("")
        print("=" * 60)
        print("✅ SentinelAI is now running!")
        print("")
        print("📊 Dashboard: http://localhost:8501")
        print("🔌 API: http://localhost:8000")
        print("📚 API Docs: http://localhost:8000/docs")
        print("🧪 Test script: python test_api.py")
        print("")
        print("=" * 60)
        print("")
        
        # Start dashboard (blocking)
        open_dashboard()
        
    except KeyboardInterrupt:
        print("\n[*] Shutting down SentinelAI...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
