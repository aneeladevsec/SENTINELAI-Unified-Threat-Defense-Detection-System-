"""
SentinelAI - Unified Threat Defense & Detection System
Main application entry point
"""

import sys
import os
from pathlib import Path
import asyncio
import threading
import time
import subprocess

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.core.logger import logger
from src.core.database import DatabaseManager
from src.core.config_manager import config


def setup_environment():
    """Setup application environment"""
    logger.log_info("=" * 60)
    logger.log_info("🛡️  SentinelAI - Unified Threat Defense & Detection System")
    logger.log_info("=" * 60)
    
    # Create necessary directories
    dirs = [
        'data/raw',
        'data/processed',
        'data/models',
        'data/backups',
        'data/quarantine',
        'logs',
        'reports'
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    logger.log_info("[+] Environment setup complete")


def initialize_database():
    """Initialize database"""
    logger.log_info("[*] Initializing database...")
    db = DatabaseManager()
    logger.log_info("[+] Database initialized")
    return db


def start_api_server():
    """Start FastAPI server"""
    logger.log_info("[*] Starting FastAPI server...")
    
    try:
        import uvicorn
        from src.api.rest_api import app
        
        uvicorn.run(
            app,
            host=config.get('api.host', '0.0.0.0'),
            port=config.get('api.port', 8000),
            workers=config.get('api.workers', 4),
            log_level="info"
        )
    except Exception as e:
        logger.log_error("start_api_server", e)


def start_dashboard():
    """Start Streamlit dashboard"""
    logger.log_info("[*] Starting Streamlit dashboard...")
    
    try:
        import streamlit.cli as stcli
        
        sys.argv = [
            "streamlit",
            "run",
            "dashboard/app.py",
            f"--server.port={config.get('dashboard.port', 8501)}",
            "--server.address=0.0.0.0"
        ]
        
        stcli.main()
    except Exception as e:
        logger.log_error("start_dashboard", e)


def start_monitoring():
    """Start system monitoring"""
    logger.log_info("[*] Starting system monitoring...")
    
    try:
        from src.core import utils
        from src.detection import network_analyzer, endpoint_analyzer
        from src.defense import response_engine
        
        while True:
            # Simulate real-time monitoring
            stats = {
                'timestamp': str(time.time()),
                'system_info': utils.get_system_info()
            }
            
            logger.log_debug(f"System monitoring active: {stats}")
            time.sleep(30)  # Monitor every 30 seconds
    
    except Exception as e:
        logger.log_error("start_monitoring", e)


def main():
    """Main application entry point"""
    try:
        # Setup environment
        setup_environment()
        
        # Initialize database
        db = initialize_database()
        
        logger.log_info("")
        logger.log_info("Starting SentinelAI components...")
        logger.log_info("")
        
        # Start services in separate threads
        services = []
        
        # API Server Thread
        api_thread = threading.Thread(target=start_api_server, daemon=True)
        services.append(('API Server', api_thread))
        
        # Monitoring Thread
        monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
        services.append(('System Monitor', monitor_thread))
        
        # Start all services
        for service_name, thread in services:
            logger.log_info(f"[+] Starting {service_name}...")
            thread.start()
        
        # Start dashboard in main thread (blocking)
        logger.log_info("[+] Starting Dashboard...")
        logger.log_info("")
        logger.log_info("=" * 60)
        logger.log_info("🎉 SentinelAI is now running!")
        logger.log_info("")
        logger.log_info("📊 Dashboard: http://localhost:8501")
        logger.log_info("🔌 API Server: http://localhost:8000")
        logger.log_info("📚 API Docs: http://localhost:8000/docs")
        logger.log_info("📋 Logs: logs/sentinelai.log")
        logger.log_info("")
        logger.log_info("Press Ctrl+C to stop...")
        logger.log_info("=" * 60)
        
        start_dashboard()
    
    except KeyboardInterrupt:
        logger.log_info("")
        logger.log_info("Shutting down SentinelAI...")
        sys.exit(0)
    
    except Exception as e:
        logger.log_error("main", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
