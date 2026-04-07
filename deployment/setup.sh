#!/bin/bash
# Setup and run SentinelAI

set -e

echo "🛡️ SentinelAI - Unified Threat Defense & Detection System"
echo "========================================================="

# Create necessary directories
echo "[*] Creating directories..."
mkdir -p data/raw data/processed data/models data/backups data/quarantine
mkdir -p logs
mkdir -p reports

# Check Python version
echo "[*] Checking Python version..."
python --version

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate || . venv/Scripts/activate

# Install dependencies
echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Initialize database
echo "[*] Initializing database..."
python -c "from src.core.database import DatabaseManager; db = DatabaseManager(); print('[+] Database initialized')"

# Run tests
echo "[*] Running tests..."
pytest tests/test_all.py -v --tb=short || echo "[!] Some tests failed, continuing..."

# Start API
echo "[*] Starting FastAPI server..."
python -m uvicorn src.api.rest_api:app --host 0.0.0.0 --port 8000 &
API_PID=$!
echo "[+] API started (PID: $API_PID)"

# Wait for API to start
sleep 3

# Start Dashboard
echo "[*] Starting Streamlit dashboard..."
streamlit run dashboard/app.py --server.port=8501 --server.address=0.0.0.0 &
DASHBOARD_PID=$!
echo "[+] Dashboard started (PID: $DASHBOARD_PID)"

echo ""
echo "========================================================="
echo "🎉 SentinelAI is now running!"
echo ""
echo "📊 Dashboard: http://localhost:8501"
echo "🔌 API Server: http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop..."
echo "========================================================="

# Wait for both processes
wait $API_PID $DASHBOARD_PID
