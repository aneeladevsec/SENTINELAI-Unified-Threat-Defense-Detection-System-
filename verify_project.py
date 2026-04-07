#!/usr/bin/env python
"""Verify SentinelAI project structure and file completeness"""

import os
from pathlib import Path

print("\n" + "="*80)
print("🔍 SENTINELAI PROJECT VERIFICATION")
print("="*80 + "\n")

# Check src files
print("📁 SOURCE CODE FILES:")
print("-" * 80)
py_files = sorted(list(Path('src').rglob('*.py')))
total_bytes = 0
for pf in py_files:
    size = os.path.getsize(pf)
    total_bytes += size
    status = "✅" if size > 100 else "⚠️ "
    print(f"{status} {pf}: {size:,} bytes")

print(f"\n   Total source code: {total_bytes:,} bytes\n")

# Check dashboard
print("📁 DASHBOARD:")
print("-" * 80)
if os.path.exists('dashboard/app.py'):
    size = os.path.getsize('dashboard/app.py')
    print(f"✅ dashboard/app.py: {size:,} bytes\n")
else:
    print("❌ dashboard/app.py NOT FOUND\n")

# Check tests
print("📁 TESTS:")
print("-" * 80)
test_files = sorted(list(Path('tests').glob('*.py')))
for tf in test_files:
    size = os.path.getsize(tf)
    status = "✅" if size > 100 else "⚠️ "
    print(f"{status} {tf}: {size:,} bytes")
print()

# Check config
print("📁 CONFIGURATION:")
print("-" * 80)
config_files = ['config/config.yaml', 'config/rules.yaml', '.env', 'requirements.txt']
for cf in config_files:
    if os.path.exists(cf):
        size = os.path.getsize(cf)
        print(f"✅ {cf}: {size:,} bytes")
    else:
        print(f"❌ {cf}: NOT FOUND")
print()

# Check directories
print("📁 DIRECTORIES:")
print("-" * 80)
required_dirs = ['src', 'src/core', 'src/detection', 'src/defense', 'src/prediction', 
                'src/api', 'dashboard', 'tests', 'config', 'data', 'logs', 'deployment']
for d in required_dirs:
    if os.path.isdir(d):
        print(f"✅ {d}/")
    else:
        print(f"❌ {d}/ NOT FOUND")
print()

# Check if API server is running
print("📡 API SERVER STATUS:")
print("-" * 80)
try:
    import requests
    response = requests.get('http://localhost:8000/health', timeout=2)
    if response.status_code == 200:
        print("✅ API is RUNNING on http://localhost:8000")
    else:
        print("⚠️  API responded with status:", response.status_code)
except:
    print("⚠️  API not running on localhost:8000")
print()

print("="*80)
print("✅ VERIFICATION COMPLETE")
print("="*80 + "\n")
