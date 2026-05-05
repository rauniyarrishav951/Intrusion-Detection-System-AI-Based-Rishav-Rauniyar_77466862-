#!/usr/bin/env python
"""
IDS System - Quick Start Setup Guide
This script verifies all dependencies and initializes the IDS system.
"""

import sys
import subprocess

def check_pip_packages():
    """Check if required packages are installed."""
    required_packages = {
        'flask': 'Flask',
        'sklearn': 'scikit-learn',
        'numpy': 'numpy',
        'pandas': 'pandas'
    }
    
    missing = []
    installed = []
    
    for import_name, pip_name in required_packages.items():
        try:
            __import__(import_name)
            installed.append(pip_name)
        except ImportError:
            missing.append(pip_name)
    
    return installed, missing

def install_packages():
    """Install missing packages."""
    print("🔧 Installing required packages...\n")
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("\n✅ All packages installed successfully!\n")
        return True
    except subprocess.CalledProcessError:
        print("\n❌ Failed to install packages. Please run manually:")
        print("   pip install -r requirements.txt\n")
        return False

def initialize_database():
    """Initialize the database."""
    print("📊 Initializing database...\n")
    
    try:
        from database import init_db
        init_db()
        print("✅ Database initialized successfully!\n")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}\n")
        return False

def print_banner():
    """Print welcome banner."""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║         IDS SYSTEM - INTRUSION DETECTION SYSTEM             ║
    ║                Quick Start Setup Guide                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def print_usage():
    """Print usage instructions."""
    print("""
    ✅ SETUP COMPLETE! Your IDS system is ready to use.
    
    📍 NEXT STEPS:
    ─────────────────────────────────────────────────────────────
    
    1. Start the application:
       python app.py
    
    2. Open your browser:
       http://localhost:5000
    
    3. Dashboard Overview:
       • Dashboard Tab: Real-time statistics
       • Events Tab: Manual event creation & viewing
       • Models Tab: Train & deploy ML models
       • Traffic Tab: Collect & analyze network traffic
       • Logs Tab: View system activity
       • Export Tab: Download data for analysis
    
    📚 QUICK START WORKFLOW:
    ─────────────────────────────────────────────────────────────
    
    Step 1: Train Models
       • Go to "Models" tab
       • Click "🧠 Train Models"
       • Wait for completion
    
    Step 2: Deploy Model
       • Review model metrics
       • Click "Activate" on best model
    
    Step 3: Collect Traffic
       • Go to "Traffic" tab
       • Click "📡 Collect Traffic"
       • View network packets
    
    Step 4: Generate Events
       • Go to "Events" tab
       • Create events manually or wait for auto-detection
       • View detection results
    
    🎯 REQUIREMENTS MET:
    ─────────────────────────────────────────────────────────────
    ✅ Network traffic collection & processing
    ✅ Multiple ML models (Random Forest, Gradient Boosting, Isolation Forest)
    ✅ Performance metrics (F1-score, Accuracy, Precision, Recall)
    ✅ Best model selection & deployment
    ✅ Harmful activity logging
    ✅ Detection results UI with notifications
    ✅ Model performance visualization
    ✅ Network traffic analysis tools
    ✅ Data export (CSV, JSON, TXT)
    
    📖 DOCUMENTATION:
    ─────────────────────────────────────────────────────────────
    See README.md for detailed documentation
    
    🆘 TROUBLESHOOTING:
    ─────────────────────────────────────────────────────────────
    • If port 5000 is in use: Change port in app.py
    • For database issues: Delete ids_system.db and restart
    • For missing packages: pip install -r requirements.txt
    
    ═══════════════════════════════════════════════════════════════
    """)

if __name__ == '__main__':
    print_banner()
    
    # Check installed packages
    print("🔍 Checking installed packages...\n")
    installed, missing = check_pip_packages()
    
    if installed:
        print(f"   ✅ Found: {', '.join(installed)}")
    
    if missing:
        print(f"   ⚠️  Missing: {', '.join(missing)}\n")
        if not install_packages():
            sys.exit(1)
    else:
        print("   ✅ All packages already installed!\n")
    
    # Initialize database
    if not initialize_database():
        sys.exit(1)
    
    # Print usage guide
    print_usage()
    
    print("\n    Ready to start? Run: python app.py\n")
