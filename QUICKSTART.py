#!/usr/bin/env python
"""
IDS System - Quick Start Guide
Run this to get started immediately!
"""

print("""
╔════════════════════════════════════════════════════════════════════════╗
║                      IDS SYSTEM - QUICK START GUIDE                   ║
║               Intrusion Detection System with ML Models                ║
╚════════════════════════════════════════════════════════════════════════╝

🎯 YOUR SYSTEM IS READY TO USE!

Your Flask project now includes a complete IDS (Intrusion Detection System) with:
✅ Network traffic collection
✅ 3 ML models (Random Forest, Gradient Boosting, Isolation Forest)
✅ Full model evaluation metrics
✅ Real-time detection dashboard
✅ Activity logging system
✅ Data export capabilities

═══════════════════════════════════════════════════════════════════════════════

📦 QUICK START (3 STEPS)

Step 1: Install Dependencies
─────────────────────────────
  Open terminal and run:
  
    cd flask_project\\flask_venv
    pip install -r requirements.txt
  
  This installs:
  • Flask (web framework)
  • scikit-learn (ML library)
  • numpy (numerical computing)
  • pandas (data processing)

Step 2: Start the Server
────────────────────────
  In the same terminal, run:
  
    python app.py
  
  You should see:
    * Running on http://localhost:5000
    * WARNING: This is a development server...

Step 3: Open Dashboard
──────────────────────
  Use your web browser and go to:
  
    http://localhost:5000
  
  You should see the IDS Dashboard!

═══════════════════════════════════════════════════════════════════════════════

🚀 FIRST TIME USAGE GUIDE

1️⃣  TRAIN ML MODELS (2-3 seconds)
   ─────────────────────────────
   • Click on "Models" tab
   • Click "🧠 Train Models" button
   • Wait for completion
   • You'll see 3 models with metrics:
     - F1-Score (overall performance)
     - Accuracy (correct predictions)
     - Precision (true positives)
     - Recall (detection rate)

2️⃣  DEPLOY BEST MODEL
   ──────────────────
   • Review the model metrics
   • Click "Activate" on the model with highest F1-Score
   • This model is now active for detection!

3️⃣  COLLECT NETWORK TRAFFIC
   ────────────────────────
   • Go to "Traffic" tab
   • Click "📡 Collect Traffic"
   • System simulates 20 network packets
   • View packet details in the table

4️⃣  CREATE DETECTION EVENTS
   ──────────────────────────
   • Go to "Events" tab
   • Use the form to create events manually:
     - Source IP: 192.168.1.100
     - Dest IP: 10.0.0.1
     - Severity: high/medium/low
     - Message: Description of event
   • Click "Add Event"
   • Event appears in the table with detection info

5️⃣  VIEW DASHBOARD
   ──────────────
   • Go to "Dashboard" tab
   • See real-time statistics:
     - Total Events
     - High Severity Count
     - Network Packets
     - Anomalies Detected
   • View recent events and active model info

6️⃣  EXPORT DATA
   ───────────
   • Go to "Export" tab
   • Download in multiple formats:
     📥 Events as CSV
     📥 Traffic as CSV
     📥 Metrics as JSON
     📥 Logs as TXT
   • Use for further analysis!

═══════════════════════════════════════════════════════════════════════════════

📊 UNDERSTANDING THE DASHBOARD

Dashboard Tab:
  • Real-time overview of the system
  • Statistics cards showing current state
  • Recent events list
  • Active ML model information

Events Tab:
  • Create manual test events
  • View all detection events with full details
  • Search and filter events
  • Delete events as needed

Models Tab:
  • Train new ML models
  • View performance metrics for each model
  • Compare F1-scores, accuracy, precision, recall
  • Activate the best performing model

Traffic Tab:
  • Collect network traffic samples
  • View traffic summary statistics
  • Filter by protocol (TCP, UDP, ICMP, IGMP)
  • Identify anomalous packets

Logs Tab:
  • View system activity logs
  • Track security events
  • Filter by severity
  • Download full log file

Export Tab:
  • Export detection events (CSV)
  • Export network traffic (CSV)
  • Export model metrics (JSON)
  • Export activity logs (TXT)

═══════════════════════════════════════════════════════════════════════════════

🔍 API ENDPOINTS (For Integration)

Network Traffic:
  POST   /api/traffic/collect         - Collect traffic
  GET    /api/traffic                 - Get all traffic

ML Models:
  POST   /api/models/train            - Train models
  GET    /api/models/metrics          - Get metrics
  POST   /api/models/<id>/activate    - Deploy model
  GET    /api/models/best             - Get best model

Detection:
  POST   /api/detect                  - Detect anomaly
  GET    /api/events                  - Get events
  POST   /api/events                  - Create event
  DELETE /api/events/<id>             - Delete event

Logging:
  GET    /api/logs                    - Get logs
  GET    /api/logs/file               - Download logs

Export:
  GET    /api/export/events           - Export events CSV
  GET    /api/export/traffic          - Export traffic CSV
  GET    /api/export/metrics          - Export metrics JSON

Dashboard:
  GET    /api/dashboard               - Get dashboard data
  GET    /api/health                  - Health check

═══════════════════════════════════════════════════════════════════════════════

🎓 EXAMPLE WORKFLOW

1. Open http://localhost:5000
2. Go to Models → Click "Train Models" → Wait 3 seconds
3. Review metrics, click "Activate" on best model
4. Go to Traffic → Click "Collect Traffic"
5. Go to Events → Create event or use manual form
6. Go to Dashboard → See real-time stats
7. Go to Export → Download data

═══════════════════════════════════════════════════════════════════════════════

❓ FREQUENTLY ASKED QUESTIONS

Q: What ports does it use?
A: Default port 5000. If busy, edit app.py and change port=5000 to port=8000

Q: Can I access from other machines?
A: Yes! Visit http://<your_ip>:5000 from another machine

Q: Is my data saved?
A: Yes! SQLite database (ids_system.db) saves all data locally

Q: How accurate are the models?
A: Training on synthetic data (90%+ accuracy). Use real data in production.

Q: How do I stop the server?
A: Press Ctrl+C in the terminal

Q: Can I use real network traffic?
A: Yes, modify network_traffic.py to capture real packets (requires libpcap)

Q: How do I reset the database?
A: Delete ids_system.db file and restart the application

═══════════════════════════════════════════════════════════════════════════════

📚 DOCUMENTATION FILES

README.md
  → Complete technical documentation
  → All API endpoints explained
  → Database schema details
  → Troubleshooting guide

IMPLEMENTATION_SUMMARY.md
  → Feature mapping to requirements
  → Component descriptions
  → Data flow diagrams
  → Code examples

═══════════════════════════════════════════════════════════════════════════════

🆘 TROUBLESHOOTING

Port 5000 in use?
  Edit app.py, change:   port=5000  →  port=8000

Database errors?
  Delete ids_system.db and restart application

Missing packages?
  Run: pip install -r requirements.txt

Models not training?
  Check Python console for error messages

UI not loading?
  Open browser console (F12) and check for JavaScript errors

═══════════════════════════════════════════════════════════════════════════════

✨ KEY FEATURES IMPLEMENTED

✅ Network Traffic Collection
   • Simulates realistic network packets
   • Stores in SQLite database
   • Extracts ML-ready features

✅ Machine Learning Models
   • Random Forest (100 trees)
   • Gradient Boosting (100 iterations)
   • Isolation Forest (unsupervised)

✅ Model Evaluation
   • F1-Score (harmonic mean)
   • Accuracy (overall correctness)
   • Precision (false alarm rate)
   • Recall (detection rate)

✅ Real-time Detection
   • Ensemble voting (3 models)
   • Confidence scoring
   • Severity classification

✅ Comprehensive Logging
   • Intrusion attempts
   • Anomalies detected
   • Port scans
   • DDoS activity
   • Brute force attempts
   • Malware detection
   • Data exfiltration

✅ Data Export
   • CSV format (events, traffic)
   • JSON format (metrics)
   • TXT format (logs)
   • Batch downloads

═══════════════════════════════════════════════════════════════════════════════

🎯 READY TO START?

Run this command now:

    python app.py

Then visit: http://localhost:5000

═══════════════════════════════════════════════════════════════════════════════

For detailed documentation, see:
  • README.md - Full documentation
  • IMPLEMENTATION_SUMMARY.md - Requirements mapping
  
Questions? Check the troubleshooting section above!

Happy Intrusion Detecting! 🛡️

═══════════════════════════════════════════════════════════════════════════════
""")

if __name__ == '__main__':
    import sys
    print("\nTo start the server, run: python app.py\n")
