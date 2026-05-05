# IDS System - Intrusion Detection System

A comprehensive Machine Learning-based Intrusion Detection System (IDS) built with Flask, scikit-learn, and SQLite.

## Features & Requirements Implementation

### ✅ MUST HAVE (M) - Implemented
- **Collect and process network traffic for database**: Network traffic collection module simulates traffic capture with full database integration
- **Create and test several machine learning models**: Three ML models implemented:
  - Random Forest Classifier
  - Gradient Boosting Classifier
  - Isolation Forest (Unsupervised)
- **Evaluate models using F1-score, accuracy, precision and recall**: Full metrics evaluation and storage in database
- **Select and deploy the best performing model**: Model activation endpoint with best-model selection based on F1-score
- **Track logs of any harmful activities**: Comprehensive activity logging system with severity levels

### ✅ SHOULD HAVE (S) - Implemented
- **UI for showing detection results and notification information**: Multi-tab dashboard with real-time updates
- **Display model performance metrics and network traffic information**: Dedicated Models tab showing metrics comparison

### ✅ COULD HAVE (C) - Implemented
- **Function for downloading data and records for further analysis**: Export endpoints for Events (CSV), Traffic (CSV), Metrics (JSON), and Logs (TXT)

### ✅ WILL NOT (W) - Excluded as requested
- No IoT Device integration
- No complex networking/traffic blocking implementation

## Project Structure

```
flask_venv/
├── app.py                 # Main Flask application with all API endpoints
├── database.py           # SQLite database management
├── network_traffic.py    # Network traffic simulation and collection
├── ml_models.py          # ML model training and evaluation
├── logging_handler.py    # Activity logging system
├── templates/
│   └── ids.html          # Multi-tab dashboard UI
├── static/
│   └── css/
│       └── ids.css       # Enhanced styling
├── requirements.txt      # Python dependencies
└── ids_system.db         # SQLite database (auto-created)
```

## Installation & Setup

### 1. Install Dependencies
```bash
cd flask_project/flask_venv
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```

The application will start on `http://localhost:5000`

## API Endpoints

### Network Traffic
- `POST /api/traffic/collect` - Collect network traffic samples
- `GET /api/traffic` - Get all network traffic records

### ML Models
- `POST /api/models/train` - Train all IDS models
- `GET /api/models/metrics` - Get model performance metrics
- `POST /api/models/<id>/activate` - Set a model as active
- `GET /api/models/best` - Get best performing model

### Detection
- `POST /api/detect` - Detect anomalies using active model

### Events
- `GET /api/events` - Get all detection events
- `POST /api/events` - Create manual event
- `DELETE /api/events/<id>` - Delete an event
- `GET /api/events/statistics` - Get event statistics

### Logging
- `GET /api/logs` - Get activity logs
- `GET /api/logs/file` - Download logs file

### Data Export
- `GET /api/export/events` - Export events as CSV
- `GET /api/export/traffic` - Export traffic as CSV
- `GET /api/export/metrics` - Export metrics as JSON

### Dashboard
- `GET /api/dashboard` - Get comprehensive dashboard data
- `GET /api/health` - Health check

## Dashboard Tabs

### 1. **Dashboard**
Real-time overview with:
- Total detection events
- High severity count
- Network packets collected
- Detected anomalies
- Recent events list
- Active model information

### 2. **Detection Events**
- View all detection events in table format
- Add manual events for testing
- Search/filter events
- Delete events
- See model used and confidence scores

### 3. **ML Models**
- Train models with configurable batch size
- View performance metrics for all models:
  - F1-Score
  - Accuracy
  - Precision
  - Recall
- Activate best performing model
- Deploy model for production use

### 4. **Network Traffic**
- Collect network traffic samples
- View traffic analysis summary
- Filter by protocol (TCP, UDP, ICMP, IGMP)
- Identify anomalies
- Table view with detailed packet information

### 5. **Activity Logs**
- View system activity logs
- Track security events and model deployments
- Filter by severity level
- Export logs for analysis

### 6. **Data Export**
Download data for further analysis:
- Detection Events (CSV)
- Network Traffic (CSV)
- Model Metrics (JSON)
- Activity Logs (TXT)

## ML Models Details

### Random Forest Classifier
- Ensemble tree-based model
- 100 estimators
- Handles non-linear patterns
- Strong baseline performance

### Gradient Boosting Classifier
- Sequential ensemble learning
- 100 estimators
- High accuracy on complex patterns
- Optimal for binary classification

### Isolation Forest
- Unsupervised anomaly detection
- Contamination rate: 15%
- Identifies outliers effectively
- No labels required during detection

## Feature Engineering

Traffic features extracted for ML models:
- Source Port (normalized 0-1)
- Destination Port (normalized 0-1)
- Protocol Type (0-3 normalized)
- Packet Size (normalized 0-1)

## Database Schema

### network_traffic
- Stores collected network packets
- Timestamp, IPs, ports, protocol, payload, anomaly flag

### detection_events
- Stores all detection results
- Source/dest IPs, severity, message, model used, confidence

### model_metrics
- Stores trained model performance
- Accuracy, precision, recall, F1-score, training samples

### activity_logs
- Tracks system events and security incidents
- Event type, severity, description, source IP

## Model Training

Models train on 1000 synthetic samples with 85% normal/15% anomalous split.

**To train models:**
1. Go to "Models" tab
2. Click "🧠 Train Models"
3. Wait for completion (~3-5 seconds)
4. View metrics and select best model
5. Click "Activate" to deploy

## Detection Workflow

1. Network traffic is collected
2. Features are extracted
3. Ensemble prediction made across all models (voting)
4. Anomaly score calculated
5. Severity level determined based on confidence
6. Event logged to database
7. Activity tracking recorded

## Performance Metrics

Models evaluated using:
- **Accuracy**: (TP + TN) / Total
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: 2 × (Precision × Recall) / (Precision + Recall)

## Data Export for Analysis

All export data includes:
- **Events CSV**: Timestamp, IPs, severity, message, confidence
- **Traffic CSV**: All collected packets with anomaly flags
- **Metrics JSON**: Model performance with timestamp
- **Logs TXT**: Formatted activity log entries

## Security Features

- Thread-safe database operations
- Model versioning and deployment tracking
- Comprehensive event logging
- Severity-based alert classification
- Ensemble voting for robust detection
- Confidence scoring on all predictions

## Future Enhancements

- Real network packet capture (requires libpcap)
- Advanced anomaly detection (LSTM, autoencoder)
- Real-time performance monitoring
- Model retraining automation
- Alert notifications (email, webhook)
- API authentication
- Web UI responsive design improvements

## Limitations

- Training on synthetic data (in production, use real network traffic)
- No actual network packet capture (uses simulation)
- Single-process execution (use production WSGI server)
- No distributed deployment (use containerization for scale)

## Requirements Met Summary

✅ Network traffic collection & processing
✅ Multiple ML models (RF, GB, IF)
✅ F1-score, accuracy, precision, recall metrics
✅ Best model selection & deployment
✅ Harmful activity logging
✅ Detection results UI
✅ Notification/information display
✅ Performance metrics visualization
✅ Network traffic information display
✅ Data download capability
❌ No IoT devices (as requested)
❌ No complex networking/safeguarding (as requested)

## Support

For issues or questions, check:
- Flask logs in terminal
- `ids_activity.log` file
- Browser console (F12)
- Database queries via `ids_system.db`
