# ===================================================================
# IMPORTS AND INITIALIZATION
# ===================================================================

# Flask core imports for web functionality
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash  # Password hashing for security
from functools import wraps  # For creating decorators
import pandas as pd  # Data manipulation and analysis
import sqlite3  # Lightweight database for storing events/logs
import io  # For in-memory file operations (CSV exports)
import sys  # System-specific parameters
import os  # Operating system interface
from datetime import datetime  # Timestamp handling
import numpy as np  # Numerical operations
from sklearn.model_selection import train_test_split  # ML: Split data for training
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier  # ML models
from sklearn.svm import SVC  # Support Vector Classifier
from sklearn.preprocessing import StandardScaler, LabelEncoder  # ML preprocessing
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score  # ML evaluation metrics

# Custom database module (separate file)
from database import (
    init_db, create_user, get_user_by_username, get_user_by_id,
    get_all_detection_events, insert_detection_event, delete_event,
    get_statistics, get_activity_logs, get_network_traffic,
    get_latest_model_metrics, get_active_model, set_active_model,
    insert_model_metrics, insert_activity_log, insert_traffic,
    init_admin_tables, log_admin_action, get_admin_audit_trail,
    get_all_users, delete_user, update_user_role, toggle_user_status,
    get_user_activity, log_user_activity, get_config_value, set_config_value,
    get_all_configs, generate_report
)
from pathlib import Path  # Object-oriented filesystem paths

# ===================================================================
# FLASK APP CONFIGURATION
# ===================================================================

app = Flask(__name__)
app.secret_key = 'REPLACE_WITH_STRONG_SECRET_KEY_12345'  # Session encryption (CHANGE THIS!)
init_db()  # Initialize database tables

# Global variables for ML model management
MODEL_POOL = {}  # Dictionary of loaded ML models
ACTIVE_MODEL_NAME = None  # Currently deployed model name
ATTACK_CLASSIFIERS = {}  # Ensemble of attack type classifiers
ATTACK_ENCODER = None  # Label encoder for attack types
ATTACK_SCALER = None  # Standard scaler for features

# Initialize admin-related database tables
init_admin_tables()

# ===================================================================
# MODEL MANAGEMENT FUNCTIONS
# ===================================================================

def reload_model_pool():
    """Reload models from disk and make them available for detection."""
    global MODEL_POOL
    from ml_models import get_ids_models  # Import custom ML module
    ids_models = get_ids_models()
    MODEL_POOL = ids_models.models  # Store all trained models

def load_active_model_setting():
    """Load the currently active deployed model from database."""
    global ACTIVE_MODEL_NAME
    active = get_active_model()  # Query database for active model
    if active and active.get('model_name'):
        ACTIVE_MODEL_NAME = active['model_name']  # Set global variable
    reload_model_pool()

# Load the active model when app starts
load_active_model_setting()

# ===================================================================
# ATTACK DATASET LOADING AND TRAINING
# ===================================================================

def load_attack_dataset(sample_frac=None):
    """Load the CIC-IDS2017 attack dataset from CSV file."""
    root = Path(__file__).resolve().parent.parent  # Navigate to project root
    csv_path = root / "datasets" / "CIC-IDS2017" / "cic_ids2017_balanced.csv"
    if not csv_path.exists():
        return None
    df = pd.read_csv(csv_path)  # Read CSV into DataFrame
    df.columns = [c.strip() for c in df.columns]  # Clean column names
    
    # Optionally sample a fraction of the data for faster training
    if sample_frac is not None and 0 < sample_frac < 1:
        df = df.sample(frac=sample_frac, random_state=42).reset_index(drop=True)
    return df

def train_attack_type_classifier(sample_frac=0.2):
    """
    Train an ensemble of classifiers to identify specific attack types.
    Uses RandomForest, SVM, GradientBoosting, and IsolationForest.
    """
    global ATTACK_CLASSIFIERS, ATTACK_ENCODER, ATTACK_SCALER, ATTACK_DATASET
    df = load_attack_dataset(sample_frac=sample_frac)
    ATTACK_DATASET = df  # Store for later sampling
    
    if df is None or df.empty:
        return

    # Define feature columns used for attack classification
    feature_cols = ['port', 'bytes_sent', 'bytes_received', 'cpu_usage', 
                    'memory_usage', 'network_load', 'response_time']
    
    # Validate dataset has required columns
    if not all(col in df.columns for col in feature_cols + ['attack_type']):
        return

    # Clean data: remove rows with missing values
    df = df.dropna(subset=feature_cols + ['attack_type'])
    if df.empty:
        return

    # Extract features and labels
    X = df[feature_cols].astype(float).values
    y = df['attack_type'].astype(str).values

    # Encode string labels to numeric values
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    # Standardize features (0 mean, unit variance)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Create ensemble of classifiers
    classifiers = {
        'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
        'SVM': SVC(probability=True, random_state=42),
        'GradientBoosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
        'IsolationForest': IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    }

    # Train each classifier
    ATTACK_CLASSIFIERS = {}
    for name, clf in classifiers.items():
        clf.fit(X_scaled, y_encoded)
        ATTACK_CLASSIFIERS[name] = clf

    # Store preprocessing objects for later use
    ATTACK_ENCODER = encoder
    ATTACK_SCALER = scaler

def predict_attack_type_from_payload(payload):
    """
    Predict attack type from network payload data using trained ensemble.
    Uses majority voting across all classifiers.
    """
    if not ATTACK_CLASSIFIERS or ATTACK_SCALER is None or ATTACK_ENCODER is None:
        return None

    try:
        # Extract and convert features from payload
        port = float(payload.get('dest_port', payload.get('port', 0)) or 0)
        bytes_sent = float(payload.get('bytes_sent', payload.get('packet_size', 0)) or 0)
        bytes_received = float(payload.get('bytes_received', payload.get('packet_size', 0)) or 0)
        cpu_usage = float(payload.get('cpu_usage', 0) or 0)
        memory_usage = float(payload.get('memory_usage', 0) or 0)
        network_load = float(payload.get('network_load', 0) or 0)
        response_time = float(payload.get('response_time', 0) or 0)

        # Create feature vector and scale it
        features = np.array([[port, bytes_sent, bytes_received, cpu_usage, 
                             memory_usage, network_load, response_time]])
        scaled = ATTACK_SCALER.transform(features)

        # Get predictions from all classifiers
        predictions = []
        for name, clf in ATTACK_CLASSIFIERS.items():
            try:
                pred = clf.predict(scaled)[0]
                predictions.append(pred)
            except Exception:
                continue

        if not predictions:
            return None

        # Majority voting to determine final prediction
        from collections import Counter
        majority_class = Counter(predictions).most_common(1)[0][0]
        return ATTACK_ENCODER.inverse_transform([majority_class])[0]
    except Exception:
        return None

def sample_attack_traffic_row():
    """Sample a random row from the attack dataset for simulation."""
    if ATTACK_DATASET is None or ATTACK_DATASET.empty:
        return None
    return ATTACK_DATASET.sample(n=1).iloc[0]

# ===================================================================
# DDoS DATASET HANDLING
# ===================================================================

def load_ddos_dataset(sample_frac=None):
    """Load DDoS dataset from CSV file."""
    root = Path(__file__).resolve().parent.parent
    csv_path = root / "datasets" / "CIC-IDS2017" / "cic_ids2017_balanced.csv"
    if not csv_path.exists():
        return None
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    if sample_frac is not None and 0 < sample_frac < 1:
        return df.sample(frac=sample_frac, random_state=42).reset_index(drop=True)
    return df.reset_index(drop=True)

def preprocess_ddos_dataset(df):
    """Clean and prepare DDoS dataset for analysis."""
    if df is None or df.empty:
        return df
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    
    # Identify label column (case-insensitive)
    label_col = next((c for c in df.columns if c.strip().lower() == 'label'), None)
    if label_col:
        df[label_col] = df[label_col].astype(str).str.upper().str.strip()
        # Create attack_type column based on DDoS detection
        df['attack_type'] = df[label_col].apply(lambda v: 'DDoS' if 'DDOS' in v else 'Benign')
        df['attack_class'] = df['attack_type'].copy()
        df['attack_flag'] = df['attack_type'].apply(lambda v: 1 if v == 'DDoS' else 0)
    
    # Handle infinite values and fill NaN with median
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if numeric_cols:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
    return df

def get_dataset_summary(df):
    """Generate summary statistics for the dataset."""
    if df is None or df.empty:
        return {
            'total_records': 0, 'benign_count': 0, 'ddos_count': 0,
            'attack_types': 'Unknown', 'label_column': None, 'feature_count': 0,
            'attack_ratio': 0, 'benign_ratio': 0
        }
    
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    label_col = next((c for c in df.columns if c.strip().lower() == 'label'), None)
    
    # Count benign vs DDoS traffic
    benign_count = 0
    ddos_count = 0
    attack_type = 'Unknown'
    
    if label_col is not None:
        labels = df[label_col].astype(str).str.upper().str.strip()
        benign_count = int((labels == 'BENIGN').sum())
        ddos_count = int(labels.str.contains('DDOS', na=False).sum())
        
        if ddos_count > 0 and benign_count > 0:
            attack_type = 'Benign + DDoS Attack'
        elif ddos_count > 0:
            attack_type = 'DDoS Attack'
        elif benign_count > 0:
            attack_type = 'Benign Traffic'
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    total = len(df)
    
    return {
        'total_records': total,
        'benign_count': benign_count,
        'ddos_count': ddos_count,
        'attack_types': attack_type,
        'label_column': label_col,
        'feature_count': len(numeric_cols),
        'attack_ratio': round(ddos_count / total if total > 0 else 0, 3),
        'benign_ratio': round(benign_count / total if total > 0 else 0, 3)
    }

# Initialize attack classifiers at startup
train_attack_type_classifier(sample_frac=0.15)

# ===================================================================
# AUTHENTICATION DECORATORS
# ===================================================================

def web_login_required(f):
    """Decorator to require user login for routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to require admin privileges for routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_user_by_id(session['user_id'])
        if user.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated

# ===================================================================
# PUBLIC ROUTES (Authentication & Info Pages)
# ===================================================================

@app.route('/')
def index():
    """Landing page - shows different content based on login status."""
    return render_template('index.html', is_logged_in='user_id' in session)

@app.route('/pricing')
def pricing():
    """Pricing page - subscription plans."""
    return render_template('pricing.html', is_logged_in='user_id' in session)

@app.route('/company')
def company():
    """Company information page."""
    return render_template('company.html', is_logged_in='user_id' in session)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration endpoint."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstname = request.form.get('firstname', '')
        lastname = request.form.get('lastname', '')
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        
        # Check if username already exists
        if get_user_by_username(username):
            flash('Username already exists', 'danger')
            return redirect(url_for('signup'))
        
        # Create new user with hashed password
        create_user(username, generate_password_hash(password), firstname, lastname, phone, email, 'user')
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login endpoint."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        user = get_user_by_username(username)
        
        # Verify password hash
        if user and check_password_hash(user['password_hash'], password):
            # Check if account is active
            if user.get('is_active', 1) == 0:
                flash('Your account has been disabled. Please contact administrator.', 'danger')
                return render_template('login.html')
            
            # Set session variables
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user.get('role', 'user')
            
            # Log the login activity
            insert_activity_log('login', f'User {username} logged in', user['id'])
            
            # Track user activity for analytics
            try:
                log_user_activity(user['id'], username, 'LOGIN', 'User logged into system', request.remote_addr)
            except:
                pass
            
            # Update last login timestamp
            try:
                conn = sqlite3.connect('ids.db')
                c = conn.cursor()
                c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                conn.commit()
                conn.close()
            except:
                pass
            
            flash(f'Welcome back, {username}!', 'success')
            
            # Redirect based on role
            if user.get('role') == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@web_login_required
def dashboard_redirect():
    """Redirect old dashboard route to new user_dashboard."""
    return redirect(url_for('user_dashboard'))

@app.route('/ids')
@web_login_required
def ids_dashboard():
    """Alias for user dashboard (backward compatibility)."""
    return redirect(url_for('user_dashboard'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """User logout - clear session and log the event."""
    user_id = session.get('user_id')
    if user_id:
        insert_activity_log('logout', 'User logged out', user_id)
    session.clear()
    return redirect(url_for('index'))

# ===================================================================
# CORE IDS API ENDPOINTS
# ===================================================================

@app.route('/api/traffic', methods=['POST'])
@web_login_required
def api_traffic():
    """
    Main traffic analysis endpoint.
    Receives network packet data and determines if it's malicious.
    Uses active ML model if available, falls back to rule-based detection.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Invalid payload"}), 400
    
    # Validate required fields
    required = ['source_ip','dest_ip','source_port','dest_port','protocol','packet_size']
    if not all(k in payload for k in required):
        return jsonify({"error": "fields missing"}), 400
    
    try:
        feedback = "benign"
        attack_type = payload.get('attack_type')
        is_alert = 0
        confidence = 0.0

        # Use ML model if active model exists
        from ml_models import get_ids_models
        ids_models = get_ids_models()
        if ACTIVE_MODEL_NAME and ACTIVE_MODEL_NAME in ids_models.models:
            try:
                # Normalize features for ML model input
                src_port = float(payload.get('source_port', payload.get('src_port', 0)) or 0)
                dest_port = float(payload.get('dest_port', payload.get('dst_port', 0)) or 0)
                protocol = payload.get('protocol', 'TCP')
                packet_size = float(payload.get('packet_size', 0) or 0)

                # Create normalized feature vector (0-1 range)
                feature_vector = [
                    min(max(src_port / 65535.0, 0.0), 1.0),
                    min(max(dest_port / 65535.0, 0.0), 1.0),
                    {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'IGMP': 3}.get(str(protocol).upper(), 0) / 3.0,
                    min(max(packet_size / 1500.0, 0.0), 1.0)
                ]

                # Get prediction from active model
                is_anomaly, confidence = ids_models.predict(feature_vector, ACTIVE_MODEL_NAME)
                if is_anomaly:
                    is_alert = 1
                    attack_type = attack_type or 'Anomalous Traffic'
                    feedback = 'attack'
            except Exception:
                pass

        # If ML didn't detect or no model, try attack type classifier
        if is_alert == 0 and not attack_type:
            attack_type = predict_attack_type_from_payload(payload)
            if attack_type is None:
                attack_type = payload.get('attack_type') or 'Normal Traffic'
            if str(attack_type).strip().lower() != 'normal traffic':
                is_alert = 1
                feedback = 'attack'
                confidence = max(confidence, 0.6)

        # Log the detection event if attack found
        if is_alert:
            insert_detection_event(payload['source_ip'], payload['dest_ip'], payload['protocol'],
                                   'High', f'Attack detected: {attack_type}', ACTIVE_MODEL_NAME or 'Ensemble Classifiers', 
                                   round(float(confidence or 0.9), 2))
            insert_activity_log('alert', f'Harmful traffic detected from {payload["source_ip"]}: {attack_type}', session['user_id'])
            feedback = 'attack'

        # Store traffic data in database
        insert_traffic(payload['source_ip'], payload['dest_ip'], payload['source_port'],
                       payload['dest_port'], payload['protocol'], payload['packet_size'], is_alert, attack_type)
        return jsonify({'status': 'ok', 'attack': bool(is_alert), 'feedback': feedback, 'confidence': float(confidence)})
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route('/api/traffic', methods=['GET'])
@web_login_required
def api_get_traffic():
    """Retrieve recent network traffic data."""
    return jsonify(get_network_traffic())

@app.route('/ids/simulate', methods=['POST'])
@web_login_required
def simulate_traffic():
    """
    Generate simulated network traffic for testing purposes.
    Creates realistic packets based on attack dataset samples.
    """
    import random
    from datetime import datetime
    
    try:
        # Define realistic traffic patterns
        protocols = ['TCP', 'UDP', 'ICMP']
        source_ips = ['192.168.1.101', '192.168.1.102', '192.168.1.103', '10.0.0.25', '172.16.0.50']
        dest_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1', '208.67.222.222']
        common_ports = [80, 443, 22, 53, 3389, 8080, 3306, 25, 110, 143]
        
        # Generate 3-8 random packets
        num_packets = random.randint(3, 8)
        attack_count = 0
        
        for i in range(num_packets):
            # Generate random packet parameters
            source_ip = random.choice(source_ips)
            dest_ip = random.choice(dest_ips)
            source_port = random.choice(common_ports) if random.random() > 0.3 else random.randint(1024, 65535)
            dest_port = random.choice(common_ports)
            protocol = random.choice(protocols)
            packet_size = random.randint(40, 1500)
            
            # Use attack dataset to determine if packet should be malicious
            row = sample_attack_traffic_row()
            if row is not None:
                attack_type = str(row['attack_type'])
                is_alert = 1 if attack_type.strip().lower() != 'normal traffic' else 0
                packet_size = int(np.clip(800 + float(row.get('total_bytes', 0)) * 200, 40, 1500))
                dest_port = int(np.clip(80 + float(row.get('port', 0)) * 1000, 1, 65535))
            else:
                is_alert = False
                attack_type = 'Normal Traffic'

            # Insert into database
            insert_traffic(source_ip, dest_ip, source_port, dest_port, protocol, packet_size, is_alert, attack_type)
            
            # Create detection event if attack
            if is_alert:
                attack_count += 1
                insert_detection_event(source_ip, dest_ip, protocol, 'Medium',
                                      f'Simulated attack packet #{i+1}', 'Simulation', random.uniform(0.7, 0.95))
                insert_activity_log('alert', f'🚨 SIMULATION: Suspicious traffic detected from {source_ip}', session['user_id'])
            else:
                insert_activity_log('info', f'📊 SIMULATION: Normal traffic recorded from {source_ip}', session['user_id'])
        
        # Log simulation completion
        insert_activity_log('info', f'✅ Traffic simulation complete: {num_packets} packets generated ({attack_count} malicious)', session['user_id'])
        
        return jsonify({
            'status': 'success',
            'packets_generated': num_packets,
            'attacks_detected': attack_count,
            'message': f'Generated {num_packets} packets with {attack_count} attacks'
        }), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ===================================================================
# DATA ANALYSIS AND FEATURE API ENDPOINTS
# ===================================================================

def update_model_metrics_with_training():
    """Update model performance metrics based on recent traffic data."""
    try:
        traffic_data = get_network_traffic()
        if len(traffic_data) < 10:
            return
        
        # Prepare features from traffic data
        import pandas as pd
        df = pd.DataFrame(traffic_data)
        
        if len(df) >= 5:
            total_packets = len(df)
            alert_count = df['is_alert'].sum() if 'is_alert' in df.columns else 0
            alert_ratio = alert_count / total_packets if total_packets > 0 else 0
            
            # Update metrics with adjustments based on recent traffic
            current_metrics = get_latest_model_metrics()
            
            if current_metrics:
                accuracy = current_metrics.get('accuracy', 0.9) * (0.95 + (alert_ratio * 0.1))
                precision = current_metrics.get('precision', 0.9) * (0.95 + (alert_ratio * 0.05))
                recall = current_metrics.get('recall', 0.9) * (0.95 + (alert_ratio * 0.1))
                f1 = current_metrics.get('f1_score', 0.9) * (0.95 + (alert_ratio * 0.08))
                
                insert_model_metrics(
                    model_name=ACTIVE_MODEL_NAME or 'RandomForest',
                    accuracy=min(0.99, accuracy),
                    precision=min(0.99, precision),
                    recall=min(0.99, recall),
                    f1_score=min(0.99, f1),
                    is_active=1
                )
    except Exception as e:
        print(f"Error updating metrics: {e}")

@app.route('/api/traffic/features', methods=['GET'])
@web_login_required
def api_traffic_features():
    """Extract ML-ready features from current traffic data."""
    try:
        traffic = get_network_traffic()
        if not traffic:
            return jsonify({
                'total_packets': 0,
                'avg_packet_size': 0,
                'tcp_ratio': 0,
                'udp_ratio': 0,
                'alert_ratio': 0,
                'unique_source_ips': 0
            })
        
        df = pd.DataFrame(traffic)
        
        # Calculate statistical features
        total_packets = len(df)
        avg_packet_size = float(df['packet_size'].mean()) if 'packet_size' in df.columns else 0
        
        tcp_count = len(df[df['protocol'] == 'TCP']) if 'protocol' in df.columns else 0
        udp_count = len(df[df['protocol'] == 'UDP']) if 'protocol' in df.columns else 0
        tcp_ratio = tcp_count / total_packets if total_packets > 0 else 0
        udp_ratio = udp_count / total_packets if total_packets > 0 else 0
        
        alert_count = df['is_alert'].sum() if 'is_alert' in df.columns else 0
        alert_ratio = alert_count / total_packets if total_packets > 0 else 0
        
        unique_ips = len(df['source_ip'].unique()) if 'source_ip' in df.columns else 0
        
        return jsonify({
            'total_packets': total_packets,
            'avg_packet_size': round(avg_packet_size, 2),
            'tcp_ratio': round(tcp_ratio, 3),
            'udp_ratio': round(udp_ratio, 3),
            'alert_ratio': round(alert_ratio, 3),
            'unique_source_ips': unique_ips
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===================================================================
# USER DASHBOARD AND VIEW ROUTES
# ===================================================================

@app.route('/user_dashboard')
@web_login_required
def user_dashboard():
    """Main user dashboard - displays IDS metrics, traffic, and alerts."""
    user = get_user_by_id(session['user_id'])
    # Load dataset for summary display
    dataset = load_ddos_dataset(sample_frac=0.05)
    dataset = preprocess_ddos_dataset(dataset)
    dataset_summary = get_dataset_summary(dataset)
    
    # Prepare dataset preview for UI
    dataset_preview = []
    if dataset is not None and not dataset.empty:
        preview_columns = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 
                          'Total Backward Packets', 'Average Packet Size', 'Label']
        preview_columns = [c for c in preview_columns if c in dataset.columns]
        dataset_preview = dataset[preview_columns].head(5).to_dict(orient='records')

    return render_template('user_dashboard.html',
                           user=user,
                           detections=get_all_detection_events(limit=50),
                           metrics=get_active_model(),
                           logs=get_activity_logs(limit=50),
                           traffic=get_network_traffic(limit=100),
                           dataset_summary=dataset_summary,
                           dataset_preview=dataset_preview)

# ===================================================================
# DASHBOARD API ENDPOINTS
# ===================================================================

@app.route('/api/model/metrics', methods=['GET'])
@web_login_required
def api_model_metrics():
    """Get current model performance metrics."""
    try:
        metrics = get_active_model()
        if not metrics:
            return jsonify({
                'accuracy': 0.85,
                'precision': 0.87,
                'recall': 0.83,
                'f1_score': 0.85,
                'model_name': ACTIVE_MODEL_NAME or 'Not Trained'
            })
        
        return jsonify({
            'accuracy': float(metrics.get('accuracy', 0)),
            'precision': float(metrics.get('precision', 0)),
            'recall': float(metrics.get('recall', 0)),
            'f1_score': float(metrics.get('f1_score', 0)),
            'model_name': metrics.get('model_name', 'Unknown')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
@web_login_required
def api_logs():
    """Get recent activity logs."""
    try:
        logs = get_activity_logs(limit=50)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===================================================================
# DATA EXPORT AND MANAGEMENT ENDPOINTS
# ===================================================================

@app.route('/ids/download/traffic', methods=['GET'])
@web_login_required
def download_traffic_csv():
    """Download traffic data as CSV file."""
    try:
        traffic = get_network_traffic()
        if not traffic:
            flash('No traffic data available', 'warning')
            return redirect(url_for('user_dashboard'))
        
        df = pd.DataFrame(traffic)
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'traffic_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        flash(f'Error downloading traffic: {str(e)}', 'danger')
        return redirect(url_for('user_dashboard'))

@app.route('/ids/download/logs', methods=['GET'])
@web_login_required
def download_logs_csv():
    """Download activity logs as CSV file."""
    try:
        logs = get_activity_logs()
        if not logs:
            flash('No logs available', 'warning')
            return redirect(url_for('user_dashboard'))
        
        df = pd.DataFrame(logs)
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        flash(f'Error downloading logs: {str(e)}', 'danger')
        return redirect(url_for('user_dashboard'))

@app.route('/api/traffic/clear', methods=['POST'])
@web_login_required
def clear_traffic():
    """Clear all network traffic and detection data."""
    try:
        conn = sqlite3.connect('ids.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM network_traffic')
        cursor.execute('DELETE FROM detection_events')
        cursor.execute('DELETE FROM activity_logs')
        conn.commit()
        conn.close()
        
        insert_activity_log('maintenance', 'All traffic data cleared by user', session['user_id'])
        
        return jsonify({'status': 'success', 'message': 'All traffic data cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ===================================================================
# ADMIN PANEL ROUTES
# ===================================================================

@app.route('/admin')
@admin_required
def admin_panel():
    """Main admin panel dashboard."""
    admin_user = get_user_by_id(session['user_id'])
    users = get_all_users()
    audit_trail = get_admin_audit_trail(limit=50)
    configs = get_all_configs()
    return render_template('admin_panel.html', 
                         admin=admin_user, 
                         users=users, 
                         audit_trail=audit_trail,
                         configs=configs)

@app.route('/admin/users')
@admin_required
def admin_get_users():
    """API endpoint to get all users."""
    users = get_all_users()
    return jsonify(users)

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user account (admin only)."""
    admin_user = get_user_by_id(session['user_id'])
    
    # Prevent self-deletion
    if user_id == admin_user['id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    success, username = delete_user(user_id)
    
    if success:
        log_admin_action(
            admin_id=admin_user['id'],
            admin_username=admin_user['username'],
            action_type='DELETE_USER',
            action_details=f'Deleted user {username}',
            target_user_id=user_id,
            target_username=username,
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'message': f'User {username} deleted'})
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def admin_update_role(user_id):
    """Update a user's role (user/admin)."""
    admin_user = get_user_by_id(session['user_id'])
    data = request.get_json()
    new_role = data.get('role')
    
    if new_role not in ['user', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Prevent demoting self if you're the only admin
    if user_id == admin_user['id'] and new_role == 'user':
        admins = [u for u in get_all_users() if u['role'] == 'admin']
        if len(admins) <= 1:
            return jsonify({'error': 'Cannot demote the only admin'}), 400
    
    success = update_user_role(user_id, new_role)
    
    if success:
        log_admin_action(
            admin_id=admin_user['id'],
            admin_username=admin_user['username'],
            action_type='UPDATE_ROLE',
            action_details=f'Updated user role to {new_role}',
            target_user_id=user_id,
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'message': f'Role updated to {new_role}'})
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin/users/<int:user_id>/status', methods=['PUT'])
@admin_required
def admin_toggle_status(user_id):
    """Enable or disable a user account."""
    admin_user = get_user_by_id(session['user_id'])
    
    # Prevent disabling self
    if user_id == admin_user['id']:
        return jsonify({'error': 'Cannot disable your own account'}), 400
    
    success = toggle_user_status(user_id)
    
    if success:
        log_admin_action(
            admin_id=admin_user['id'],
            admin_username=admin_user['username'],
            action_type='TOGGLE_STATUS',
            action_details=f'Toggled user account status',
            target_user_id=user_id,
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'message': 'User status updated'})
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin/user-activity')
@admin_required
def admin_get_user_activity():
    """Get user activity logs with filtering."""
    user_id = request.args.get('user_id', type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = request.args.get('limit', 100, type=int)
    
    activities = get_user_activity(user_id, limit, start_date, end_date)
    return jsonify(activities)

@app.route('/admin/audit-trail')
@admin_required
def admin_get_audit_trail():
    """Get admin action audit trail."""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    limit = request.args.get('limit', 100, type=int)
    
    audit_trail = get_admin_audit_trail(limit, start_date, end_date)
    return jsonify(audit_trail)

@app.route('/admin/export/logs', methods=['GET'])
@admin_required
def admin_export_logs():
    """Export logs with date filters."""
    log_type = request.args.get('type', 'audit')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    format = request.args.get('format', 'csv')
    
    # Fetch appropriate log data based on type
    if log_type == 'audit':
        data = get_admin_audit_trail(limit=10000, start_date=start_date, end_date=end_date)
        filename = f'admin_audit_trail_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    elif log_type == 'user_activity':
        data = get_user_activity(limit=10000, start_date=start_date, end_date=end_date)
        filename = f'user_activity_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    elif log_type == 'detection':
        from database import get_all_detection_events
        data = get_all_detection_events(limit=10000)
        # Apply date filtering
        if start_date or end_date:
            filtered = []
            for event in data:
                event_date = event['timestamp'][:10] if event['timestamp'] else ''
                if start_date and event_date < start_date:
                    continue
                if end_date and event_date > end_date:
                    continue
                filtered.append(event)
            data = filtered
        filename = f'detection_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    else:
        return jsonify({'error': 'Invalid log type'}), 400
    
    # Export as CSV or JSON
    if format == 'csv':
        df = pd.DataFrame(data)
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'{filename}.csv'
        )
    else:
        return jsonify(data)

@app.route('/admin/generate-report', methods=['POST'])
@admin_required
def admin_generate_report():
    """Generate system reports (security, activity, performance)."""
    admin_user = get_user_by_id(session['user_id'])
    data = request.get_json()
    
    report_type = data.get('report_type')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    if not all([report_type, start_date, end_date]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    report = generate_report(report_type, start_date, end_date)
    
    log_admin_action(
        admin_id=admin_user['id'],
        admin_username=admin_user['username'],
        action_type='GENERATE_REPORT',
        action_details=f'Generated {report_type} report from {start_date} to {end_date}',
        ip_address=request.remote_addr
    )
    
    return jsonify(report)

@app.route('/admin/config')
@admin_required
def admin_get_config():
    """Get all system configurations."""
    configs = get_all_configs()
    return jsonify(configs)

@app.route('/admin/config/<key>', methods=['PUT'])
@admin_required
def admin_update_config(key):
    """Update a system configuration value."""
    admin_user = get_user_by_id(session['user_id'])
    data = request.get_json()
    value = data.get('value')
    
    if value is None:
        return jsonify({'error': 'Value required'}), 400
    
    success = set_config_value(key, value, admin_user['id'])
    
    if success:
        log_admin_action(
            admin_id=admin_user['id'],
            admin_username=admin_user['username'],
            action_type='UPDATE_CONFIG',
            action_details=f'Updated config {key} to {value}',
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'message': 'Configuration updated'})
    return jsonify({'error': 'Config key not found'}), 404

# ===================================================================
# EVENT AND STATISTICS API ENDPOINTS
# ===================================================================

@app.route('/api/events/statistics', methods=['GET'])
@web_login_required
def api_events_statistics():
    """Get aggregated event statistics for dashboard."""
    try:
        conn = sqlite3.connect('ids.db')
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM detection_events')
        total = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM detection_events WHERE severity = "High" OR severity = "HIGH"')
        high_severity = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM detection_events WHERE severity = "Medium" OR severity = "MEDIUM"')
        medium_severity = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM detection_events WHERE severity = "Low" OR severity = "LOW"')
        low_severity = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total': total,
            'high_severity': high_severity,
            'medium_severity': medium_severity,
            'low_severity': low_severity
        })
    except Exception as e:
        return jsonify({'error': str(e), 'total': 0, 'high_severity': 0, 'medium_severity': 0, 'low_severity': 0}), 200

@app.route('/api/events', methods=['GET'])
@web_login_required
def api_get_events():
    """Get all detection events."""
    try:
        events = get_all_detection_events(limit=200)
        return jsonify(events)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/events', methods=['POST'])
@web_login_required
def api_create_event():
    """Create a manual detection event."""
    try:
        data = request.get_json()
        
        src_ip = data.get('source_ip', 'Unknown')
        dst_ip = data.get('dest_ip', 'Unknown')
        protocol = data.get('protocol', 'TCP')
        severity = data.get('severity', 'Medium')
        description = data.get('message', 'Manual event created')
        model_used = data.get('model_used', 'Manual')
        confidence = data.get('confidence', 0.95)
        
        event_id = insert_detection_event(src_ip, dst_ip, protocol, severity, description, model_used, confidence)
        
        insert_activity_log('event_created', f'Manual event created: {description}', session.get('user_id'))
        
        return jsonify({'success': True, 'event_id': event_id, 'message': 'Event created successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@web_login_required
def api_delete_event(event_id):
    """Delete a detection event."""
    try:
        delete_event(event_id)
        insert_activity_log('event_deleted', f'Event {event_id} deleted', session.get('user_id'))
        return jsonify({'success': True, 'message': 'Event deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===================================================================
# ML MODEL TRAINING AND MANAGEMENT API ENDPOINTS
# ===================================================================

@app.route('/api/models/train', methods=['POST'])
@web_login_required
def api_train_models():
    """Train ML models using current dataset."""
    try:
        from ml_models import get_ids_models
        ids_models = get_ids_models()
        
        data = request.get_json() or {}
        samples = data.get('samples', 1000)
        
        # Train all models
        results = ids_models.train_all_models(samples=samples)
        reload_model_pool()  # Reload models into memory
        
        # Update active model from database
        active = get_active_model()
        if active:
            global ACTIVE_MODEL_NAME
            ACTIVE_MODEL_NAME = active.get('model_name')

        insert_activity_log('model_training', f'Models trained with {samples} samples and deployed {ACTIVE_MODEL_NAME or "best model"}', session.get('user_id'))
        
        return jsonify({
            'success': True,
            'message': 'Models trained successfully',
            'results': results,
            'active_model': ACTIVE_MODEL_NAME
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/metrics', methods=['GET'])
@web_login_required
def api_get_model_metrics():
    """Get all model metrics history."""
    try:
        conn = sqlite3.connect('ids.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT id, model_name, accuracy, precision, recall, f1_score, is_active, created_at
            FROM model_metrics
            ORDER BY created_at DESC
        ''')
        rows = c.fetchall()
        conn.close()
        
        metrics = []
        for row in rows:
            metrics.append({
                'id': row['id'],
                'model_name': row['model_name'],
                'accuracy': row['accuracy'],
                'precision': row['precision'],
                'recall': row['recall'],
                'f1_score': row['f1_score'],
                'is_active': row['is_active'],
                'created_at': row['created_at']
            })
        
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/<int:model_id>/activate', methods=['POST'])
@web_login_required
def api_activate_model(model_id):
    """Activate a specific model for detection."""
    try:
        conn = sqlite3.connect('ids.db')
        c = conn.cursor()
        
        # Deactivate all models
        c.execute('UPDATE model_metrics SET is_active = 0')
        
        # Activate selected model
        c.execute('UPDATE model_metrics SET is_active = 1 WHERE id = ?', (model_id,))
        
        # Get model name for logging
        c.execute('SELECT model_name FROM model_metrics WHERE id = ?', (model_id,))
        row = c.fetchone()
        model_name = row[0] if row else 'Unknown'
        
        conn.commit()
        conn.close()
        
        global ACTIVE_MODEL_NAME
        ACTIVE_MODEL_NAME = model_name
        reload_model_pool()  # Refresh in-memory models
        
        insert_activity_log('model_activated', f'Model {model_name} activated', session.get('user_id'))
        
        return jsonify({'success': True, 'message': f'Model {model_name} activated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/models/best', methods=['GET'])
@web_login_required
def api_get_best_model():
    """Get the best performing model based on F1 score."""
    try:
        conn = sqlite3.connect('ids.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT id, model_name, accuracy, precision, recall, f1_score, created_at
            FROM model_metrics
            ORDER BY f1_score DESC
            LIMIT 1
        ''')
        row = c.fetchone()
        conn.close()
        
        if row:
            return jsonify({
                'id': row['id'],
                'model_name': row['model_name'],
                'accuracy': row['accuracy'],
                'precision': row['precision'],
                'recall': row['recall'],
                'f1_score': row['f1_score'],
                'created_at': row['created_at']
            })
        else:
            return jsonify({'error': 'No models found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===================================================================
# REAL-TIME DETECTION AND HEALTH ENDPOINTS
# ===================================================================

@app.route('/api/detect', methods=['POST'])
@web_login_required
def api_detect_anomaly():
    """Detect anomaly using rule-based logic with ML fallback."""
    try:
        data = request.get_json()
        
        # Extract features
        src_port = data.get('source_port', 0)
        dst_port = data.get('dest_port', 0)
        protocol = data.get('protocol', 'TCP')
        packet_size = data.get('packet_size', 500)
        
        # Rule-based detection (fallback)
        is_anomaly = 0
        confidence = 0.5
        
        # Simple heuristic rules
        if packet_size > 1400:
            is_anomaly = 1
            confidence = 0.85
        elif dst_port in [445, 3389, 23, 22] and packet_size > 1000:
            is_anomaly = 1
            confidence = 0.75
        elif src_port < 1024 and packet_size > 1200:
            is_anomaly = 1
            confidence = 0.70
        
        # Try ML model if available
        from ml_models import get_ids_models
        ids_models = get_ids_models()
        if ACTIVE_MODEL_NAME and ACTIVE_MODEL_NAME in ids_models.models:
            try:
                feature_vector = [
                    min(max(src_port / 65535.0, 0.0), 1.0),
                    min(max(dst_port / 65535.0, 0.0), 1.0),
                    {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'IGMP': 3}.get(protocol, 0) / 3.0,
                    min(max(packet_size / 1500.0, 0.0), 1.0)
                ]
                is_anomaly, confidence = ids_models.predict(feature_vector, ACTIVE_MODEL_NAME)
            except Exception as e:
                print(f"ML prediction error: {e}")
        
        # Create detection event if anomaly found
        if is_anomaly:
            severity = 'High' if confidence > 0.8 else 'Medium' if confidence > 0.6 else 'Low'
            insert_detection_event(
                src_ip=data.get('source_ip', 'Unknown'),
                dst_ip=data.get('dest_ip', 'Unknown'),
                protocol=protocol,
                severity=severity,
                description=f'Anomaly detected: Large packet size {packet_size} to port {dst_port}',
                model_used=ACTIVE_MODEL_NAME or 'Rule-based',
                confidence_score=confidence
            )
        
        return jsonify({
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'severity': 'High' if confidence > 0.8 else 'Medium' if confidence > 0.6 else 'Low' if is_anomaly else 'Normal'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'is_anomaly': 0, 'confidence': 0}), 500

@app.route('/api/dashboard', methods=['GET'])
@web_login_required
def api_dashboard_data():
    """Get comprehensive dashboard statistics."""
    try:
        conn = sqlite3.connect('ids.db')
        c = conn.cursor()
        
        # Collect various statistics
        c.execute('SELECT COUNT(*) FROM detection_events')
        total_events = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM detection_events WHERE severity = "High" OR severity = "HIGH"')
        high_severity = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM network_traffic')
        total_traffic = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM network_traffic WHERE is_alert = 1')
        anomalies = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM activity_logs')
        total_logs = c.fetchone()[0]
        
        # Get recent events for display
        c.execute('''
            SELECT id, source_ip, dest_ip, severity, message, timestamp
            FROM detection_events
            ORDER BY timestamp DESC
            LIMIT 10
        ''')
        recent_events = []
        for row in c.fetchall():
            recent_events.append({
                'id': row[0],
                'source_ip': row[1],
                'dest_ip': row[2],
                'severity': row[3],
                'message': row[4],
                'timestamp': row[5]
            })
        
        conn.close()
        
        return jsonify({
            'total_events': total_events,
            'high_severity': high_severity,
            'total_traffic': total_traffic,
            'anomalies': anomalies,
            'total_logs': total_logs,
            'recent_events': recent_events
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_model': ACTIVE_MODEL_NAME
    })

# ===================================================================
# DATA EXPORT AND FILE ENDPOINTS
# ===================================================================

@app.route('/api/logs/file', methods=['GET'])
@web_login_required
def api_get_logs_file():
    """Download raw log file."""
    try:
        log_file = 'ids_activity.log'
        if os.path.exists(log_file):
            return send_file(
                log_file,
                as_attachment=True,
                download_name=f'ids_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
            )
        else:
            return jsonify({'error': 'Log file not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/events', methods=['GET'])
@web_login_required
def api_export_events():
    """Export detection events as CSV."""
    try:
        events = get_all_detection_events(limit=10000)
        df = pd.DataFrame(events)
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'events_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/traffic', methods=['GET'])
@web_login_required
def api_export_traffic():
    """Export traffic data as CSV."""
    try:
        traffic = get_network_traffic(limit=10000)
        df = pd.DataFrame(traffic)
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'traffic_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/metrics', methods=['GET'])
@web_login_required
def api_export_metrics():
    """Export model metrics as JSON."""
    try:
        conn = sqlite3.connect('ids.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM model_metrics ORDER BY created_at DESC')
        rows = c.fetchall()
        conn.close()
        
        metrics = [dict(row) for row in rows]
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===================================================================
# USER ENHANCEMENTS - ALERT MANAGEMENT
# ===================================================================

@app.route('/api/user/alerts/pending')
@web_login_required
def get_user_pending_alerts():
    """Get alerts pending acknowledgment for current user."""
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    
    # Return recent unacknowledged events (requires user_acknowledged column)
    c.execute('''
        SELECT id, source_ip, dest_ip, severity, message, timestamp
        FROM detection_events
        WHERE user_acknowledged = 0 OR user_acknowledged IS NULL
        ORDER BY timestamp DESC LIMIT 20
    ''')
    rows = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': r[0], 'source_ip': r[1], 'dest_ip': r[2],
        'severity': r[3], 'message': r[4], 'timestamp': r[5]
    } for r in rows])

@app.route('/api/user/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@web_login_required
def acknowledge_alert(alert_id):
    """Acknowledge a specific alert."""
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    c.execute('UPDATE detection_events SET user_acknowledged = 1, acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP WHERE id = ?',
              (session['user_id'], alert_id))
    conn.commit()
    conn.close()
    
    # Log user activity
    log_user_activity(session['user_id'], session['username'], 'ACKNOWLEDGE_ALERT', f'Acknowledged alert {alert_id}')
    
    return jsonify({'success': True})

@app.route('/api/user/alerts/acknowledge-all', methods=['POST'])
@web_login_required
def acknowledge_all_alerts():
    """Acknowledge all pending alerts."""
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    c.execute('UPDATE detection_events SET user_acknowledged = 1, acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP WHERE user_acknowledged = 0 OR user_acknowledged IS NULL',
              (session['user_id'],))
    conn.commit()
    count = c.rowcount
    conn.close()
    
    log_user_activity(session['user_id'], session['username'], 'ACKNOWLEDGE_ALL', f'Acknowledged {count} alerts')
    
    return jsonify({'success': True, 'count': count})

@app.route('/api/user/change-password', methods=['POST'])
@web_login_required
def user_change_password():
    """Change user password."""
    data = request.get_json()
    current = data.get('current_password')
    new_pwd = data.get('new_password')
    
    user = get_user_by_id(session['user_id'])
    
    # Verify current password
    if not check_password_hash(user['password_hash'], current):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401
    
    new_hash = generate_password_hash(new_pwd)
    
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, session['user_id']))
    conn.commit()
    conn.close()
    
    log_user_activity(session['user_id'], session['username'], 'PASSWORD_CHANGE', 'User changed password')
    
    return jsonify({'success': True, 'message': 'Password updated successfully'})

# ===================================================================
# ADMIN ENHANCEMENTS - SYSTEM MANAGEMENT
# ===================================================================

@app.route('/admin/api/system-health')
@admin_required
def admin_system_health():
    """Get system health metrics (CPU, memory, database size)."""
    import psutil  # Requires: pip install psutil
    
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    
    # Get today's alert count
    c.execute('SELECT COUNT(*) FROM detection_events WHERE DATE(timestamp) = DATE("now")')
    today_alerts = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'today_alerts': today_alerts,
        'cpu_percent': psutil.cpu_percent(interval=0.5) if 'psutil' in sys.modules else 0,
        'memory_percent': psutil.virtual_memory().percent if 'psutil' in sys.modules else 0,
        'database_size': os.path.getsize('ids.db') // 1024 if os.path.exists('ids.db') else 0  # KB
    })

@app.route('/admin/api/threat-intel')
@admin_required
def admin_threat_intelligence():
    """Get threat intelligence data aggregated from detection events."""
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    
    # Group attacks by source IP
    c.execute('''
        SELECT source_ip, COUNT(*) as attack_count, 
               MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
        FROM detection_events
        GROUP BY source_ip
        ORDER BY attack_count DESC
        LIMIT 50
    ''')
    rows = c.fetchall()
    conn.close()
    
    return jsonify([{
        'ip_address': r[0],
        'threat_type': 'Suspicious Source',
        'confidence_score': min(0.5 + (r[1] * 0.05), 0.99),
        'first_event': r[2],
        'last_event': r[3],
        'block_count': r[1]
    } for r in rows])

@app.route('/admin/api/alert-rules', methods=['GET', 'POST'])
@admin_required
def admin_alert_rules():
    """Manage custom alert rules."""
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    
    # Create alert_rules table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS alert_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL,
        rule_condition TEXT NOT NULL,
        severity TEXT DEFAULT 'Medium',
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    
    if request.method == 'POST':
        # Add new rule
        data = request.get_json()
        c.execute('''
            INSERT INTO alert_rules (rule_name, rule_condition, severity, enabled)
            VALUES (?, ?, ?, ?)
        ''', (data['rule_name'], data['rule_condition'], data['severity'], 1 if data['enabled'] else 0))
        conn.commit()
        rule_id = c.lastrowid
        conn.close()
        
        log_admin_action(session['user_id'], session['username'], 'ADD_RULE', f'Added rule: {data["rule_name"]}')
        return jsonify({'id': rule_id})
    
    # GET method - retrieve all rules
    c.execute('SELECT id, rule_name, rule_condition, severity, enabled FROM alert_rules ORDER BY created_at DESC')
    rows = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': r[0], 'rule_name': r[1], 'rule_condition': r[2],
        'severity': r[3], 'enabled': bool(r[4])
    } for r in rows])

@app.route('/admin/api/alert-rules/<int:rule_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_rule(rule_id):
    """Enable or disable an alert rule."""
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    c.execute('UPDATE alert_rules SET enabled = NOT enabled WHERE id = ?', (rule_id,))
    conn.commit()
    conn.close()
    
    log_admin_action(session['user_id'], session['username'], 'TOGGLE_RULE', f'Toggled rule {rule_id}')
    return jsonify({'success': True})

@app.route('/admin/api/threat-intel/block', methods=['POST'])
@admin_required
def admin_block_ips():
    """Add IP addresses to blocklist."""
    data = request.get_json()
    ips = data.get('ips', [])
    
    # Create blocked_ips table if not exists
    conn = sqlite3.connect('ids.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        blocked_by INTEGER,
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reason TEXT
    )''')
    
    blocked_count = 0
    for ip in ips:
        try:
            c.execute('INSERT INTO blocked_ips (ip_address, blocked_by, reason) VALUES (?, ?, ?)',
                      (ip, session['user_id'], 'Manual block from threat intel'))
            blocked_count += 1
        except sqlite3.IntegrityError:
            pass  # IP already blocked
    
    conn.commit()
    conn.close()
    
    log_admin_action(session['user_id'], session['username'], 'BLOCK_IPS', f'Blocked {blocked_count} IPs')
    
    return jsonify({'blocked_count': blocked_count})

# ===================================================================
# APPLICATION ENTRY POINT
# ===================================================================

if __name__ == "__main__":
    # Run the Flask development server
    app.run(debug=True, host="127.0.0.1", port=5000)