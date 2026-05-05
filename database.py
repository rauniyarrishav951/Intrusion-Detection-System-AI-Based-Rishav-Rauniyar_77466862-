import sqlite3
from datetime import datetime

import json

DB_PATH = 'ids.db'

def get_db():
    """Get database connection with row_factory for dictionary access"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with all required tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        firstname TEXT DEFAULT '',
        lastname TEXT DEFAULT '',
        email TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Network traffic table
    c.execute('''CREATE TABLE IF NOT EXISTS network_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        dest_ip TEXT,
        source_port INTEGER,
        dest_port INTEGER,
        protocol TEXT,
        packet_size INTEGER,
        is_alert INTEGER DEFAULT 0,
        attack_type TEXT DEFAULT NULL
    )''')

    # Check if is_alert/attack_type columns exist in network_traffic (for backward compatibility)
    c.execute("PRAGMA table_info(network_traffic)")
    cols = [row[1] for row in c.fetchall()]
    if 'is_alert' not in cols:
        c.execute("ALTER TABLE network_traffic ADD COLUMN is_alert INTEGER DEFAULT 0")
    if 'attack_type' not in cols:
        c.execute("ALTER TABLE network_traffic ADD COLUMN attack_type TEXT DEFAULT NULL")

    # Detection events table
    c.execute('''CREATE TABLE IF NOT EXISTS detection_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT,
        model_used TEXT,
        confidence REAL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute("PRAGMA table_info(detection_events)")
    detection_cols = [row[1] for row in c.fetchall()]
    if 'user_acknowledged' not in detection_cols:
        c.execute('ALTER TABLE detection_events ADD COLUMN user_acknowledged INTEGER DEFAULT 0')
    if 'acknowledged_by' not in detection_cols:
        c.execute('ALTER TABLE detection_events ADD COLUMN acknowledged_by INTEGER DEFAULT NULL')
    if 'acknowledged_at' not in detection_cols:
        c.execute('ALTER TABLE detection_events ADD COLUMN acknowledged_at TIMESTAMP DEFAULT NULL')

    # Activity logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')

    # Model metrics table
    c.execute('''CREATE TABLE IF NOT EXISTS model_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT NOT NULL,
        accuracy REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        is_active INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()

def create_user(username, password_hash, firstname='', lastname='', phone='', email='', role='user'):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO users(username, password_hash, firstname, lastname, phone, email, role)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, firstname, lastname, phone, email, role))
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT id, username, password_hash, firstname, lastname, phone, role, email, is_active, last_login, created_at
                 FROM users WHERE username=?''', (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        'id': row[0],
        'username': row[1],
        'password_hash': row[2],
        'firstname': row[3],
        'lastname': row[4],
        'phone': row[5],
        'role': row[6],
        'email': row[7] if len(row) > 7 else '',
        'is_active': row[8] if len(row) > 8 else 1,
        'last_login': row[9] if len(row) > 9 else None,
        'created_at': row[10] if len(row) > 10 else None
    }

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT id, username, password_hash, firstname, lastname, phone, role, email, is_active, last_login, created_at
                 FROM users WHERE id=?''', (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        'id': row[0],
        'username': row[1],
        'password_hash': row[2],
        'firstname': row[3],
        'lastname': row[4],
        'phone': row[5],
        'role': row[6],
        'email': row[7] if len(row) > 7 else '',
        'is_active': row[8] if len(row) > 8 else 1,
        'last_login': row[9] if len(row) > 9 else None,
        'created_at': row[10] if len(row) > 10 else None
    }

def insert_traffic(source_ip, dest_ip, source_port, dest_port, protocol, packet_size, is_alert=0, attack_type=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO network_traffic(source_ip, dest_ip, source_port, dest_port, protocol, packet_size, is_alert, attack_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (source_ip, dest_ip, source_port, dest_port, protocol, packet_size, int(is_alert), attack_type))
    conn.commit()
    rowid = c.lastrowid
    conn.close()
    return rowid

def get_network_traffic(limit=200):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, is_alert, attack_type
        FROM network_traffic ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            'id': r[0], 
            'timestamp': r[1], 
            'source_ip': r[2], 
            'dest_ip': r[3],
            'source_port': r[4], 
            'dest_port': r[5], 
            'protocol': r[6], 
            'packet_size': r[7], 
            'is_alert': r[8],
            'attack_type': r[9]
        } for r in rows
    ]

def insert_activity_log(event_type, message, user_id=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO activity_logs(event_type, message, user_id)
        VALUES (?, ?, ?)
    ''', (event_type, message, user_id))
    conn.commit()
    last = c.lastrowid
    conn.close()
    return last

def get_activity_logs(limit=100):
    """Get recent activity logs with limit"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, timestamp, event_type, message, user_id
        FROM activity_logs 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            'id': r[0],
            'timestamp': r[1],
            'event_type': r[2],
            'message': r[3],
            'user_id': r[4]
        } for r in rows
    ]

def get_all_detection_events(limit=200):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, source_ip, dest_ip, protocol, severity, message, model_used, confidence, timestamp
        FROM detection_events
        ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            'id': r[0], 
            'source_ip': r[1], 
            'dest_ip': r[2], 
            'protocol': r[3],
            'severity': r[4], 
            'message': r[5], 
            'model_used': r[6],
            'confidence': r[7], 
            'timestamp': r[8]
        } for r in rows
    ]

def insert_detection_event(src_ip, dst_ip, protocol, severity, description, model_used, confidence_score):
    """Insert a detection event"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO detection_events(source_ip, dest_ip, protocol, severity, message, model_used, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, protocol, severity, description, model_used, confidence_score))
    conn.commit()
    rowid = c.lastrowid
    conn.close()
    return rowid

def delete_event(event_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM detection_events WHERE id=?', (event_id,))
    conn.commit()
    conn.close()

def get_statistics():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    users = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM network_traffic')
    traffic = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM detection_events')
    events = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM activity_logs')
    logs = c.fetchone()[0]
    conn.close()
    return {
        'total_users': users,
        'total_traffic': traffic,
        'total_detections': events,
        'total_logs': logs,
    }

def insert_model_metrics(model_name, accuracy, precision, recall, f1_score, is_active=0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO model_metrics (model_name, accuracy, precision, recall, f1_score, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (model_name, accuracy, precision, recall, f1_score, is_active))
    conn.commit()
    last = c.lastrowid
    conn.close()
    return last

def get_latest_model_metrics():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT model_name, accuracy, precision, recall, f1_score, created_at, is_active
        FROM model_metrics
        ORDER BY created_at DESC LIMIT 1
    ''')
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        'model_name': row[0],
        'accuracy': row[1],
        'precision': row[2],
        'recall': row[3],
        'f1_score': row[4],
        'created_at': row[5],
        'is_active': row[6]
    }

def get_active_model():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT model_name, accuracy, precision, recall, f1_score, created_at
        FROM model_metrics
        WHERE is_active = 1
        ORDER BY created_at DESC LIMIT 1
    ''')
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        'model_name': row[0],
        'accuracy': row[1],
        'precision': row[2],
        'recall': row[3],
        'f1_score': row[4],
        'created_at': row[5]
    }

def set_active_model(model_name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE model_metrics SET is_active = 0')
    c.execute('UPDATE model_metrics SET is_active = 1 WHERE model_name = ?', (model_name,))
    conn.commit()
    conn.close()

# Admin functions
def init_admin_tables():
    """Initialize admin-specific tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Admin actions audit trail
    c.execute('''CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        admin_username TEXT NOT NULL,
        action_type TEXT NOT NULL,
        action_details TEXT,
        target_user_id INTEGER,
        target_username TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # System configuration
    c.execute('''CREATE TABLE IF NOT EXISTS system_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_key TEXT UNIQUE NOT NULL,
        config_value TEXT,
        config_type TEXT DEFAULT 'string',
        description TEXT,
        updated_by INTEGER,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Insert default configurations
    default_configs = [
        ('model_confidence_threshold', '0.7', 'float', 'Minimum confidence score for alert generation'),
        ('alert_severity_high', '0.8', 'float', 'Confidence threshold for HIGH severity alerts'),
        ('alert_severity_medium', '0.5', 'float', 'Confidence threshold for MEDIUM severity alerts'),
        ('packet_size_threshold', '1400', 'int', 'Packet size threshold for anomaly detection'),
        ('max_alerts_per_minute', '100', 'int', 'Maximum alerts per minute to prevent flooding'),
        ('log_retention_days', '30', 'int', 'Number of days to retain logs'),
        ('auto_train_interval', '24', 'int', 'Hours between automatic model retraining'),
        ('enable_real_time_monitoring', 'true', 'boolean', 'Enable real-time packet monitoring')
    ]
    
    for key, value, config_type, desc in default_configs:
        c.execute('''
            INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description)
            VALUES (?, ?, ?, ?)
        ''', (key, value, config_type, desc))
    
    # User activity tracking table
    c.execute('''CREATE TABLE IF NOT EXISTS user_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        activity_details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    conn.commit()
    conn.close()
    print("Admin tables initialized successfully")

def log_admin_action(admin_id, admin_username, action_type, action_details, 
                     target_user_id=None, target_username=None, ip_address=None):
    """Log admin actions for audit trail"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO admin_audit_log (admin_id, admin_username, action_type, 
                                      action_details, target_user_id, target_username, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (admin_id, admin_username, action_type, action_details, 
          target_user_id, target_username, ip_address))
    conn.commit()
    log_id = c.lastrowid
    conn.close()
    return log_id

def get_admin_audit_trail(limit=100, start_date=None, end_date=None):
    """Get admin action audit trail with optional date filters"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    query = '''
        SELECT id, admin_id, admin_username, action_type, action_details,
               target_user_id, target_username, ip_address, timestamp
        FROM admin_audit_log
        WHERE 1=1
    '''
    params = []
    
    if start_date:
        query += ' AND DATE(timestamp) >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND DATE(timestamp) <= ?'
        params.append(end_date)
    
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    return [
        {
            'id': row[0],
            'admin_id': row[1],
            'admin_username': row[2],
            'action_type': row[3],
            'action_details': row[4],
            'target_user_id': row[5],
            'target_username': row[6],
            'ip_address': row[7],
            'timestamp': row[8]
        } for row in rows
    ]

def get_all_users():
    """Get all users for management"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''
        SELECT id, username, firstname, lastname, email, phone, role, 
               is_active, last_login, created_at
        FROM users
        ORDER BY created_at DESC
    ''')
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def delete_user(user_id):
    """Delete a user (admin only)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get user info before deletion
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if user:
        # Delete user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        # Delete their activity logs
        c.execute('DELETE FROM user_activity WHERE user_id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        return True, user[0]
    
    conn.close()
    return False, None

def update_user_role(user_id, new_role):
    """Update user role (user/admin)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    affected = c.rowcount
    conn.close()
    return affected > 0

def toggle_user_status(user_id):
    """Enable/disable user account"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET is_active = NOT is_active WHERE id = ?', (user_id,))
    conn.commit()
    affected = c.rowcount
    conn.close()
    return affected > 0

def get_user_activity(user_id=None, limit=100, start_date=None, end_date=None):
    """Get user activity logs"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    query = '''
        SELECT id, user_id, username, activity_type, activity_details, 
               ip_address, timestamp
        FROM user_activity
        WHERE 1=1
    '''
    params = []
    
    if user_id:
        query += ' AND user_id = ?'
        params.append(user_id)
    if start_date:
        query += ' AND DATE(timestamp) >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND DATE(timestamp) <= ?'
        params.append(end_date)
    
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    return [
        {
            'id': row[0],
            'user_id': row[1],
            'username': row[2],
            'activity_type': row[3],
            'activity_details': row[4],
            'ip_address': row[5],
            'timestamp': row[6]
        } for row in rows
    ]

def log_user_activity(user_id, username, activity_type, activity_details, ip_address=None):
    """Log user activity"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO user_activity (user_id, username, activity_type, activity_details, ip_address)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, username, activity_type, activity_details, ip_address))
    conn.commit()
    log_id = c.lastrowid
    conn.close()
    return log_id

def get_config_value(key, default=None):
    """Get system configuration value"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT config_value, config_type FROM system_config WHERE config_key = ?', (key,))
    row = c.fetchone()
    conn.close()
    
    if row:
        value, config_type = row
        if config_type == 'float':
            return float(value)
        elif config_type == 'int':
            return int(value)
        elif config_type == 'boolean':
            return value.lower() == 'true'
        return value
    return default

def set_config_value(key, value, admin_id=None):
    """Update system configuration"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Determine type
    if isinstance(value, bool):
        value_str = str(value).lower()
        config_type = 'boolean'
    elif isinstance(value, float):
        value_str = str(value)
        config_type = 'float'
    elif isinstance(value, int):
        value_str = str(value)
        config_type = 'int'
    else:
        value_str = str(value)
        config_type = 'string'
    
    c.execute('''
        UPDATE system_config 
        SET config_value = ?, config_type = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE config_key = ?
    ''', (value_str, config_type, admin_id, key))
    
    conn.commit()
    affected = c.rowcount
    conn.close()
    return affected > 0

def get_all_configs():
    """Get all system configurations"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT config_key, config_value, config_type, description, updated_at
        FROM system_config
        ORDER BY config_key
    ''')
    rows = c.fetchall()
    conn.close()
    
    configs = {}
    for row in rows:
        key, value, config_type, description, updated_at = row
        if config_type == 'float':
            value = float(value)
        elif config_type == 'int':
            value = int(value)
        elif config_type == 'boolean':
            value = value.lower() == 'true'
        configs[key] = {
            'value': value,
            'type': config_type,
            'description': description,
            'updated_at': updated_at
        }
    return configs

def generate_report(report_type, start_date, end_date):
    """Generate system reports"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    report_data = {
        'generated_at': datetime.now().isoformat(),
        'date_range': {'start': start_date, 'end': end_date},
        'report_type': report_type
    }
    
    if report_type == 'user_activity':
        # User activity summary
        c.execute('''
            SELECT username, COUNT(*) as activity_count
            FROM user_activity
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY username
            ORDER BY activity_count DESC
        ''', (start_date, end_date))
        report_data['user_activity_summary'] = [{'username': row[0], 'count': row[1]} for row in c.fetchall()]
        
        # Activity type breakdown
        c.execute('''
            SELECT activity_type, COUNT(*) as count
            FROM user_activity
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY activity_type
        ''', (start_date, end_date))
        report_data['activity_breakdown'] = [{'type': row[0], 'count': row[1]} for row in c.fetchall()]
    
    elif report_type == 'detection_summary':
        # Detection events summary
        c.execute('''
            SELECT severity, COUNT(*) as count
            FROM detection_events
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY severity
        ''', (start_date, end_date))
        report_data['detection_by_severity'] = [{'severity': row[0], 'count': row[1]} for row in c.fetchall()]
        
        # Top attack sources
        c.execute('''
            SELECT source_ip, COUNT(*) as attack_count
            FROM detection_events
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY source_ip
            ORDER BY attack_count DESC
            LIMIT 10
        ''', (start_date, end_date))
        report_data['top_attack_sources'] = [{'ip': row[0], 'count': row[1]} for row in c.fetchall()]
    
    elif report_type == 'system_health':
        # System health metrics
        c.execute('SELECT COUNT(*) FROM detection_events WHERE DATE(timestamp) BETWEEN ? AND ?', (start_date, end_date))
        total_alerts = c.fetchone()
        report_data['total_alerts'] = total_alerts[0] if total_alerts else 0
        
        c.execute('SELECT COUNT(*) FROM network_traffic WHERE DATE(timestamp) BETWEEN ? AND ?', (start_date, end_date))
        total_packets = c.fetchone()
        report_data['total_packets'] = total_packets[0] if total_packets else 0
        
        c.execute('SELECT COUNT(*) FROM user_activity WHERE DATE(timestamp) BETWEEN ? AND ?', (start_date, end_date))
        total_actions = c.fetchone()
        report_data['total_user_actions'] = total_actions[0] if total_actions else 0
        
        # Model performance
        c.execute('''
            SELECT model_name, accuracy, f1_score, created_at
            FROM model_metrics
            ORDER BY created_at DESC
            LIMIT 1
        ''')
        latest_model = c.fetchone()
        if latest_model:
            report_data['active_model'] = {
                'name': latest_model[0],
                'accuracy': latest_model[1],
                'f1_score': latest_model[2],
                'deployed_at': latest_model[3]
            }
    
    conn.close()
    return report_data