-- Schema for ids.db
-- Generated from sqlite_master

CREATE TABLE activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )

CREATE TABLE admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        admin_username TEXT NOT NULL,
        action_type TEXT NOT NULL,
        action_details TEXT,
        target_user_id INTEGER,
        target_username TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )

CREATE TABLE detection_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT,
        model_used TEXT,
        confidence REAL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )

CREATE TABLE model_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT NOT NULL,
        accuracy REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        is_active INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )

CREATE TABLE network_traffic (
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
    )

CREATE TABLE system_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_key TEXT UNIQUE NOT NULL,
        config_value TEXT,
        config_type TEXT DEFAULT 'string',
        description TEXT,
        updated_by INTEGER,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )

CREATE TABLE user_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        activity_details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )

CREATE TABLE users (
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
    )

