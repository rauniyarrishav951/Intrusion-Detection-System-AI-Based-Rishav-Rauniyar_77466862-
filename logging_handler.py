import os
from datetime import datetime
from database import insert_activity_log


class ActivityLogger:
    """Handles logging of security-related activities."""
    
    LOG_FILE = os.path.join(os.path.dirname(__file__), 'ids_activity.log')
    
    # Event severity levels
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'
    
    @staticmethod
    def log_intrusion_attempt(source_ip, dest_ip, attack_type, confidence):
        """Log an intrusion attempt."""
        severity = ActivityLogger._get_severity(confidence)
        description = f"Possible {attack_type} detected from {source_ip} to {dest_ip} (confidence: {confidence:.2f})"
        
        ActivityLogger._write_log(severity, description, source_ip)
        insert_activity_log(
            event_type='INTRUSION_ATTEMPT',
            severity=severity,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_model_deployment(model_name, f1_score):
        """Log model deployment."""
        description = f"Model '{model_name}' deployed to production (F1-Score: {f1_score:.4f})"
        
        ActivityLogger._write_log(ActivityLogger.INFO, description, '')
        insert_activity_log(
            event_type='MODEL_DEPLOYMENT',
            severity=ActivityLogger.INFO,
            description=description,
            source_ip=''
        )
    
    @staticmethod
    def log_anomaly_detected(source_ip, anomaly_type, details):
        """Log detected anomaly."""
        description = f"{anomaly_type}: {details}"
        
        ActivityLogger._write_log(ActivityLogger.HIGH, description, source_ip)
        insert_activity_log(
            event_type='ANOMALY_DETECTED',
            severity=ActivityLogger.HIGH,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_suspicious_traffic(source_ip, protocol, ports, reason):
        """Log suspicious traffic pattern."""
        description = f"Suspicious {protocol} traffic detected on ports {ports}: {reason}"
        
        ActivityLogger._write_log(ActivityLogger.MEDIUM, description, source_ip)
        insert_activity_log(
            event_type='SUSPICIOUS_TRAFFIC',
            severity=ActivityLogger.MEDIUM,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_port_scan(source_ip, port_range):
        """Log detected port scan."""
        severity = ActivityLogger.HIGH
        description = f"Port scan detected from {source_ip} on range {port_range}"
        
        ActivityLogger._write_log(severity, description, source_ip)
        insert_activity_log(
            event_type='PORT_SCAN',
            severity=severity,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_ddos_activity(source_ip, target_ip, packet_count):
        """Log DDoS activity."""
        severity = ActivityLogger.CRITICAL
        description = f"DDoS activity detected: {packet_count} packets from {source_ip} to {target_ip}"
        
        ActivityLogger._write_log(severity, description, source_ip)
        insert_activity_log(
            event_type='DDOS_ACTIVITY',
            severity=severity,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_brute_force_attempt(source_ip, service, attempts):
        """Log brute force attempt."""
        severity = ActivityLogger.HIGH
        description = f"Brute force attempt on {service}: {attempts} attempts from {source_ip}"
        
        ActivityLogger._write_log(severity, description, source_ip)
        insert_activity_log(
            event_type='BRUTE_FORCE',
            severity=severity,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_malware_signature(source_ip, signature, file_hash):
        """Log malware signature detection."""
        severity = ActivityLogger.CRITICAL
        description = f"Malware signature detected: {signature} (hash: {file_hash}) from {source_ip}"
        
        ActivityLogger._write_log(severity, description, source_ip)
        insert_activity_log(
            event_type='MALWARE_DETECTED',
            severity=severity,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_data_exfiltration(source_ip, dest_ip, data_volume):
        """Log suspicious data exfiltration."""
        severity = ActivityLogger.CRITICAL
        description = f"Data exfiltration detected: {data_volume} GB from {source_ip} to {dest_ip}"
        
        ActivityLogger._write_log(severity, description, source_ip)
        insert_activity_log(
            event_type='DATA_EXFILTRATION',
            severity=severity,
            description=description,
            source_ip=source_ip
        )
    
    @staticmethod
    def log_system_event(event_type, message):
        """Log system events."""
        ActivityLogger._write_log(ActivityLogger.INFO, message, '')
        insert_activity_log(
            event_type=event_type,
            severity=ActivityLogger.INFO,
            description=message,
            source_ip=''
        )
    
    @staticmethod
    def _get_severity(confidence):
        """Determine severity level based on confidence."""
        if confidence >= 0.9:
            return ActivityLogger.CRITICAL
        elif confidence >= 0.7:
            return ActivityLogger.HIGH
        elif confidence >= 0.5:
            return ActivityLogger.MEDIUM
        else:
            return ActivityLogger.LOW
    
    @staticmethod
    def _write_log(severity, message, source_ip):
        """Write log entry to file."""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {severity} | {source_ip} | {message}\n"
        
        try:
            with open(ActivityLogger.LOG_FILE, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write log: {e}")
    
    @staticmethod
    def get_logs(limit=100):
        """Read recent logs from file."""
        try:
            if not os.path.exists(ActivityLogger.LOG_FILE):
                return []
            
            with open(ActivityLogger.LOG_FILE, 'r') as f:
                lines = f.readlines()
            
            return lines[-limit:] if len(lines) > limit else lines
        except Exception as e:
            print(f"Failed to read logs: {e}")
            return []
    
    @staticmethod
    def clear_logs():
        """Clear log file."""
        try:
            if os.path.exists(ActivityLogger.LOG_FILE):
                open(ActivityLogger.LOG_FILE, 'w').close()
                return True
        except Exception as e:
            print(f"Failed to clear logs: {e}")
            return False
