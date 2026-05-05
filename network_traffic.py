import random
import string
from datetime import datetime
from database import insert_traffic
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkTraffic:
    """Handles network traffic collection and processing."""
    
    # Common ports
    COMMON_PORTS = {
        20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB'
    }
    
    # Protocols
    PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'IGMP']
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        'SQL injection', 'XSS attack', 'Buffer overflow', 'Port scan',
        'DDoS attempt', 'Brute force', 'Malware signature', 'Command injection',
        'XXE attack', 'CSRF token invalid', 'Privilege escalation', 'Data exfiltration'
    ]
    
    # Real-time monitoring
    _monitoring_active = False
    _monitor_thread = None
    _packet_count = 0
    
    @staticmethod
    def generate_ip():
        """Generate random IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    @staticmethod
    def generate_payload(size=100):
        """Generate random network payload."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=min(size, 256)))
    
    @staticmethod
    def collect_traffic(count=10, use_real_packets=False):
        """Collect network traffic samples."""
        if use_real_packets:
            return NetworkTraffic._collect_real_traffic(count)
        else:
            return NetworkTraffic._collect_simulated_traffic(count)
    
    @staticmethod
    def _collect_simulated_traffic(count=10):
        """Simulate collecting network traffic."""
        traffic_records = []
        
        for _ in range(count):
            source_ip = NetworkTraffic.generate_ip()
            dest_ip = NetworkTraffic.generate_ip()
            source_port = random.randint(1024, 65535)
            dest_port = random.choice(list(NetworkTraffic.COMMON_PORTS.keys()))
            protocol = random.choice(NetworkTraffic.PROTOCOLS)
            packet_size = random.randint(50, 1500)
            payload = NetworkTraffic.generate_payload(packet_size)
            
            # 10% chance to be anomaly
            is_anomaly = 1 if random.random() < 0.1 else 0
            
            # Insert to database
            traffic_id = insert_traffic(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                packet_size=packet_size,
                payload=payload,
                is_anomaly=is_anomaly
            )
            
            traffic_records.append({
                'id': traffic_id,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'source_port': source_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'packet_size': packet_size,
                'is_anomaly': is_anomaly,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        
        return traffic_records
    
    @staticmethod
    def _collect_real_traffic(count=10):
        """Collect real network traffic using scapy."""
        traffic_records = []
        packets_captured = []
        
        def packet_callback(packet):
            if len(packets_captured) >= count:
                return
            
            try:
                if IP in packet:
                    ip_layer = packet[IP]
                    source_ip = ip_layer.src
                    dest_ip = ip_layer.dst
                    packet_size = len(packet)
                    
                    # Extract port information
                    source_port = 0
                    dest_port = 0
                    protocol = 'UNKNOWN'
                    
                    if TCP in packet:
                        source_port = packet[TCP].sport
                        dest_port = packet[TCP].dport
                        protocol = 'TCP'
                    elif UDP in packet:
                        source_port = packet[UDP].sport
                        dest_port = packet[UDP].dport
                        protocol = 'UDP'
                    elif ICMP in packet:
                        protocol = 'ICMP'
                    
                    # Basic anomaly detection (simplified)
                    is_anomaly = NetworkTraffic._detect_anomaly(packet)
                    
                    # Insert to database
                    traffic_id = insert_traffic(
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        source_port=source_port,
                        dest_port=dest_port,
                        protocol=protocol,
                        packet_size=packet_size,
                        payload='',  # Don't store actual payload for privacy
                        is_anomaly=is_anomaly
                    )
                    
                    traffic_records.append({
                        'id': traffic_id,
                        'source_ip': source_ip,
                        'dest_ip': dest_ip,
                        'source_port': source_port,
                        'dest_port': dest_port,
                        'protocol': protocol,
                        'packet_size': packet_size,
                        'is_anomaly': is_anomaly,
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    })
                    
                    packets_captured.append(packet)
                    
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        
        try:
            # Capture packets (non-blocking, timeout after 10 seconds)
            sniff(prn=packet_callback, count=count, timeout=10, store=0)
        except Exception as e:
            logger.error(f"Error capturing packets: {e}")
            # Fallback to simulated traffic
            return NetworkTraffic._collect_simulated_traffic(count)
        
        return traffic_records
    
    @staticmethod
    def _detect_anomaly(packet):
        """Basic anomaly detection for packets."""
        try:
            if IP in packet:
                packet_size = len(packet)
                
                # Simple heuristics for anomaly detection
                if packet_size > 1400:  # Large packets
                    return 1
                if TCP in packet and packet[TCP].flags & 0x02:  # SYN packets (potential scans)
                    return 1
                if packet[IP].ttl < 30:  # Low TTL
                    return 1
                
                # Random factor for simulation
                return 1 if random.random() < 0.05 else 0
        except:
            pass
        return 0
    
    @staticmethod
    def start_real_time_monitoring():
        """Start real-time network monitoring."""
        if NetworkTraffic._monitoring_active:
            return
        
        NetworkTraffic._monitoring_active = True
        NetworkTraffic._packet_count = 0
        
        def monitor_worker():
            logger.info("Starting real-time network monitoring...")
            
            def packet_handler(packet):
                if not NetworkTraffic._monitoring_active:
                    return
                
                try:
                    NetworkTraffic._packet_count += 1
                    
                    if IP in packet:
                        ip_layer = packet[IP]
                        source_ip = ip_layer.src
                        dest_ip = ip_layer.dst
                        packet_size = len(packet)
                        
                        # Extract port information
                        source_port = 0
                        dest_port = 0
                        protocol = 'UNKNOWN'
                        
                        if TCP in packet:
                            source_port = packet[TCP].sport
                            dest_port = packet[TCP].dport
                            protocol = 'TCP'
                        elif UDP in packet:
                            source_port = packet[UDP].sport
                            dest_port = packet[UDP].dport
                            protocol = 'UDP'
                        elif ICMP in packet:
                            protocol = 'ICMP'
                        
                        is_anomaly = NetworkTraffic._detect_anomaly(packet)
                        
                        # Insert to database
                        insert_traffic(
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            source_port=source_port,
                            dest_port=dest_port,
                            protocol=protocol,
                            packet_size=packet_size,
                            payload='',
                            is_anomaly=is_anomaly
                        )
                        
                except Exception as e:
                    logger.error(f"Error in real-time monitoring: {e}")
            
            try:
                # Continuous monitoring with 1-second intervals
                while NetworkTraffic._monitoring_active:
                    sniff(prn=packet_handler, count=10, timeout=1, store=0)
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Real-time monitoring error: {e}")
            finally:
                NetworkTraffic._monitoring_active = False
        
        NetworkTraffic._monitor_thread = threading.Thread(target=monitor_worker, daemon=True)
        NetworkTraffic._monitor_thread.start()
    
    @staticmethod
    def stop_real_time_monitoring():
        """Stop real-time network monitoring."""
        NetworkTraffic._monitoring_active = False
        if NetworkTraffic._monitor_thread:
            NetworkTraffic._monitor_thread.join(timeout=5)
    
    @staticmethod
    def is_monitoring_active():
        """Check if real-time monitoring is active."""
        return NetworkTraffic._monitoring_active
    
    @staticmethod
    def get_packet_count():
        """Get the number of packets processed in real-time monitoring."""
        return NetworkTraffic._packet_count
    
    @staticmethod
    def generate_ip():
        """Generate random IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    @staticmethod
    def generate_payload(size=100):
        """Generate random network payload."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=min(size, 256)))
    
    @staticmethod
    def collect_traffic(count=10):
        """Simulate collecting network traffic."""
        traffic_records = []
        
        for _ in range(count):
            source_ip = NetworkTraffic.generate_ip()
            dest_ip = NetworkTraffic.generate_ip()
            source_port = random.randint(1024, 65535)
            dest_port = random.choice(list(NetworkTraffic.COMMON_PORTS.keys()))
            protocol = random.choice(NetworkTraffic.PROTOCOLS)
            packet_size = random.randint(50, 1500)
            payload = NetworkTraffic.generate_payload(packet_size)
            
            # 10% chance to be anomaly
            is_anomaly = 1 if random.random() < 0.1 else 0
            
            # Insert to database
            traffic_id = insert_traffic(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                packet_size=packet_size,
                payload=payload,
                is_anomaly=is_anomaly
            )
            
            traffic_records.append({
                'id': traffic_id,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'source_port': source_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'packet_size': packet_size,
                'is_anomaly': is_anomaly,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        
        return traffic_records
    
    @staticmethod
    def extract_features(traffic_data):
        """
        Extract ML features from traffic data.
        Returns feature vectors suitable for ML models.
        """
        features = []
        
        for traffic in traffic_data:
            # Extract port numbers
            src_port = traffic.get('source_port', 0)
            dst_port = traffic.get('dest_port', 0)
            packet_size = traffic.get('packet_size', 0)
            
            # Encode protocol
            protocol = traffic.get('protocol', 'TCP')
            protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'IGMP': 3}
            protocol_encoded = protocol_map.get(protocol, 0)
            
            # Feature vector: [src_port, dst_port, protocol, packet_size]
            feature_vector = [
                src_port / 65535.0,  # Normalize port
                dst_port / 65535.0,  # Normalize port
                protocol_encoded / 3.0,  # Normalize protocol
                packet_size / 1500.0  # Normalize packet size
            ]
            
            features.append(feature_vector)
        
        return features
    
    @staticmethod
    def get_traffic_summary():
        """Get summary of collected traffic."""
        from database import get_network_traffic
        traffic = get_network_traffic()
        
        if not traffic:
            return {
                'total_packets': 0,
                'total_anomalies': 0,
                'avg_packet_size': 0,
                'protocols_seen': []
            }
        
        protocols = list(set([t.get('protocol') for t in traffic if t.get('protocol')]))
        total_size = sum([t.get('packet_size', 0) for t in traffic])
        
        return {
            'total_packets': len(traffic),
            'total_anomalies': sum([1 for t in traffic if t.get('is_anomaly') == 1]),
            'avg_packet_size': total_size / len(traffic) if traffic else 0,
            'protocols_seen': protocols
        }
