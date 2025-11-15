import hashlib
import os
import time
import random
import json
from datetime import datetime
from models import db, AnalysisSession, BehaviorEvent, NetworkEvent

class SandboxAnalyzer:
    """Simulated sandbox analyzer for files"""

    def __init__(self):
        self.suspicious_patterns = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'URLDownloadToFile'
        ]
        self.malicious_domains = [
            'malicious-server.com', 'evil-cdn.net', 'phishing-site.org',
            'cryptominer.xyz', 'ransomware-c2.com'
        ]

    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def detect_file_type(self, filepath):
        """Simple file type detection based on extension"""
        ext = os.path.splitext(filepath)[1].lower()
        type_map = {
            '.exe': 'Windows Executable',
            '.dll': 'Dynamic Link Library',
            '.pdf': 'PDF Document',
            '.docx': 'Word Document',
            '.xlsx': 'Excel Spreadsheet',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.js': 'JavaScript File',
            '.vbs': 'VBScript File',
            '.bat': 'Batch File',
            '.ps1': 'PowerShell Script',
            '.py': 'Python Script'
        }
        return type_map.get(ext, 'Unknown File Type')

    def generate_behaviors(self, session_id, file_type):
        """Generate simulated behavioral events"""
        behaviors = []

        # File operations
        if random.random() > 0.3:
            behaviors.append({
                'session_id': session_id,
                'event_type': 'file_created',
                'description': f'Created file: C:\\Users\\Public\\temp_{random.randint(1000, 9999)}.tmp',
                'severity': 'low',
                'details': json.dumps({'path': 'C:\\Users\\Public\\', 'action': 'create'})
            })

        # Process operations
        if random.random() > 0.4:
            behaviors.append({
                'session_id': session_id,
                'event_type': 'process_created',
                'description': f'Started process: {random.choice(["cmd.exe", "powershell.exe", "rundll32.exe"])}',
                'severity': random.choice(['medium', 'high']),
                'details': json.dumps({'process': 'system', 'pid': random.randint(1000, 9999)})
            })

        # Registry operations
        if random.random() > 0.5:
            behaviors.append({
                'session_id': session_id,
                'event_type': 'registry_modified',
                'description': 'Modified registry key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'severity': 'high',
                'details': json.dumps({'key': 'HKCU\\Software\\...', 'action': 'set_value'})
            })

        # Suspicious API calls
        if random.random() > 0.6:
            api = random.choice(self.suspicious_patterns)
            behaviors.append({
                'session_id': session_id,
                'event_type': 'api_call',
                'description': f'Suspicious API call: {api}',
                'severity': 'critical',
                'details': json.dumps({'api': api, 'module': 'kernel32.dll'})
            })

        # Memory operations
        if random.random() > 0.7:
            behaviors.append({
                'session_id': session_id,
                'event_type': 'memory_allocation',
                'description': 'Allocated executable memory region',
                'severity': 'high',
                'details': json.dumps({'size': f'{random.randint(100, 1000)}KB', 'protection': 'RWX'})
            })

        return behaviors

    def generate_network_events(self, session_id):
        """Generate simulated network events"""
        events = []

        # DNS queries
        if random.random() > 0.3:
            domain = random.choice(self.malicious_domains)
            events.append({
                'session_id': session_id,
                'protocol': 'DNS',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'destination_port': 53,
                'domain': domain,
                'url': None
            })

        # HTTP/HTTPS requests
        if random.random() > 0.4:
            domain = random.choice(self.malicious_domains)
            events.append({
                'session_id': session_id,
                'protocol': random.choice(['HTTP', 'HTTPS']),
                'source_ip': '192.168.1.100',
                'destination_ip': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'destination_port': random.choice([80, 443, 8080]),
                'domain': domain,
                'url': f'https://{domain}/payload.exe'
            })

        # TCP connections
        if random.random() > 0.5:
            events.append({
                'session_id': session_id,
                'protocol': 'TCP',
                'source_ip': '192.168.1.100',
                'destination_ip': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'destination_port': random.choice([4444, 5555, 6666, 1337]),
                'domain': None,
                'url': None
            })

        return events

    def analyze_file(self, filepath, filename, session_id):
        """Perform simulated file analysis"""
        try:
            # Calculate file info
            file_hash = self.calculate_file_hash(filepath)
            file_size = os.path.getsize(filepath)
            file_type = self.detect_file_type(filepath)

            # Create session in database
            session = AnalysisSession(
                session_id=session_id,
                filename=filename,
                file_hash=file_hash,
                file_size=file_size,
                file_type=file_type,
                status='analyzing'
            )
            db.session.add(session)
            db.session.commit()

            # Simulate analysis time
            time.sleep(2)

            # Generate behavioral events
            behaviors = self.generate_behaviors(session_id, file_type)
            for behavior in behaviors:
                event = BehaviorEvent(**behavior)
                db.session.add(event)
                time.sleep(0.5)  # Simulate real-time events

            # Generate network events
            network_events = self.generate_network_events(session_id)
            for net_event in network_events:
                event = NetworkEvent(**net_event)
                db.session.add(event)
                time.sleep(0.3)

            # Update session status
            session.status = 'completed'
            session.completed_at = datetime.utcnow()
            db.session.commit()

            return {
                'success': True,
                'session_id': session_id,
                'file_hash': file_hash,
                'file_type': file_type
            }

        except Exception as e:
            if session:
                session.status = 'error'
                db.session.commit()
            return {
                'success': False,
                'error': str(e)
            }

    def get_session_details(self, session_id):
        """Retrieve detailed analysis results for a session"""
        session = AnalysisSession.query.filter_by(session_id=session_id).first()
        if not session:
            return None

        behaviors = BehaviorEvent.query.filter_by(session_id=session_id).all()
        network_events = NetworkEvent.query.filter_by(session_id=session_id).all()

        return {
            'session': session.to_dict(),
            'behaviors': [b.to_dict() for b in behaviors],
            'network_events': [n.to_dict() for n in network_events],
            'threat_score': self.calculate_threat_score(behaviors, network_events)
        }

    def calculate_threat_score(self, behaviors, network_events):
        """Calculate a threat score based on behaviors and network activity"""
        score = 0

        for behavior in behaviors:
            if behavior.severity == 'critical':
                score += 25
            elif behavior.severity == 'high':
                score += 15
            elif behavior.severity == 'medium':
                score += 5
            else:
                score += 1

        # Network activity adds to score
        score += len(network_events) * 3

        # Cap at 100
        return min(score, 100)
