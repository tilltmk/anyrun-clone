from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class AnalysisSession(db.Model):
    """Model for storing analysis sessions"""
    __tablename__ = 'analysis_sessions'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(100))
    status = db.Column(db.String(50), default='pending')  # pending, analyzing, completed, error
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    # Relationships
    behaviors = db.relationship('BehaviorEvent', backref='session', lazy=True, cascade='all, delete-orphan')
    network_events = db.relationship('NetworkEvent', backref='session', lazy=True, cascade='all, delete-orphan')
    processes = db.relationship('ProcessEvent', backref='session', lazy=True, cascade='all, delete-orphan')
    dropped_files = db.relationship('DroppedFile', backref='session', lazy=True, cascade='all, delete-orphan')
    iocs = db.relationship('IOC', backref='session', lazy=True, cascade='all, delete-orphan')
    mitre_attacks = db.relationship('MitreAttack', backref='session', lazy=True, cascade='all, delete-orphan')
    strings = db.relationship('StringAnalysis', backref='session', lazy=True, cascade='all, delete-orphan')
    mutexes = db.relationship('MutexHandle', backref='session', lazy=True, cascade='all, delete-orphan')
    memory_regions = db.relationship('MemoryRegion', backref='session', lazy=True, cascade='all, delete-orphan')
    screenshots = db.relationship('Screenshot', backref='session', lazy=True, cascade='all, delete-orphan')
    yara_matches = db.relationship('YaraMatch', backref='session', lazy=True, cascade='all, delete-orphan')
    certificates = db.relationship('Certificate', backref='session', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class BehaviorEvent(db.Model):
    """Model for storing behavioral events during analysis"""
    __tablename__ = 'behavior_events'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(100))  # file_created, registry_modified, process_started, etc.
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    details = db.Column(db.Text)  # JSON string with additional details

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'description': self.description,
            'severity': self.severity,
            'details': json.loads(self.details) if self.details else {}
        }


class NetworkEvent(db.Model):
    """Model for storing network events during analysis"""
    __tablename__ = 'network_events'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    protocol = db.Column(db.String(20))  # HTTP, HTTPS, DNS, TCP, UDP
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    destination_port = db.Column(db.Integer)
    domain = db.Column(db.String(255))
    url = db.Column(db.Text)
    method = db.Column(db.String(10))  # GET, POST, etc.
    headers = db.Column(db.Text)  # JSON
    payload = db.Column(db.Text)
    response_code = db.Column(db.Integer)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'protocol': self.protocol,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'domain': self.domain,
            'url': self.url,
            'method': self.method,
            'headers': json.loads(self.headers) if self.headers else {},
            'payload': self.payload,
            'response_code': self.response_code
        }


class ProcessEvent(db.Model):
    """Model for storing process events and building process tree"""
    __tablename__ = 'process_events'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    pid = db.Column(db.Integer, nullable=False)
    parent_pid = db.Column(db.Integer)
    process_name = db.Column(db.String(255))
    command_line = db.Column(db.Text)
    user = db.Column(db.String(100))
    integrity_level = db.Column(db.String(50))  # Low, Medium, High, System
    status = db.Column(db.String(20))  # created, running, terminated
    exit_code = db.Column(db.Integer)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'pid': self.pid,
            'parent_pid': self.parent_pid,
            'process_name': self.process_name,
            'command_line': self.command_line,
            'user': self.user,
            'integrity_level': self.integrity_level,
            'status': self.status,
            'exit_code': self.exit_code
        }


class DroppedFile(db.Model):
    """Model for storing dropped/created files during analysis"""
    __tablename__ = 'dropped_files'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.Text, nullable=False)
    file_name = db.Column(db.String(255))
    file_hash = db.Column(db.String(64))
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    is_malicious = db.Column(db.Boolean, default=False)
    dropped_by_pid = db.Column(db.Integer)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'is_malicious': self.is_malicious,
            'dropped_by_pid': self.dropped_by_pid
        }


class IOC(db.Model):
    """Model for storing Indicators of Compromise"""
    __tablename__ = 'iocs'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    ioc_type = db.Column(db.String(50))  # ip, domain, url, hash, email, mutex, registry
    value = db.Column(db.Text, nullable=False)
    confidence = db.Column(db.String(20))  # low, medium, high
    description = db.Column(db.Text)
    source = db.Column(db.String(100))  # Where it was found

    def to_dict(self):
        return {
            'id': self.id,
            'ioc_type': self.ioc_type,
            'value': self.value,
            'confidence': self.confidence,
            'description': self.description,
            'source': self.source
        }


class MitreAttack(db.Model):
    """Model for MITRE ATT&CK framework mapping"""
    __tablename__ = 'mitre_attacks'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    technique_id = db.Column(db.String(20))  # e.g., T1055
    technique_name = db.Column(db.String(255))
    tactic = db.Column(db.String(100))  # e.g., Defense Evasion, Persistence
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)  # What triggered this detection

    def to_dict(self):
        return {
            'id': self.id,
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'tactic': self.tactic,
            'description': self.description,
            'evidence': self.evidence
        }


class StringAnalysis(db.Model):
    """Model for storing extracted strings from file"""
    __tablename__ = 'string_analysis'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    string_type = db.Column(db.String(50))  # ascii, unicode, url, ip, email, path
    value = db.Column(db.Text, nullable=False)
    offset = db.Column(db.Integer)
    is_suspicious = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'string_type': self.string_type,
            'value': self.value,
            'offset': self.offset,
            'is_suspicious': self.is_suspicious
        }


class MutexHandle(db.Model):
    """Model for storing mutex and handle information"""
    __tablename__ = 'mutex_handles'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    handle_type = db.Column(db.String(50))  # mutex, event, semaphore, file, registry
    name = db.Column(db.String(255))
    pid = db.Column(db.Integer)
    access_rights = db.Column(db.String(100))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'handle_type': self.handle_type,
            'name': self.name,
            'pid': self.pid,
            'access_rights': self.access_rights
        }


class MemoryRegion(db.Model):
    """Model for storing memory dump information"""
    __tablename__ = 'memory_regions'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    pid = db.Column(db.Integer)
    base_address = db.Column(db.String(20))
    size = db.Column(db.Integer)
    protection = db.Column(db.String(20))  # RWX, RW, RX, etc.
    region_type = db.Column(db.String(50))  # private, mapped, image
    is_suspicious = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'pid': self.pid,
            'base_address': self.base_address,
            'size': self.size,
            'protection': self.protection,
            'region_type': self.region_type,
            'is_suspicious': self.is_suspicious
        }


class Screenshot(db.Model):
    """Model for storing screenshot information"""
    __tablename__ = 'screenshots'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    filename = db.Column(db.String(255))
    description = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'filename': self.filename,
            'description': self.description
        }


class YaraMatch(db.Model):
    """Model for storing YARA rule matches"""
    __tablename__ = 'yara_matches'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    rule_name = db.Column(db.String(255))
    category = db.Column(db.String(100))  # malware_family, behavior, packer, etc.
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    matched_strings = db.Column(db.Text)  # JSON

    def to_dict(self):
        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'matched_strings': json.loads(self.matched_strings) if self.matched_strings else []
        }


class Certificate(db.Model):
    """Model for storing certificate and signature information"""
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), db.ForeignKey('analysis_sessions.session_id'), nullable=False)
    subject = db.Column(db.String(255))
    issuer = db.Column(db.String(255))
    serial_number = db.Column(db.String(100))
    valid_from = db.Column(db.DateTime)
    valid_to = db.Column(db.DateTime)
    thumbprint = db.Column(db.String(64))
    is_valid = db.Column(db.Boolean)
    is_trusted = db.Column(db.Boolean)

    def to_dict(self):
        return {
            'id': self.id,
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_to': self.valid_to.isoformat() if self.valid_to else None,
            'thumbprint': self.thumbprint,
            'is_valid': self.is_valid,
            'is_trusted': self.is_trusted
        }
