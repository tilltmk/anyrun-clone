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

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'protocol': self.protocol,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'domain': self.domain,
            'url': self.url
        }
