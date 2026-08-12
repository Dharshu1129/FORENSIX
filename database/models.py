from datetime import datetime, timezone
import json
from database.database import db

def utc_now():
    return datetime.now(timezone.utc)

class Case(db.Model):
    __tablename__ = 'cases'
    
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(32), unique=True, nullable=False, index=True) # e.g. FX-2026-0001
    name = db.Column(db.String(256), nullable=False)
    investigator = db.Column(db.String(128), nullable=False, default='Lead Investigator')
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default='Open') # Open, Under Investigation, Closed
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)
    
    # Relationships
    evidence_items = db.relationship('Evidence', backref='case', cascade='all, delete-orphan', lazy=True)
    artifacts = db.relationship('Artifact', backref='case', cascade='all, delete-orphan', lazy=True)
    timeline_events = db.relationship('TimelineEvent', backref='case', cascade='all, delete-orphan', lazy=True)
    findings = db.relationship('Finding', backref='case', cascade='all, delete-orphan', lazy=True)
    custody_events = db.relationship('ChainOfCustodyEvent', backref='case', cascade='all, delete-orphan', lazy=True)
    notes = db.relationship('InvestigatorNote', backref='case', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'case_number': self.case_number,
            'name': self.name,
            'investigator': self.investigator,
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'evidence_count': len(self.evidence_items),
            'findings_count': len(self.findings)
        }

class Evidence(db.Model):
    __tablename__ = 'evidence'
    
    id = db.Column(db.Integer, primary_key=True)
    evidence_number = db.Column(db.String(32), unique=True, nullable=False, index=True) # e.g. EVD-0001
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    
    original_filename = db.Column(db.String(256), nullable=False)
    stored_filename = db.Column(db.String(256), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    working_copy_path = db.Column(db.String(512), nullable=True)
    
    file_type = db.Column(db.String(64), nullable=False, default='Unknown')
    mime_type = db.Column(db.String(128), nullable=False, default='application/octet-stream')
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    
    sha256_hash = db.Column(db.String(64), nullable=False)
    md5_hash = db.Column(db.String(32), nullable=False)
    
    acquisition_timestamp = db.Column(db.DateTime, default=utc_now)
    import_timestamp = db.Column(db.DateTime, default=utc_now)
    investigator = db.Column(db.String(128), nullable=False, default='Lead Investigator')
    description = db.Column(db.Text, nullable=True)
    integrity_status = db.Column(db.String(32), nullable=False, default='VERIFIED') # VERIFIED, FAILED, UNCHECKED

    # Relationships
    hashes = db.relationship('EvidenceHash', backref='evidence', cascade='all, delete-orphan', lazy=True)
    artifacts = db.relationship('Artifact', backref='evidence', cascade='all, delete-orphan', lazy=True)
    timeline_events = db.relationship('TimelineEvent', backref='evidence', cascade='all, delete-orphan', lazy=True)
    findings = db.relationship('Finding', backref='evidence', cascade='all, delete-orphan', lazy=True)
    custody_events = db.relationship('ChainOfCustodyEvent', backref='evidence', cascade='all, delete-orphan', lazy=True)
    notes = db.relationship('InvestigatorNote', backref='evidence', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'evidence_number': self.evidence_number,
            'case_id': self.case_id,
            'original_filename': self.original_filename,
            'stored_filename': self.stored_filename,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'sha256_hash': self.sha256_hash,
            'md5_hash': self.md5_hash,
            'acquisition_timestamp': self.acquisition_timestamp.isoformat() if self.acquisition_timestamp else None,
            'import_timestamp': self.import_timestamp.isoformat() if self.import_timestamp else None,
            'investigator': self.investigator,
            'description': self.description,
            'integrity_status': self.integrity_status
        }

class EvidenceHash(db.Model):
    __tablename__ = 'evidence_hashes'
    
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    md5_hash = db.Column(db.String(32), nullable=False)
    calculated_at = db.Column(db.DateTime, default=utc_now)
    verification_status = db.Column(db.String(32), nullable=False, default='MATCH') # MATCH, MISMATCH
    notes = db.Column(db.Text, nullable=True)

class Artifact(db.Model):
    __tablename__ = 'artifacts'
    
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    
    artifact_type = db.Column(db.String(64), nullable=False) # browser_history, browser_download, log_entry, file_metadata, exif
    timestamp = db.Column(db.DateTime, nullable=True, index=True)
    source = db.Column(db.String(128), nullable=False) # e.g. Chrome, Linux Auth Log, EXIF
    
    # Generic fields for fast queries
    url = db.Column(db.Text, nullable=True)
    title = db.Column(db.Text, nullable=True)
    visit_count = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(128), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    event_type = db.Column(db.String(128), nullable=True)
    status_code = db.Column(db.String(32), nullable=True)
    message = db.Column(db.Text, nullable=True)
    
    details_json = db.Column(db.Text, nullable=True) # Full details serialized

    def get_details(self):
        if self.details_json:
            try:
                return json.loads(self.details_json)
            except Exception:
                return {}
        return {}

class TimelineEvent(db.Model):
    __tablename__ = 'timeline_events'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=True)
    
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    artifact_type = db.Column(db.String(64), nullable=False) # BROWSER, LOG, FILE, DOWNLOAD, SYSTEM, AUDIT
    source = db.Column(db.String(128), nullable=False)
    event_name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(32), nullable=False, default='INFORMATIONAL') # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    
    raw_data_json = db.Column(db.Text, nullable=True)

class Finding(db.Model):
    __tablename__ = 'findings'
    
    id = db.Column(db.Integer, primary_key=True)
    finding_number = db.Column(db.String(32), unique=True, nullable=False, index=True) # FND-0001
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=True)
    
    rule_id = db.Column(db.String(64), nullable=False)
    rule_name = db.Column(db.String(256), nullable=False)
    category = db.Column(db.String(64), nullable=False, default='General')
    severity = db.Column(db.String(32), nullable=False, default='MEDIUM') # LOW, MEDIUM, HIGH, CRITICAL
    
    timestamp = db.Column(db.DateTime, default=utc_now)
    reason = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    recommended_action = db.Column(db.Text, nullable=False)
    confidence = db.Column(db.String(32), nullable=False, default='HIGH') # LOW, MEDIUM, HIGH

class ChainOfCustodyEvent(db.Model):
    __tablename__ = 'chain_of_custody'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=True)
    
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)
    event_action = db.Column(db.String(128), nullable=False) # e.g. Evidence Added, Hash Calculated, Integrity Verified
    investigator = db.Column(db.String(128), nullable=False, default='Lead Investigator')
    description = db.Column(db.Text, nullable=False)

class InvestigatorNote(db.Model):
    __tablename__ = 'investigator_notes'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=True)
    timeline_event_id = db.Column(db.Integer, db.ForeignKey('timeline_events.id'), nullable=True)
    
    note = db.Column(db.Text, nullable=False)
    investigator = db.Column(db.String(128), nullable=False, default='Lead Investigator')
    timestamp = db.Column(db.DateTime, default=utc_now)
