from datetime import datetime, timezone
from database.models import Evidence, EvidenceHash, ChainOfCustodyEvent, db
from forensic.hashing import verify_hash

class ForensicIntegrityChecker:
    @staticmethod
    def verify_evidence_integrity(evidence_id, investigator_name='Lead Investigator'):
        """
        Calculates current hash of working evidence copy and compares with baseline hash.
        Records EvidenceHash entry, updates Evidence integrity status, and logs Chain of Custody event.
        """
        evidence = db.session.get(Evidence, evidence_id)
        if not evidence:
            return {'success': False, 'error': 'Evidence item not found'}
            
        file_path = evidence.working_copy_path or evidence.file_path
        
        result = verify_hash(file_path, evidence.sha256_hash, evidence.md5_hash)
        
        status_str = 'VERIFIED' if result['verified'] else 'FAILED'
        evidence.integrity_status = status_str
        
        # Add hash audit record
        hash_record = EvidenceHash(
            evidence_id=evidence.id,
            sha256_hash=result['current_sha256'],
            md5_hash=result['current_md5'],
            verification_status='MATCH' if result['verified'] else 'MISMATCH',
            notes=f"Verification performed by {investigator_name}. Status: {status_str}"
        )
        db.session.add(hash_record)
        
        # Add Chain of Custody event
        custody_desc = (
            f"Integrity check passed. Baseline SHA-256 ({evidence.sha256_hash[:16]}...) matches current file hash."
            if result['verified'] else
            f"WARNING: Integrity verification failed! Current SHA-256 ({result['current_sha256'][:16]}...) DOES NOT match baseline hash ({evidence.sha256_hash[:16]}...)."
        )
        
        custody_event = ChainOfCustodyEvent(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            event_action='Hash Verification',
            investigator=investigator_name,
            description=custody_desc
        )
        db.session.add(custody_event)
        
        db.session.commit()
        
        return {
            'success': True,
            'verified': result['verified'],
            'integrity_status': status_str,
            'current_sha256': result['current_sha256'],
            'expected_sha256': evidence.sha256_hash,
            'current_md5': result['current_md5'],
            'expected_md5': evidence.md5_hash
        }
