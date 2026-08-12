import datetime
import json
from database.models import TimelineEvent, db, Artifact, Evidence, ChainOfCustodyEvent

class ForensicTimelineBuilder:
    @staticmethod
    def rebuild_case_timeline(case_id):
        """
        Clears existing timeline events for a case and aggregates fresh timeline items
        from Evidence metadata, Artifacts, Log entries, and Chain of Custody logs.
        """
        # Delete existing timeline events for this case
        TimelineEvent.query.filter_by(case_id=case_id).delete()
        
        timeline_items = []
        
        # 1. Aggregate from Evidence files (creation & modification)
        evidence_list = Evidence.query.filter_by(case_id=case_id).all()
        for ev in evidence_list:
            if ev.import_timestamp:
                timeline_items.append(TimelineEvent(
                    case_id=case_id,
                    evidence_id=ev.id,
                    timestamp=ev.import_timestamp,
                    artifact_type='FILE_IMPORT',
                    source='Evidence Manager',
                    event_name=f"Evidence File Imported: {ev.original_filename}",
                    description=f"Evidence {ev.evidence_number} ({ev.original_filename}) imported into system. Size: {ev.file_size} bytes. SHA256: {ev.sha256_hash[:16]}...",
                    severity='INFORMATIONAL',
                    raw_data_json=json.dumps({'sha256': ev.sha256_hash, 'size': ev.file_size})
                ))

        # 2. Aggregate from Artifacts (Browser & Log artifacts)
        artifacts = Artifact.query.filter_by(case_id=case_id).all()
        for art in artifacts:
            if not art.timestamp:
                continue
                
            if art.artifact_type in ['browser_history', 'browser_download']:
                evt_type = 'DOWNLOAD' if art.artifact_type == 'browser_download' else 'BROWSER'
                desc = f"Visited URL: {art.url}"
                if art.artifact_type == 'browser_download':
                    desc = f"Downloaded artifact from {art.url}"
                timeline_items.append(TimelineEvent(
                    case_id=case_id,
                    evidence_id=art.evidence_id,
                    timestamp=art.timestamp,
                    artifact_type=evt_type,
                    source=art.source,
                    event_name=f"Browser Activity ({art.title or 'URL'})",
                    description=desc,
                    severity='INFORMATIONAL' if art.artifact_type != 'browser_download' else 'LOW',
                    raw_data_json=art.details_json
                ))
            elif art.artifact_type == 'log_entry':
                details = art.get_details()
                label = details.get('label', 'NORMAL')
                
                # Map label to timeline severity
                sev_map = {'NORMAL': 'INFORMATIONAL', 'INTERESTING': 'LOW', 'SUSPICIOUS': 'HIGH', 'CRITICAL': 'CRITICAL'}
                timeline_sev = sev_map.get(label, 'INFORMATIONAL')
                
                timeline_items.append(TimelineEvent(
                    case_id=case_id,
                    evidence_id=art.evidence_id,
                    timestamp=art.timestamp,
                    artifact_type='LOG',
                    source=art.source,
                    event_name=f"Log Event: {art.event_type or 'Event'}",
                    description=art.message or 'Log event recorded',
                    severity=timeline_sev,
                    raw_data_json=art.details_json
                ))

        # 3. Aggregate from Chain of Custody Events
        custody_events = ChainOfCustodyEvent.query.filter_by(case_id=case_id).all()
        for c in custody_events:
            timeline_items.append(TimelineEvent(
                case_id=case_id,
                evidence_id=c.evidence_id,
                timestamp=c.timestamp,
                artifact_type='AUDIT',
                source='Chain of Custody',
                event_name=f"Custody Event: {c.event_action}",
                description=f"{c.event_action} by {c.investigator}: {c.description}",
                severity='INFORMATIONAL'
            ))

        # Batch insert timeline items
        db.session.add_all(timeline_items)
        db.session.commit()
        
        return len(timeline_items)

    @staticmethod
    def get_timeline_events(case_id, artifact_type=None, severity=None, search_query=None, sort_dir='asc'):
        """Retrieves and filters timeline events for display."""
        query = TimelineEvent.query.filter_by(case_id=case_id)
        
        if artifact_type and artifact_type != 'ALL':
            query = query.filter(TimelineEvent.artifact_type == artifact_type)
            
        if severity and severity != 'ALL':
            query = query.filter(TimelineEvent.severity == severity)
            
        if search_query:
            pattern = f"%{search_query}%"
            query = query.filter(
                (TimelineEvent.event_name.like(pattern)) |
                (TimelineEvent.description.like(pattern)) |
                (TimelineEvent.source.like(pattern))
            )
            
        if sort_dir == 'desc':
            query = query.order_by(TimelineEvent.timestamp.desc())
        else:
            query = query.order_by(TimelineEvent.timestamp.asc())
            
        return query.all()
