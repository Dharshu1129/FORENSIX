import json
import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from database.models import Evidence, Case, Artifact, ChainOfCustodyEvent, InvestigatorNote, db
from forensic.evidence_manager import ForensicEvidenceManager
from forensic.hashing import calculate_file_hashes
from forensic.metadata_analyzer import ForensicMetadataAnalyzer
from forensic.file_analyzer import ForensicFileAnalyzer
from forensic.browser_parser import ForensicBrowserParser
from forensic.log_analyzer import ForensicLogAnalyzer
from forensic.integrity import ForensicIntegrityChecker
from forensic.timeline import ForensicTimelineBuilder
from forensic.suspicious_activity import ForensicSuspiciousActivityEngine

evidence_bp = Blueprint('evidence', __name__)

def generate_evidence_number():
    count = Evidence.query.count() + 1
    return f"EVD-{count:04d}"

@evidence_bp.route('/evidence')
def list_evidence():
    case_id = request.args.get('case_id', type=int)
    if case_id:
        evidence_items = Evidence.query.filter_by(case_id=case_id).all()
        current_case = db.session.get(Case, case_id)
    else:
        evidence_items = Evidence.query.all()
        current_case = None
        
    cases = Case.query.order_by(Case.name).all()
    return render_template('evidence.html', evidence_items=evidence_items, cases=cases, current_case=current_case)

@evidence_bp.route('/evidence/upload', methods=['POST'])
def upload_evidence():
    case_id = request.form.get('case_id', type=int)
    investigator = request.form.get('investigator', 'Lead Investigator')
    description = request.form.get('description', '')
    
    if not case_id:
        flash('Please select a valid case for evidence ingestion.', 'danger')
        return redirect(url_for('evidence.list_evidence'))
        
    target_case = Case.query.get_or_404(case_id)
    
    uploaded_files = request.files.getlist('evidence_files')
    if not uploaded_files or uploaded_files[0].filename == '':
        flash('No evidence files selected for upload.', 'warning')
        return redirect(url_for('evidence.list_evidence', case_id=case_id))
        
    ingested_count = 0
    for file_storage in uploaded_files:
        if not file_storage.filename:
            continue
            
        # 1. Store evidence file safely in uploads/ & working_evidence/
        ev_meta = ForensicEvidenceManager.store_evidence_file(file_storage, target_case.case_number)
        
        # 2. Calculate initial SHA-256 and MD5 hashes
        hashes = calculate_file_hashes(ev_meta['file_path'])
        
        # 3. Create Evidence Record
        ev_number = generate_evidence_number()
        evidence = Evidence(
            evidence_number=ev_number,
            case_id=case_id,
            original_filename=ev_meta['original_filename'],
            stored_filename=ev_meta['stored_filename'],
            file_path=ev_meta['file_path'],
            working_copy_path=ev_meta['working_copy_path'],
            file_type=ev_meta['file_type'],
            mime_type=ev_meta['mime_type'],
            file_size=ev_meta['file_size'],
            sha256_hash=hashes['sha256'],
            md5_hash=hashes['md5'],
            investigator=investigator,
            description=description,
            integrity_status='VERIFIED'
        )
        db.session.add(evidence)
        db.session.commit()
        
        # 4. Log Chain of Custody Event
        db.session.add(ChainOfCustodyEvent(
            case_id=case_id,
            evidence_id=evidence.id,
            event_action="Evidence Ingestion",
            investigator=investigator,
            description=f"Evidence {ev_number} ({evidence.original_filename}) uploaded and stored safely. SHA-256: {hashes['sha256']}"
        ))
        db.session.commit()
        
        # 5. Extract Artifacts automatically based on file type
        target_path = evidence.working_copy_path or evidence.file_path
        
        # Check if browser history
        if 'Database' in evidence.file_type or evidence.original_filename.lower() in ['history', 'places.sqlite']:
            res = ForensicBrowserParser.parse_browser_database(target_path)
            if res['supported']:
                for item in res['artifacts']:
                    ts_dt = datetime.datetime.fromisoformat(item['timestamp']) if item.get('timestamp') else None
                    db.session.add(Artifact(
                        evidence_id=evidence.id,
                        case_id=case_id,
                        artifact_type=item['artifact_type'],
                        timestamp=ts_dt,
                        source=item['browser'],
                        url=item.get('url'),
                        title=item.get('title'),
                        visit_count=item.get('visit_count', 1),
                        message=f"{item['activity']}: {item['title']}",
                        details_json=json.dumps(item)
                    ))
                    
        # Check if log file
        elif 'Log' in evidence.file_type or evidence.original_filename.lower().endswith(('.log', '.txt')):
            res = ForensicLogAnalyzer.parse_log_file(target_path)
            for entry in res['entries']:
                ts_dt = datetime.datetime.fromisoformat(entry['timestamp']) if entry.get('timestamp') else None
                db.session.add(Artifact(
                    evidence_id=evidence.id,
                    case_id=case_id,
                    artifact_type='log_entry',
                    timestamp=ts_dt,
                    source=f"Log ({evidence.original_filename})",
                    username=entry.get('username'),
                    ip_address=entry.get('ip_address'),
                    event_type=entry.get('event_type'),
                    message=entry['message'],
                    details_json=json.dumps(entry)
                ))

        db.session.commit()
        ingested_count += 1

    # Rebuild Timeline & Run Transparent Rule Engine
    ForensicTimelineBuilder.rebuild_case_timeline(case_id)
    ForensicSuspiciousActivityEngine.run_case_analysis(case_id)

    flash(f"Successfully ingested {ingested_count} evidence item(s). Artifacts and timeline updated.", "success")
    return redirect(url_for('evidence.list_evidence', case_id=case_id))

@evidence_bp.route('/evidence/<int:id>')
def evidence_detail(id):
    evidence = Evidence.query.get_or_404(id)
    target_path = evidence.working_copy_path or evidence.file_path
    
    # Analyze metadata & file anomalies
    metadata = ForensicMetadataAnalyzer.extract_file_metadata(target_path)
    file_analysis = ForensicFileAnalyzer.analyze_file(target_path, evidence.original_filename)
    
    artifacts = Artifact.query.filter_by(evidence_id=evidence.id).all()
    custody_logs = ChainOfCustodyEvent.query.filter_by(evidence_id=evidence.id).order_by(ChainOfCustodyEvent.timestamp.desc()).all()
    notes = InvestigatorNote.query.filter_by(evidence_id=evidence.id).order_by(InvestigatorNote.timestamp.desc()).all()
    
    return render_template(
        'evidence_detail.html',
        evidence=evidence,
        metadata=metadata,
        file_analysis=file_analysis,
        artifacts=artifacts,
        custody_logs=custody_logs,
        notes=notes
    )

@evidence_bp.route('/evidence/<int:id>/verify-hash', methods=['POST'])
def verify_hash_route(id):
    evidence = Evidence.query.get_or_404(id)
    res = ForensicIntegrityChecker.verify_evidence_integrity(evidence.id)
    
    if res['verified']:
        flash(f"Integrity Verified: SHA-256 hash matches baseline ({res['current_sha256'][:16]}...).", "success")
    else:
        flash(f"WARNING: Evidence integrity verification failed! Current hash does not match baseline.", "danger")
        
    return redirect(url_for('evidence.evidence_detail', id=evidence.id))

@evidence_bp.route('/evidence/<int:id>/add-note', methods=['POST'])
def add_note(id):
    evidence = db.session.get(Evidence, id)
    if not evidence:
        flash("Evidence item not found.", "danger")
        return redirect(url_for('evidence.list_evidence'))
    note_text = request.form.get('note')
    investigator = request.form.get('investigator', 'Lead Investigator')
    
    if note_text:
        new_note = InvestigatorNote(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            note=note_text,
            investigator=investigator
        )
        db.session.add(new_note)
        
        # Log chain of custody event
        db.session.add(ChainOfCustodyEvent(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            event_action="Investigator Note Added",
            investigator=investigator,
            description=f"Added note: '{note_text[:50]}...'"
        ))
        db.session.commit()
        flash("Investigator note added.", "success")
        
    return redirect(url_for('evidence.evidence_detail', id=evidence.id))

@evidence_bp.route('/evidence/export/csv')
def export_evidence_csv():
    """Exports evidence inventory as a structured CSV file."""
    import io
    import csv
    from flask import Response
    
    case_id = request.args.get('case_id', type=int)
    query = Evidence.query
    if case_id:
        query = query.filter_by(case_id=case_id)
    evidence_items = query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Evidence ID', 'Case Number', 'Original Filename', 'Type', 'MIME Type', 'File Size (Bytes)', 'SHA-256 Hash', 'MD5 Hash', 'Integrity Status', 'Import Timestamp'])
    
    for ev in evidence_items:
        writer.writerow([
            ev.evidence_number,
            ev.case.case_number if ev.case else '',
            ev.original_filename,
            ev.file_type,
            ev.mime_type,
            ev.file_size,
            ev.sha256_hash,
            ev.md5_hash,
            ev.integrity_status,
            ev.import_timestamp.isoformat() if ev.import_timestamp else ''
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=Forensic_Evidence_Inventory.csv"}
    )
