from flask import Blueprint, render_template, request
from database.models import Case, Evidence, Artifact, TimelineEvent, Finding, db
from forensic.keyword_search import ForensicKeywordSearch

investigation_bp = Blueprint('investigation', __name__)

@investigation_bp.route('/investigation')
def entity_investigation():
    query = request.args.get('q', '').strip()
    case_id = request.args.get('case_id', type=int)
    
    cases = Case.query.order_by(Case.created_at.desc()).all()
    current_case = db.session.get(Case, case_id) if case_id else None
    
    results = {
        'entity': query,
        'first_seen': None,
        'last_seen': None,
        'event_count': 0,
        'associated_evidence': [],
        'associated_artifacts': [],
        'associated_findings': [],
        'associated_timeline': [],
        'file_matches': []
    }
    
    if query:
        pattern = f"%{query}%"
        
        # 1. Search Artifacts
        art_query = Artifact.query.filter(
            (Artifact.url.like(pattern)) |
            (Artifact.title.like(pattern)) |
            (Artifact.message.like(pattern)) |
            (Artifact.username.like(pattern)) |
            (Artifact.ip_address.like(pattern)) |
            (Artifact.source.like(pattern))
        )
        if case_id:
            art_query = art_query.filter(Artifact.case_id == case_id)
        matched_artifacts = art_query.order_by(Artifact.timestamp.asc()).all()
        results['associated_artifacts'] = matched_artifacts
        
        # 2. Search Timeline Events
        time_query = TimelineEvent.query.filter(
            (TimelineEvent.event_name.like(pattern)) |
            (TimelineEvent.description.like(pattern)) |
            (TimelineEvent.source.like(pattern))
        )
        if case_id:
            time_query = time_query.filter(TimelineEvent.case_id == case_id)
        matched_timeline = time_query.order_by(TimelineEvent.timestamp.asc()).all()
        results['associated_timeline'] = matched_timeline
        
        # 3. Search Findings
        fnd_query = Finding.query.filter(
            (Finding.rule_name.like(pattern)) |
            (Finding.reason.like(pattern)) |
            (Finding.explanation.like(pattern)) |
            (Finding.category.like(pattern))
        )
        if case_id:
            fnd_query = fnd_query.filter(Finding.case_id == case_id)
        results['associated_findings'] = fnd_query.all()
        
        # Calculate First Seen & Last Seen
        all_timestamps = []
        for a in matched_artifacts:
            if a.timestamp:
                all_timestamps.append(a.timestamp)
        for t in matched_timeline:
            if t.timestamp:
                all_timestamps.append(t.timestamp)
                
        if all_timestamps:
            all_timestamps.sort()
            results['first_seen'] = all_timestamps[0].strftime("%Y-%m-%d %H:%M:%S UTC")
            results['last_seen'] = all_timestamps[-1].strftime("%Y-%m-%d %H:%M:%S UTC")
            results['event_count'] = len(all_timestamps)
            
        # 4. Search Evidence Files content safely
        ev_query = Evidence.query
        if case_id:
            ev_query = ev_query.filter_by(case_id=case_id)
        evidence_list = ev_query.all()
        
        file_matches = []
        for ev in evidence_list:
            target_path = ev.working_copy_path or ev.file_path
            snippets = ForensicKeywordSearch.search_file(target_path, query)
            if snippets:
                file_matches.append({
                    'evidence': ev,
                    'matches': snippets
                })
        results['file_matches'] = file_matches

    return render_template(
        'investigation.html',
        cases=cases,
        current_case=current_case,
        query=query,
        results=results
    )
