from flask import Blueprint, render_template, request, jsonify
from database.models import TimelineEvent, Case, db
from forensic.timeline import ForensicTimelineBuilder

timeline_bp = Blueprint('timeline', __name__)

@timeline_bp.route('/timeline')
def index():
    case_id = request.args.get('case_id', type=int)
    cases = Case.query.order_by(Case.created_at.desc()).all()
    
    if not case_id and cases:
        case_id = cases[0].id
        
    current_case = db.session.get(Case, case_id) if case_id else None
    
    events = []
    if case_id:
        events = ForensicTimelineBuilder.get_timeline_events(case_id, sort_dir='asc')
        
    return render_template(
        'timeline.html',
        cases=cases,
        current_case=current_case,
        events=events
    )

@timeline_bp.route('/api/timeline/<int:case_id>')
def timeline_api(case_id):
    artifact_type = request.args.get('type', 'ALL')
    severity = request.args.get('severity', 'ALL')
    q = request.args.get('q', '')
    sort_dir = request.args.get('sort', 'asc')
    
    events = ForensicTimelineBuilder.get_timeline_events(
        case_id, artifact_type=artifact_type, severity=severity, search_query=q, sort_dir=sort_dir
    )
    
    events_data = []
    for e in events:
        events_data.append({
            'id': e.id,
            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
            'artifact_type': e.artifact_type,
            'source': e.source,
            'event_name': e.event_name,
            'description': e.description,
            'severity': e.severity
        })
        
    return jsonify({
        'case_id': case_id,
        'count': len(events_data),
        'events': events_data
    })
