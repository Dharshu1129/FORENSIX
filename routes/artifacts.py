from flask import Blueprint, render_template, request
from database.models import Artifact, Case, db

artifacts_bp = Blueprint('artifacts', __name__)

@artifacts_bp.route('/artifacts')
def list_artifacts():
    case_id = request.args.get('case_id', type=int)
    artifact_type = request.args.get('type', '')
    query_str = request.args.get('q', '')
    
    query = Artifact.query
    
    if case_id:
        query = query.filter_by(case_id=case_id)
        
    if artifact_type and artifact_type != 'ALL':
        query = query.filter_by(artifact_type=artifact_type)
        
    if query_str:
        pattern = f"%{query_str}%"
        query = query.filter(
            (Artifact.url.like(pattern)) |
            (Artifact.title.like(pattern)) |
            (Artifact.message.like(pattern)) |
            (Artifact.username.like(pattern)) |
            (Artifact.ip_address.like(pattern))
        )
        
    artifacts = query.order_by(Artifact.timestamp.desc().nullslast()).limit(500).all()
    cases = Case.query.order_by(Case.name).all()
    current_case = db.session.get(Case, case_id) if case_id else None
    
    return render_template(
        'artifacts.html',
        artifacts=artifacts,
        cases=cases,
        current_case=current_case,
        selected_type=artifact_type,
        search_query=query_str
    )
