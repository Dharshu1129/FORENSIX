from flask import Blueprint, render_template, jsonify
from database.models import Case, Evidence, Artifact, Finding, TimelineEvent, ChainOfCustodyEvent, db
from sqlalchemy import func

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def index():
    # Gather high level SOC stats
    total_cases = Case.query.count()
    total_evidence = Evidence.query.count()
    total_artifacts = Artifact.query.count()
    total_findings = Finding.query.count()
    critical_findings = Finding.query.filter_by(severity='CRITICAL').count()
    integrity_failures = Evidence.query.filter_by(integrity_status='FAILED').count()
    
    recent_cases = Case.query.order_by(Case.created_at.desc()).limit(5).all()
    recent_findings = Finding.query.order_by(Finding.timestamp.desc()).limit(8).all()
    
    return render_template(
        'dashboard.html',
        total_cases=total_cases,
        total_evidence=total_evidence,
        total_artifacts=total_artifacts,
        total_findings=total_findings,
        critical_findings=critical_findings,
        integrity_failures=integrity_failures,
        recent_cases=recent_cases,
        recent_findings=recent_findings
    )

@dashboard_bp.route('/api/dashboard/charts')
def chart_data():
    """API endpoint providing aggregated chart data for Chart.js visualizations."""
    
    # 1. Evidence by Type
    ev_types = db.session.query(
        Evidence.file_type, func.count(Evidence.id)
    ).group_by(Evidence.file_type).all()
    
    # 2. Findings by Severity
    severity_counts = db.session.query(
        Finding.severity, func.count(Finding.id)
    ).group_by(Finding.severity).all()
    
    # 3. Artifact Distribution
    artifact_types = db.session.query(
        Artifact.artifact_type, func.count(Artifact.id)
    ).group_by(Artifact.artifact_type).all()
    
    # Format response
    return jsonify({
        'evidence_types': {
            'labels': [t[0] for t in ev_types],
            'data': [t[1] for t in ev_types]
        },
        'findings_severity': {
            'labels': [s[0] for s in severity_counts],
            'data': [s[1] for s in severity_counts]
        },
        'artifact_distribution': {
            'labels': [a[0] for a in artifact_types],
            'data': [a[1] for a in artifact_types]
        }
    })
