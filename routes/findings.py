from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.models import Finding, Case, db
from forensic.suspicious_activity import ForensicSuspiciousActivityEngine

findings_bp = Blueprint('findings', __name__)

@findings_bp.route('/findings')
def list_findings():
    case_id = request.args.get('case_id', type=int)
    severity = request.args.get('severity', '')
    
    query = Finding.query
    
    if case_id:
        query = query.filter_by(case_id=case_id)
        
    if severity and severity != 'ALL':
        query = query.filter_by(severity=severity)
        
    findings = query.order_by(Finding.timestamp.desc()).all()
    cases = Case.query.order_by(Case.name).all()
    current_case = db.session.get(Case, case_id) if case_id else None
    
    return render_template(
        'findings.html',
        findings=findings,
        cases=cases,
        current_case=current_case,
        selected_severity=severity
    )

@findings_bp.route('/findings/reanalyze/<int:case_id>', methods=['POST'])
def reanalyze_case(case_id):
    case = Case.query.get_or_404(case_id)
    count = ForensicSuspiciousActivityEngine.run_case_analysis(case.id)
    flash(f"Re-analysis complete for case {case.case_number}. Generated {count} suspicious activity finding(s).", "info")
    return redirect(url_for('findings.list_findings', case_id=case.id))
