import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from database.models import Case, db
from reports.report_generator import ForensicReportGenerator

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
def list_reports():
    case_id = request.args.get('case_id', type=int)
    cases = Case.query.order_by(Case.created_at.desc()).all()
    current_case = db.session.get(Case, case_id) if case_id else (cases[0] if cases else None)
    
    return render_template('report.html', cases=cases, current_case=current_case)

@reports_bp.route('/reports/generate/<int:case_id>', methods=['POST'])
def generate_report(case_id):
    case = Case.query.get_or_404(case_id)
    try:
        pdf_path = ForensicReportGenerator.generate_pdf_report(case.id)
        flash(f"Forensic PDF report generated successfully for case {case.case_number}.", "success")
        return redirect(url_for('reports.list_reports', case_id=case.id))
    except Exception as e:
        flash(f"Failed to generate forensic PDF report: {str(e)}", "danger")
        return redirect(url_for('reports.list_reports', case_id=case.id))

@reports_bp.route('/reports/download/<int:case_id>')
def download_report(case_id):
    case = Case.query.get_or_404(case_id)
    try:
        pdf_path = ForensicReportGenerator.generate_pdf_report(case.id)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"Forensic_Report_{case.case_number}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f"Report file error: {str(e)}", "danger")
        return redirect(url_for('reports.list_reports', case_id=case.id))
