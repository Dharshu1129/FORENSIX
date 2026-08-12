import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from database.models import Case, Evidence, Finding, ChainOfCustodyEvent, InvestigatorNote, db
from forensic.sample_generator import SyntheticEvidenceGenerator

cases_bp = Blueprint('cases', __name__)

def generate_case_number():
    year = datetime.datetime.now().year
    count = Case.query.count() + 1
    return f"FX-{year}-{count:04d}"

@cases_bp.route('/cases')
def list_cases():
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template('cases.html', cases=all_cases)

@cases_bp.route('/cases/create', methods=['GET', 'POST'])
def create_case():
    if request.method == 'POST':
        name = request.form.get('name')
        investigator = request.form.get('investigator', 'Lead Investigator')
        description = request.form.get('description')
        
        if not name:
            flash('Case name is required.', 'danger')
            return redirect(url_for('cases.create_case'))
            
        case_num = generate_case_number()
        new_case = Case(
            case_number=case_num,
            name=name,
            investigator=investigator,
            description=description,
            status='Open'
        )
        db.session.add(new_case)
        db.session.commit()
        
        # Log chain of custody event for case creation
        db.session.add(ChainOfCustodyEvent(
            case_id=new_case.id,
            event_action="Case Created",
            investigator=investigator,
            description=f"Forensic case {case_num} initialized."
        ))
        db.session.commit()
        
        flash(f"Case {case_num} created successfully.", "success")
        return redirect(url_for('cases.case_detail', id=new_case.id))
        
    return render_template('create_case.html', auto_case_num=generate_case_number())

@cases_bp.route('/cases/<int:id>')
def case_detail(id):
    case = db.session.get(Case, id)
    if not case:
        return render_template('404.html', error_title="Case Not Found", error_msg="The requested case ID does not exist."), 404
    return render_template('case_detail.html', case=case)

@cases_bp.route('/cases/<int:id>/edit', methods=['POST'])
def edit_case(id):
    case = db.session.get(Case, id)
    if not case:
        return render_template('404.html', error_title="Case Not Found", error_msg="The requested case ID does not exist."), 404
    case.name = request.form.get('name', case.name)
    case.investigator = request.form.get('investigator', case.investigator)
    case.description = request.form.get('description', case.description)
    case.status = request.form.get('status', case.status)
    db.session.commit()
    
    flash(f"Case {case.case_number} updated.", "info")
    return redirect(url_for('cases.case_detail', id=case.id))

@cases_bp.route('/cases/<int:id>/close', methods=['POST'])
def close_case(id):
    case = db.session.get(Case, id)
    if not case:
        return render_template('404.html', error_title="Case Not Found", error_msg="The requested case ID does not exist."), 404
    case.status = 'Closed'
    db.session.commit()
    
    db.session.add(ChainOfCustodyEvent(
        case_id=case.id,
        event_action="Case Closed",
        investigator=case.investigator,
        description=f"Forensic case {case.case_number} officially closed."
    ))
    db.session.commit()
    
    flash(f"Case {case.case_number} has been closed.", "warning")
    return redirect(url_for('cases.case_detail', id=case.id))

@cases_bp.route('/cases/<int:id>/delete', methods=['POST'])
def delete_case(id):
    case = db.session.get(Case, id)
    if not case:
        return render_template('404.html', error_title="Case Not Found", error_msg="The requested case ID does not exist."), 404
    case_num = case.case_number
    db.session.delete(case)
    db.session.commit()
    
    flash(f"Case {case_num} permanently deleted.", "danger")
    return redirect(url_for('cases.list_cases'))

@cases_bp.route('/cases/generate-demo', methods=['POST'])
def generate_demo():
    """Generates synthetic demonstration case with sample evidence files."""
    try:
        demo_case = SyntheticEvidenceGenerator.generate_demo_case()
        flash(f"Demo case '{demo_case.case_number}' generated with synthetic evidence files, artifacts, timeline, and findings!", "success")
        return redirect(url_for('cases.case_detail', id=demo_case.id))
    except Exception as e:
        flash(f"Failed to generate demo case: {str(e)}", "danger")
        return redirect(url_for('cases.list_cases'))
