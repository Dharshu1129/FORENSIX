from flask import Blueprint, render_template, request
from database.models import ChainOfCustodyEvent, Case, db

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('/chain-of-custody')
def chain_of_custody():
    case_id = request.args.get('case_id', type=int)
    
    query = ChainOfCustodyEvent.query
    if case_id:
        query = query.filter_by(case_id=case_id)
        
    events = query.order_by(ChainOfCustodyEvent.timestamp.desc()).all()
    cases = Case.query.order_by(Case.name).all()
    current_case = db.session.get(Case, case_id) if case_id else None
    
    return render_template(
        'chain_of_custody.html',
        events=events,
        cases=cases,
        current_case=current_case
    )
