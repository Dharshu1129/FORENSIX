import pytest
from app import create_app
from database.database import db
from database.models import Case, Evidence, Artifact, TimelineEvent, Finding, ChainOfCustodyEvent
from forensic.sample_generator import SyntheticEvidenceGenerator

@pytest.fixture
def app_instance():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

def test_generate_demo_case_end_to_end(app_instance):
    with app_instance.app_context():
        demo_case = SyntheticEvidenceGenerator.generate_demo_case()
        
        assert demo_case is not None
        assert demo_case.case_number == "FX-2026-DEMO"
        
        # Verify evidence items ingested
        evidence_items = Evidence.query.filter_by(case_id=demo_case.id).all()
        assert len(evidence_items) >= 4
        
        # Verify artifacts extracted
        artifacts = Artifact.query.filter_by(case_id=demo_case.id).all()
        assert len(artifacts) > 0
        
        # Verify timeline events generated
        timeline_events = TimelineEvent.query.filter_by(case_id=demo_case.id).all()
        assert len(timeline_events) > 0
        
        # Verify transparent rule findings generated
        findings = Finding.query.filter_by(case_id=demo_case.id).all()
        assert len(findings) > 0
        
        # Verify custody audit events
        custody_logs = ChainOfCustodyEvent.query.filter_by(case_id=demo_case.id).all()
        assert len(custody_logs) > 0

def test_flask_routes_and_404(app_instance):
    client = app_instance.test_client()
    
    # Test main routes
    assert client.get('/').status_code == 200
    assert client.get('/cases').status_code == 200
    assert client.get('/evidence').status_code == 200
    assert client.get('/artifacts').status_code == 200
    assert client.get('/timeline').status_code == 200
    assert client.get('/investigation').status_code == 200
    assert client.get('/findings').status_code == 200
    assert client.get('/chain-of-custody').status_code == 200
    assert client.get('/reports').status_code == 200
    
    # Test 404 error handler page rendering
    res = client.get('/non-existent-route-404')
    assert res.status_code == 404
    assert b"404 - Resource Not Found" in res.data
