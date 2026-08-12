import pytest
import os
from app import create_app
from database.database import db
from forensic.sample_generator import SyntheticEvidenceGenerator
from reports.report_generator import ForensicReportGenerator

def test_report_generation():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })
    with app.app_context():
        db.create_all()
        demo_case = SyntheticEvidenceGenerator.generate_demo_case()
        pdf_path = ForensicReportGenerator.generate_pdf_report(demo_case.id)
        
        assert pdf_path is not None
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 0
