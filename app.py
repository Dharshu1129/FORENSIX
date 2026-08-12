import os
from flask import Flask, render_template
from config import Config
from database.database import db
from database import models # Ensure models are loaded before create_all

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize Configuration and Folders
    Config.init_app(app)
    
    # Initialize SQLAlchemy database
    db.init_app(app)
    
    # Register Blueprints
    from routes.dashboard import dashboard_bp
    from routes.cases import cases_bp
    from routes.evidence import evidence_bp
    from routes.artifacts import artifacts_bp
    from routes.timeline import timeline_bp
    from routes.investigation import investigation_bp
    from routes.findings import findings_bp
    from routes.reports import reports_bp
    from routes.audit import audit_bp
    
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(artifacts_bp)
    app.register_blueprint(timeline_bp)
    app.register_blueprint(investigation_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(audit_bp)
    
    # Global Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html', error_title="404 - Resource Not Found", error_msg="The requested forensic asset or route does not exist."), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('base.html', error_title="500 - System Error", error_msg="An unexpected exception occurred during forensic processing."), 500

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template('base.html', error_title="413 - File Size Exceeded", error_msg="Uploaded evidence exceeds maximum allowed upload size (100MB)."), 413

    # Initialize Database Tables automatically
    with app.app_context():
        db.create_all()
        
    return app

app = create_app()

if __name__ == '__main__':
    print("==================================================")
    print("  FORENSIX — Digital Forensics Evidence Analyzer  ")
    print("  Starting Local Forensic Examination Server      ")
    print("  URL: http://127.0.0.1:5000                     ")
    print("==================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
