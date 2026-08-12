import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Check if running in Vercel Serverless environment
IS_VERCEL = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None

if IS_VERCEL:
    DATA_DIR = Path('/tmp')
else:
    DATA_DIR = BASE_DIR

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'forensix-digital-forensics-secure-key-2026')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{DATA_DIR / "forensix.db"}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Forensic Evidence Directories
    UPLOAD_FOLDER = DATA_DIR / 'uploads'
    WORKING_EVIDENCE_FOLDER = DATA_DIR / 'working_evidence'
    REPORT_FOLDER = DATA_DIR / 'generated_reports'
    SAMPLE_EVIDENCE_FOLDER = DATA_DIR / 'sample_evidence'
    
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload limit
    
    @staticmethod
    def init_app(app):
        # Ensure critical forensic directories exist
        for folder in [
            Config.UPLOAD_FOLDER,
            Config.WORKING_EVIDENCE_FOLDER,
            Config.REPORT_FOLDER,
            Config.SAMPLE_EVIDENCE_FOLDER
        ]:
            try:
                folder.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

