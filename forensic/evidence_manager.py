import os
import shutil
import mimetypes
import zipfile
import tarfile
from pathlib import Path
from werkzeug.utils import secure_filename
from config import Config

class ForensicEvidenceManager:
    @staticmethod
    def sanitize_filename(filename):
        """Sanitizes uploaded filename safely."""
        cleaned = secure_filename(filename)
        if not cleaned:
            cleaned = "unnamed_evidence.dat"
        return cleaned

    @staticmethod
    def store_evidence_file(file_storage, case_number):
        """
        Saves incoming uploaded file to UPLOAD_FOLDER and creates a read-only copy in WORKING_EVIDENCE_FOLDER.
        Returns metadata dict containing file paths, size, and MIME type.
        """
        original_filename = file_storage.filename
        safe_name = ForensicEvidenceManager.sanitize_filename(original_filename)
        
        # Case specific subfolder
        case_upload_dir = Config.UPLOAD_FOLDER / case_number
        case_working_dir = Config.WORKING_EVIDENCE_FOLDER / case_number
        
        case_upload_dir.mkdir(parents=True, exist_ok=True)
        case_working_dir.mkdir(parents=True, exist_ok=True)
        
        # Unique target filename to avoid collision
        stored_filename = f"{os.urandom(4).hex()}_{safe_name}"
        upload_path = case_upload_dir / stored_filename
        working_path = case_working_dir / stored_filename
        
        # Save original file
        file_storage.save(upload_path)
        
        # Make original file read-only to preserve forensic integrity
        try:
            os.chmod(upload_path, 0o444) # Read-only
        except Exception:
            pass # Windows file permissions might differ, handles gracefully
            
        # Copy to working directory for analysis
        shutil.copy2(upload_path, working_path)
        try:
            os.chmod(working_path, 0o666) # Ensure working copy can be read/written by analysis engines
        except Exception:
            pass
        
        # Calculate file size & mime type
        file_size = upload_path.stat().st_size
        mime_type, _ = mimetypes.guess_type(upload_path)
        if not mime_type:
            mime_type = "application/octet-stream"
            
        file_type = ForensicEvidenceManager.classify_file_type(safe_name, mime_type)
        
        return {
            'original_filename': original_filename,
            'stored_filename': stored_filename,
            'file_path': str(upload_path),
            'working_copy_path': str(working_path),
            'file_size': file_size,
            'mime_type': mime_type,
            'file_type': file_type
        }

    @staticmethod
    def classify_file_type(filename, mime_type):
        """Classifies evidence into logical forensic categories."""
        fn_lower = filename.lower()
        
        if fn_lower.endswith(('.db', '.sqlite', '.sqlite3')) or 'sqlite' in mime_type:
            return 'Database / Browser History'
        elif fn_lower.endswith(('.log', '.txt')) or 'text' in mime_type:
            return 'Log / Text File'
        elif fn_lower.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff')):
            return 'Image File'
        elif fn_lower.endswith(('.pdf', '.docx', '.xlsx', '.pptx', '.csv', '.json')):
            return 'Document / Data'
        elif fn_lower.endswith(('.zip', '.tar', '.gz', '.7z', '.rar')):
            return 'Archive File'
        elif fn_lower.endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs', '.elf', '.sh')):
            return 'Executable / Script'
        return 'Binary / Unknown'

    @staticmethod
    def extract_archive_evidence(archive_path, extract_dir):
        """Safely extracts ZIP/TAR archive without path traversal vulnerability."""
        extract_dir = Path(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)
        extracted_files = []
        
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    # Path traversal protection
                    target_path = extract_dir / member.filename
                    if not target_path.resolve().is_relative_to(extract_dir.resolve()):
                        continue # Skip malicious relative path entry
                    if member.is_dir():
                        target_path.mkdir(parents=True, exist_ok=True)
                    else:
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        with zip_ref.open(member) as source, open(target_path, "wb") as target:
                            shutil.copyfileobj(source, target)
                        extracted_files.append(target_path)
        return extracted_files
