import os
from pathlib import Path
from forensic.metadata_analyzer import ForensicMetadataAnalyzer

SUSPICIOUS_EXECUTABLE_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.elf', '.sh', '.htc']
DOCUMENT_IMAGE_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.txt']

class ForensicFileAnalyzer:
    @staticmethod
    def analyze_file(file_path, original_filename):
        """
        Performs static structural file analysis without executing the file.
        Detects extension spoofing, double extensions, hidden status, and anomalies.
        """
        p = Path(file_path)
        issues = []
        is_suspicious = False
        
        # 1. Double extension check
        parts = original_filename.split('.')
        if len(parts) > 2:
            second_last_ext = f".{parts[-2].lower()}"
            last_ext = f".{parts[-1].lower()}"
            
            if second_last_ext in DOCUMENT_IMAGE_EXTENSIONS and last_ext in SUSPICIOUS_EXECUTABLE_EXTENSIONS:
                is_suspicious = True
                issues.append({
                    'type': 'DOUBLE_EXTENSION',
                    'severity': 'HIGH',
                    'reason': f"File has a deceptive double extension '{original_filename}'. Appears as a document/image but is an executable."
                })
                
        # 2. Magic byte / Extension Mismatch check
        magic_info = ForensicMetadataAnalyzer.get_magic_signature(p)
        ext = p.suffix.lower()
        
        if magic_info['matched']:
            desc = magic_info['description']
            if 'Executable' in desc and ext not in SUSPICIOUS_EXECUTABLE_EXTENSIONS:
                is_suspicious = True
                issues.append({
                    'type': 'EXTENSION_MISMATCH',
                    'severity': 'CRITICAL',
                    'reason': f"Extension Mismatch: Header magic bytes indicate '{desc}' (Header: {magic_info['signature_bytes']}) but extension is '{ext}'."
                })
            elif 'ZIP Archive' in desc and ext not in ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk']:
                issues.append({
                    'type': 'EXTENSION_MISMATCH',
                    'severity': 'MEDIUM',
                    'reason': f"Header magic bytes indicate ZIP archive but file extension is '{ext}'."
                })
            elif 'PDF Document' in desc and ext != '.pdf':
                issues.append({
                    'type': 'EXTENSION_MISMATCH',
                    'severity': 'HIGH',
                    'reason': f"Header magic bytes indicate PDF document but extension is '{ext}'."
                })
                
        # 3. Hidden File Detection
        if original_filename.startswith('.') or (os.name == 'nt' and original_filename.startswith('$')):
            issues.append({
                'type': 'HIDDEN_FILE',
                'severity': 'LOW',
                'reason': f"File '{original_filename}' is marked as a hidden or system file."
            })
            
        # 4. Zero byte / Suspiciously small file check
        try:
            size = p.stat().st_size
            if size == 0:
                issues.append({
                    'type': 'ZERO_BYTE_FILE',
                    'severity': 'INFORMATIONAL',
                    'reason': "File size is 0 bytes (empty file)."
                })
        except Exception:
            pass

        return {
            'is_suspicious': is_suspicious or len(issues) > 0,
            'issue_count': len(issues),
            'issues': issues,
            'magic_info': magic_info
        }
