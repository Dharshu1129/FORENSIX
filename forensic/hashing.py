import hashlib
from pathlib import Path

CHUNK_SIZE = 65536  # 64 KB chunks

def calculate_sha256(file_path):
    """Calculates SHA-256 hash of a file using chunked reading."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest().lower()

def calculate_md5(file_path):
    """Calculates MD5 hash of a file for legacy forensic compatibility using chunked reading."""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
    return md5.hexdigest().lower()

def calculate_file_hashes(file_path):
    """Calculates both SHA-256 and MD5 in a single pass to optimize IO."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            md5.update(chunk)
            
    return {
        'sha256': sha256.hexdigest().lower(),
        'md5': md5.hexdigest().lower()
    }

def verify_hash(file_path, expected_sha256, expected_md5=None):
    """
    Verifies file against expected SHA-256 and optional MD5 hash.
    Returns dict containing verification result and status.
    """
    current_hashes = calculate_file_hashes(file_path)
    sha256_match = (current_hashes['sha256'] == expected_sha256.lower())
    
    md5_match = True
    if expected_md5:
        md5_match = (current_hashes['md5'] == expected_md5.lower())
        
    is_valid = sha256_match and md5_match
    
    return {
        'verified': is_valid,
        'sha256_match': sha256_match,
        'md5_match': md5_match,
        'current_sha256': current_hashes['sha256'],
        'current_md5': current_hashes['md5'],
        'expected_sha256': expected_sha256.lower(),
        'expected_md5': expected_md5.lower() if expected_md5 else None
    }
