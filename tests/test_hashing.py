import pytest
import os
import hashlib
from forensic.hashing import calculate_sha256, calculate_md5, calculate_file_hashes, verify_hash

def test_hash_calculation(tmp_path):
    sample_file = tmp_path / "test_evidence.txt"
    content = b"FORENSIX_TEST_EVIDENCE_DATA_12345"
    sample_file.write_bytes(content)
    
    expected_sha256 = hashlib.sha256(content).hexdigest().lower()
    expected_md5 = hashlib.md5(content).hexdigest().lower()
    
    sha256_result = calculate_sha256(sample_file)
    md5_result = calculate_md5(sample_file)
    combined = calculate_file_hashes(sample_file)
    
    assert sha256_result == expected_sha256
    assert md5_result == expected_md5
    assert combined['sha256'] == expected_sha256
    assert combined['md5'] == expected_md5

def test_hash_verification_success(tmp_path):
    sample_file = tmp_path / "valid.dat"
    content = b"Valid evidence file content"
    sample_file.write_bytes(content)
    
    hashes = calculate_file_hashes(sample_file)
    verification = verify_hash(sample_file, hashes['sha256'], hashes['md5'])
    
    assert verification['verified'] is True
    assert verification['sha256_match'] is True
    assert verification['md5_match'] is True

def test_hash_verification_mismatch(tmp_path):
    sample_file = tmp_path / "tampered.dat"
    sample_file.write_bytes(b"Original content")
    
    hashes = calculate_file_hashes(sample_file)
    
    # Tamper with file content
    sample_file.write_bytes(b"Modified tampered content!")
    
    verification = verify_hash(sample_file, hashes['sha256'], hashes['md5'])
    
    assert verification['verified'] is False
    assert verification['sha256_match'] is False
