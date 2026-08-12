import pytest
from forensic.metadata_analyzer import ForensicMetadataAnalyzer
from forensic.file_analyzer import ForensicFileAnalyzer

def test_magic_signature_pdf(tmp_path):
    pdf_file = tmp_path / "sample.pdf"
    pdf_file.write_bytes(b"%PDF-1.4 header data sample...")
    
    magic_info = ForensicMetadataAnalyzer.get_magic_signature(pdf_file)
    assert magic_info['matched'] is True
    assert 'PDF Document' in magic_info['description']

def test_extension_spoof_detection(tmp_path):
    # Executable magic bytes with PDF filename
    spoof_file = tmp_path / "fake_document.pdf"
    spoof_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00Dummy executable header")
    
    analysis = ForensicFileAnalyzer.analyze_file(spoof_file, "fake_document.pdf")
    assert analysis['is_suspicious'] is True
    assert any(issue['type'] == 'EXTENSION_MISMATCH' for issue in analysis['issues'])

def test_double_extension_detection(tmp_path):
    double_ext_file = tmp_path / "invoice.pdf.exe"
    double_ext_file.write_bytes(b"MZ header")
    
    analysis = ForensicFileAnalyzer.analyze_file(double_ext_file, "invoice.pdf.exe")
    assert analysis['is_suspicious'] is True
    assert any(issue['type'] == 'DOUBLE_EXTENSION' for issue in analysis['issues'])
