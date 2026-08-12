import pytest
from forensic.keyword_search import ForensicKeywordSearch

def test_keyword_search_basic():
    content = "User logged in with password Secret123 from IP 192.168.1.100."
    snippets = ForensicKeywordSearch.search_text_content(content, "password")
    
    assert len(snippets) == 1
    assert snippets[0]['match'] == "password"
    assert "<mark" in snippets[0]['snippet']

def test_keyword_search_case_insensitive():
    content = "DETECTED MALWARE PAYLOAD EXPLOIT IN MEMORY"
    snippets = ForensicKeywordSearch.search_text_content(content, "malware", case_sensitive=False)
    
    assert len(snippets) == 1
    assert snippets[0]['match'] == "MALWARE"

def test_keyword_search_regex():
    content = "Connection from 10.0.0.5 and 192.168.1.105 recorded."
    regex_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    snippets = ForensicKeywordSearch.search_text_content(content, regex_ip, is_regex=True)
    assert len(snippets) == 2
