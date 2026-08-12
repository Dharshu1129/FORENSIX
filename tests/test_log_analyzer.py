import pytest
from forensic.log_analyzer import ForensicLogAnalyzer

def test_linux_auth_log_parsing(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Jan 15 10:15:30 server sshd[1042]: Failed password for invalid user admin from 192.168.1.100 port 41200 ssh2\n"
        "Jan 15 10:20:00 server sshd[1045]: Accepted password for root from 10.0.0.5 port 50122 ssh2\n"
    )
    
    result = ForensicLogAnalyzer.parse_log_file(log_file)
    assert result['count'] == 2
    
    entry1 = result['entries'][0]
    assert entry1['ip_address'] == '192.168.1.100'
    assert entry1['label'] == 'SUSPICIOUS'
    assert entry1['username'] == 'admin'
    
    entry2 = result['entries'][1]
    assert entry2['ip_address'] == '10.0.0.5'
    assert entry2['label'] == 'CRITICAL' # Root login
    assert entry2['username'] == 'root'

def test_apache_access_log_parsing(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(
        '192.168.1.105 - admin [15/Jan/2026:10:30:00 +0000] "GET /admin/config.php HTTP/1.1" 401 4500\n'
    )
    
    result = ForensicLogAnalyzer.parse_log_file(log_file)
    assert result['count'] == 1
    entry = result['entries'][0]
    assert entry['ip_address'] == '192.168.1.105'
    assert entry['label'] == 'INTERESTING' # Status 401
