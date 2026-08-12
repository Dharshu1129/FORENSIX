import re
import datetime
from pathlib import Path

# Regular expressions for log formats
LINUX_AUTH_RE = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?: (?P<message>.+)$'
)

APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)

IP_ADDRESS_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class ForensicLogAnalyzer:
    @staticmethod
    def parse_log_file(file_path):
        """
        Reads text log file line by line and extracts timestamp, IP, username, event type, and severity.
        """
        p = Path(file_path)
        if not p.exists():
            return {'count': 0, 'entries': [], 'summary': {}}
            
        entries = []
        counts = {'NORMAL': 0, 'INTERESTING': 0, 'SUSPICIOUS': 0, 'CRITICAL': 0}
        
        current_year = datetime.datetime.now().year
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_no = 0
                for line in f:
                    line_no += 1
                    line_str = line.strip()
                    if not line_str:
                        continue
                        
                    entry = ForensicLogAnalyzer.parse_single_line(line_str, line_no, current_year)
                    if entry:
                        entries.append(entry)
                        severity = entry['label']
                        counts[severity] = counts.get(severity, 0) + 1

            return {
                'count': len(entries),
                'entries': entries,
                'summary': counts
            }
        except Exception as e:
            return {'count': 0, 'entries': [], 'error': str(e)}

    @staticmethod
    def parse_single_line(line, line_no, year):
        """Parses a single line of log data and assigns forensic metadata."""
        ip_match = IP_ADDRESS_RE.search(line)
        extracted_ip = ip_match.group(0) if ip_match else None
        
        # 1. Check Linux Auth Log
        auth_match = LINUX_AUTH_RE.match(line)
        if auth_match:
            month = auth_match.group('month')
            day = auth_match.group('day')
            time_str = auth_match.group('time')
            msg = auth_match.group('message')
            
            # Format ISO Timestamp
            dt_str = f"{month} {day} {time_str} {year}"
            try:
                dt = datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S %Y")
                iso_ts = dt.isoformat()
            except Exception:
                iso_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                
            username = ForensicLogAnalyzer.extract_username(msg)
            label, event_type = ForensicLogAnalyzer.classify_auth_message(msg)
            
            return {
                'line_number': line_no,
                'timestamp': iso_ts,
                'ip_address': extracted_ip,
                'username': username,
                'event_type': event_type,
                'label': label,
                'message': msg,
                'raw_line': line
            }

        # 2. Check Apache / Nginx Combined Log
        apache_match = APACHE_COMBINED_RE.match(line)
        if apache_match:
            ip = apache_match.group('ip')
            user = apache_match.group('user')
            ts_str = apache_match.group('timestamp') # e.g. 15/Jan/2026:10:30:00 +0000
            url = apache_match.group('url')
            status = apache_match.group('status')
            
            try:
                # 15/Jan/2026:10:30:00 +0000
                dt = datetime.datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                iso_ts = dt.isoformat()
            except Exception:
                iso_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                
            label = 'NORMAL'
            if status in ['401', '403']:
                label = 'INTERESTING'
            elif status in ['500', '502'] or '/admin' in url or '/etc/passwd' in url or 'union select' in url.lower():
                label = 'SUSPICIOUS'
                
            return {
                'line_number': line_no,
                'timestamp': iso_ts,
                'ip_address': ip,
                'username': user if user != '-' else None,
                'event_type': f"HTTP {apache_match.group('method')} ({status})",
                'label': label,
                'message': f"Request to {url} - Status {status}",
                'raw_line': line
            }
            
        # 3. Fallback generic log parsing
        label = 'NORMAL'
        if any(w in line.lower() for w in ['fail', 'error', 'invalid', 'denied', 'unauthorized']):
            label = 'INTERESTING'
        if any(w in line.lower() for w in ['exploit', 'root', 'attack', 'malware', 'backdoor', 'sqli']):
            label = 'SUSPICIOUS'
            
        return {
            'line_number': line_no,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'ip_address': extracted_ip,
            'username': None,
            'event_type': 'Log Event',
            'label': label,
            'message': line,
            'raw_line': line
        }

    @staticmethod
    def extract_username(msg):
        """Extracts username from authentication log messages."""
        patterns = [
            r'user (\S+)',
            r'for (\S+) from',
            r'user=(?P<u_eq>\S+)',
            r'Accepted \S+ for (\S+)',
            r'Failed \S+ for (\S+)'
        ]
        for p in patterns:
            m = re.search(p, msg)
            if m:
                u = m.group(1)
                if u not in ['invalid', 'password', 'user']:
                    return u
        return None

    @staticmethod
    def classify_auth_message(msg):
        """Classifies Linux authentication log severity and event type."""
        msg_lower = msg.lower()
        if 'failed password' in msg_lower or 'authentication failure' in msg_lower:
            return ('SUSPICIOUS', 'AUTHENTICATION_FAILURE')
        elif 'accepted password' in msg_lower or 'accepted publickey' in msg_lower:
            if 'for root' in msg_lower:
                return ('CRITICAL', 'ROOT_LOGIN_SUCCESS')
            return ('INTERESTING', 'LOGIN_SUCCESS')
        elif 'invalid user' in msg_lower:
            return ('SUSPICIOUS', 'INVALID_USER_ATTEMPT')
        elif 'session opened for user root' in msg_lower or 'sudo:' in msg_lower:
            return ('SUSPICIOUS', 'PRIVILEGE_ESCALATION')
        elif 'connection closed' in msg_lower:
            return ('NORMAL', 'DISCONNECT')
        return ('NORMAL', 'AUTH_EVENT')
