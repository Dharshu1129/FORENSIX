from datetime import datetime, timezone
import json
from database.models import Finding, Artifact, Evidence, Case, db
from forensic.file_analyzer import ForensicFileAnalyzer

SUSPICIOUS_KEYWORDS = ['password', 'shadow', 'mimikatz', 'exploit', 'unauthorized', 'sql injection', 'union select', 'backdoor', 'shell', 'payload']

class ForensicSuspiciousActivityEngine:
    @staticmethod
    def run_case_analysis(case_id):
        """
        Executes all transparent rule-based checks on a case.
        Clears previous findings for re-analysis and generates new Finding records.
        Returns count of findings generated.
        """
        # Remove previous automated findings for case
        Finding.query.filter_by(case_id=case_id).delete()
        
        findings = []
        finding_counter = 1
        
        # Fetch case evidence & artifacts
        evidence_items = Evidence.query.filter_by(case_id=case_id).all()
        artifacts = Artifact.query.filter_by(case_id=case_id).all()
        
        # -------------------------------------------------------------
        # RULE 1 & 8: Multiple Failed Logins & Invalid User Attempts
        # -------------------------------------------------------------
        failed_logins_by_ip = {}
        invalid_users = []
        
        for art in artifacts:
            if art.artifact_type == 'log_entry':
                details = art.get_details()
                event_type = art.event_type or ''
                ip = art.ip_address or 'Unknown_IP'
                
                if 'AUTHENTICATION_FAILURE' in event_type or 'INVALID_USER' in event_type or (art.message and 'failed password' in art.message.lower()):
                    if ip not in failed_logins_by_ip:
                        failed_logins_by_ip[ip] = []
                    failed_logins_by_ip[ip].append(art)
                    
                if 'INVALID_USER' in event_type or (art.message and 'invalid user' in art.message.lower()):
                    invalid_users.append(art)
                    
        # Process failed login threshold (>= 3 attempts)
        for ip, log_list in failed_logins_by_ip.items():
            if len(log_list) >= 3:
                fnd_num = f"FND-{finding_counter:04d}"
                finding_counter += 1
                findings.append(Finding(
                    finding_number=fnd_num,
                    case_id=case_id,
                    evidence_id=log_list[0].evidence_id,
                    rule_id='RULE_01_FAILED_LOGINS',
                    rule_name='Multiple Failed Authentication Attempts',
                    category='Authentication Anomaly',
                    severity='HIGH' if len(log_list) < 10 else 'CRITICAL',
                    reason=f"Recorded {len(log_list)} failed login attempts originating from IP address {ip}.",
                    explanation=f"A threshold of >=3 failed authentication attempts was exceeded for IP {ip}. Repeated login failures are indicative of automated brute-force or credential-stuffing attacks.",
                    recommended_action="Correlate IP address with firewall logs, block IP if external, and inspect target account status for compromise.",
                    confidence='HIGH'
                ))

        if len(invalid_users) >= 2:
            fnd_num = f"FND-{finding_counter:04d}"
            finding_counter += 1
            findings.append(Finding(
                finding_number=fnd_num,
                case_id=case_id,
                evidence_id=invalid_users[0].evidence_id,
                rule_id='RULE_08_INVALID_USERS',
                rule_name='Repeated Invalid Username Authentication Attempts',
                category='Authentication Anomaly',
                severity='HIGH',
                reason=f"Recorded {len(invalid_users)} authentication attempts specifying non-existent or invalid usernames.",
                explanation="Attempts to log into non-existent user accounts indicate username enumeration or brute-force scanning using external user dictionaries.",
                recommended_action="Review authentication log sources and restrict remote SSH/RDP access.",
                confidence='HIGH'
            ))

        # -------------------------------------------------------------
        # RULE 2: Suspicious File Extension Mismatch / Double Extension
        # -------------------------------------------------------------
        for ev in evidence_items:
            # Analyze physical working file
            if ev.working_copy_path or ev.file_path:
                target_path = ev.working_copy_path or ev.file_path
                file_analysis = ForensicFileAnalyzer.analyze_file(target_path, ev.original_filename)
                
                for issue in file_analysis['issues']:
                    fnd_num = f"FND-{finding_counter:04d}"
                    finding_counter += 1
                    findings.append(Finding(
                        finding_number=fnd_num,
                        case_id=case_id,
                        evidence_id=ev.id,
                        rule_id=f"RULE_02_{issue['type']}",
                        rule_name=f"File Structural Anomaly: {issue['type']}",
                        category='File System Anomaly',
                        severity=issue['severity'],
                        reason=issue['reason'],
                        explanation=f"Static file header inspection revealed structural anomalies in file '{ev.original_filename}'. Cyber adversaries often disguise executable code with document extensions to deceive users.",
                        recommended_action="Isolate file, perform static analysis in sandbox, check file hash against threat databases (VirusTotal).",
                        confidence='HIGH'
                    ))

        # -------------------------------------------------------------
        # RULE 3: Suspicious Web Downloads / Suspicious URLs
        # -------------------------------------------------------------
        for art in artifacts:
            if art.artifact_type == 'browser_download' or (art.url and any(art.url.lower().endswith(ext) for ext in ['.exe', '.zip', '.vbs', '.sh', '.bat', '.ps1'])):
                fnd_num = f"FND-{finding_counter:04d}"
                finding_counter += 1
                findings.append(Finding(
                    finding_number=fnd_num,
                    case_id=case_id,
                    evidence_id=art.evidence_id,
                    rule_id='RULE_03_SUSPICIOUS_DOWNLOAD',
                    rule_name='Suspicious File Download via Browser',
                    category='Browser Anomaly',
                    severity='HIGH',
                    reason=f"Browser artifact recorded a download of an executable or archive file: '{art.title}' from URL '{art.url}'.",
                    explanation="Executable or script downloads via browser sessions present a high risk of drive-by malware delivery or unauthorized payload retrieval.",
                    recommended_action="Verify user intent, cross-reference download timestamp with host creation timestamps.",
                    confidence='MEDIUM'
                ))

        # -------------------------------------------------------------
        # RULE 4: Evidence Integrity Status Mismatch
        # -------------------------------------------------------------
        for ev in evidence_items:
            if ev.integrity_status == 'FAILED':
                fnd_num = f"FND-{finding_counter:04d}"
                finding_counter += 1
                findings.append(Finding(
                    finding_number=fnd_num,
                    case_id=case_id,
                    evidence_id=ev.id,
                    rule_id='RULE_04_INTEGRITY_MISMATCH',
                    rule_name='Evidence Cryptographic Hash Mismatch',
                    category='Forensic Integrity',
                    severity='CRITICAL',
                    reason=f"Evidence '{ev.original_filename}' ({ev.evidence_number}) failed cryptographic SHA-256 verification.",
                    explanation="The calculated SHA-256 hash does not match the baseline acquisition hash stored during evidence ingestion. The evidence file has been modified, corrupted, or tampered with.",
                    recommended_action="Immediately quarantine working copy, inspect file system access logs, and re-acquire pristine evidence copy from original source.",
                    confidence='HIGH'
                ))

        # -------------------------------------------------------------
        # RULE 5: Root / Privileged Access Attempt
        # -------------------------------------------------------------
        for art in artifacts:
            if art.artifact_type == 'log_entry':
                event_type = art.event_type or ''
                msg = art.message or ''
                if 'ROOT_LOGIN' in event_type or 'PRIVILEGE_ESCALATION' in event_type or 'root' in (art.username or '').lower():
                    fnd_num = f"FND-{finding_counter:04d}"
                    finding_counter += 1
                    findings.append(Finding(
                        finding_number=fnd_num,
                        case_id=case_id,
                        evidence_id=art.evidence_id,
                        rule_id='RULE_05_ROOT_PRIVILEGE',
                        rule_name='Privileged Root Account Login or Escalation',
                        category='Privilege Escalation',
                        severity='HIGH',
                        reason=f"Privileged root activity detected: '{msg}'.",
                        explanation="Direct root logins or successful privilege escalations bypass standard user auditing and present a serious security boundary breach if unexpected.",
                        recommended_action="Validate authorization of root access session and verify root audit logs.",
                        confidence='HIGH'
                    ))

        # -------------------------------------------------------------
        # RULE 6: Activity Outside Standard Business Hours (23:00 - 05:00)
        # -------------------------------------------------------------
        off_hour_events = []
        for art in artifacts:
            if art.timestamp:
                hour = art.timestamp.hour
                if 23 <= hour or hour <= 4:
                    off_hour_events.append(art)
                    
        if len(off_hour_events) >= 5:
            fnd_num = f"FND-{finding_counter:04d}"
            finding_counter += 1
            findings.append(Finding(
                finding_number=fnd_num,
                case_id=case_id,
                evidence_id=off_hour_events[0].evidence_id,
                rule_id='RULE_06_OFF_HOURS_ACTIVITY',
                rule_name='Significant Off-Hours Activity Recorded',
                category='Operational Anomaly',
                severity='MEDIUM',
                reason=f"Observed {len(off_hour_events)} activity events occurring outside standard business hours (between 23:00 and 05:00 UTC).",
                explanation="Unusual activity volumes during non-business hours may indicate automated malware execution, unauthorized insider access, or exfiltration activities.",
                recommended_action="Cross-reference off-hours event timestamps with physical access control and user shift rosters.",
                confidence='MEDIUM'
            ))

        # -------------------------------------------------------------
        # RULE 7: Known Suspicious Keywords in Log / Browser / Text
        # -------------------------------------------------------------
        keyword_hits = []
        for art in artifacts:
            searchable_text = f"{art.message or ''} {art.url or ''} {art.title or ''}".lower()
            found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in searchable_text]
            if found_kw:
                keyword_hits.append((art, found_kw))
                
        if keyword_hits:
            for art, kws in keyword_hits[:5]: # Cap findings to avoid spam
                fnd_num = f"FND-{finding_counter:04d}"
                finding_counter += 1
                findings.append(Finding(
                    finding_number=fnd_num,
                    case_id=case_id,
                    evidence_id=art.evidence_id,
                    rule_id='RULE_07_SUSPICIOUS_KEYWORD',
                    rule_name='Suspicious Keyword Match in Artifact Data',
                    category='Content Anomaly',
                    severity='MEDIUM',
                    reason=f"Artifact contained suspicious forensic keyword(s): {', '.join(kws)}.",
                    explanation=f"Text content matching security-sensitive terms '{', '.join(kws)}' was discovered in evidence source '{art.source}'.",
                    recommended_action="Inspect full raw line context using the Keyword Search module.",
                    confidence='HIGH'
                ))

        # Save findings
        db.session.add_all(findings)
        db.session.commit()
        
        return len(findings)
