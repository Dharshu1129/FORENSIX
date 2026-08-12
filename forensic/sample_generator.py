import os
import json
import sqlite3
import datetime
import shutil
from pathlib import Path
from PIL import Image, ImageDraw

from config import Config
from database.models import Case, Evidence, Artifact, db, ChainOfCustodyEvent, InvestigatorNote
from forensic.hashing import calculate_file_hashes
from forensic.browser_parser import ForensicBrowserParser, CHROME_EPOCH_OFFSET
from forensic.log_analyzer import ForensicLogAnalyzer
from forensic.metadata_analyzer import ForensicMetadataAnalyzer
from forensic.timeline import ForensicTimelineBuilder
from forensic.suspicious_activity import ForensicSuspiciousActivityEngine

class SyntheticEvidenceGenerator:
    @staticmethod
    def generate_demo_case():
        """
        Creates a complete synthetic demonstration case (FX-2026-DEMO)
        with sample browser databases, Linux auth logs, apache logs, and files.
        Executes full forensic parsing pipeline end-to-end.
        """
        case_number = "FX-2026-DEMO"
        
        # Check if demo case exists
        existing = Case.query.filter_by(case_number=case_number).first()
        if existing:
            # Clean up existing demo case to recreate cleanly
            db.session.delete(existing)
            db.session.commit()

        # 1. Create Case Object
        demo_case = Case(
            case_number=case_number,
            name="Synthetic Cyber Incident Investigation (Demo)",
            investigator="Forensic Analyst (Demo)",
            description="SYNTHETIC DEMONSTRATION DATA - Case simulated for testing security event correlation, browser artifact extraction, log analysis, and hash integrity verification.",
            status="Under Investigation"
        )
        db.session.add(demo_case)
        db.session.commit()

        sample_dir = Config.SAMPLE_EVIDENCE_FOLDER / case_number
        sample_dir.mkdir(parents=True, exist_ok=True)
        
        upload_dir = Config.UPLOAD_FOLDER / case_number
        working_dir = Config.WORKING_EVIDENCE_FOLDER / case_number
        upload_dir.mkdir(parents=True, exist_ok=True)
        working_dir.mkdir(parents=True, exist_ok=True)

        evidences_created = []

        # -------------------------------------------------------------
        # Sample 1: Browser History SQLite Database
        # -------------------------------------------------------------
        chrome_db_path = sample_dir / "History"
        if chrome_db_path.exists():
            chrome_db_path.unlink()

        conn = sqlite3.connect(chrome_db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);")
        cur.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, total_bytes INTEGER, tab_url TEXT);")

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        def to_chrome_time(dt):
            us = int(dt.timestamp() * 1000000)
            return us + CHROME_EPOCH_OFFSET

        sample_urls = [
            ("https://company-intranet.local/dashboard", "Company Dashboard", 12, to_chrome_time(now_utc - datetime.timedelta(hours=5))),
            ("https://github.com/cybersecurity/forensics", "GitHub - Digital Forensics Tools", 4, to_chrome_time(now_utc - datetime.timedelta(hours=4))),
            ("http://192.168.1.105/admin/login.php", "Admin Portal Login", 8, to_chrome_time(now_utc - datetime.timedelta(hours=3))),
            ("http://malicious-c2-server.org/download/payload.exe", "Suspicious Payload Download", 1, to_chrome_time(now_utc - datetime.timedelta(hours=2))),
            ("https://stackoverflow.com/questions/python-forensics", "StackOverflow Python Forensics", 3, to_chrome_time(now_utc - datetime.timedelta(hours=1)))
        ]
        cur.executemany("INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)", sample_urls)

        sample_dl = [
            ("/home/user/Downloads/payload.exe", "/home/user/Downloads/payload.exe", to_chrome_time(now_utc - datetime.timedelta(hours=2)), 2048500, "http://malicious-c2-server.org/download/payload.exe"),
            ("/home/user/Downloads/invoice_2026.pdf", "/home/user/Downloads/invoice_2026.pdf", to_chrome_time(now_utc - datetime.timedelta(hours=4)), 512000, "https://company-intranet.local/docs/invoice_2026.pdf")
        ]
        cur.executemany("INSERT INTO downloads (current_path, target_path, start_time, total_bytes, tab_url) VALUES (?, ?, ?, ?, ?)", sample_dl)
        conn.commit()
        conn.close()

        # Copy to uploads and working evidence
        up_file_1 = upload_dir / "browser_history.db"
        work_file_1 = working_dir / "browser_history.db"
        shutil.copy2(chrome_db_path, up_file_1)
        shutil.copy2(chrome_db_path, work_file_1)
        
        # Evidence counter helper
        base_ev_count = Evidence.query.count()
        def next_ev_num(idx):
            return f"EVD-{(base_ev_count + idx):04d}"

        hashes_1 = calculate_file_hashes(up_file_1)
        ev1 = Evidence(
            evidence_number=next_ev_num(1),
            case_id=demo_case.id,
            original_filename="browser_history.db",
            stored_filename="browser_history.db",
            file_path=str(up_file_1),
            working_copy_path=str(work_file_1),
            file_type="Database / Browser History",
            mime_type="application/x-sqlite3",
            file_size=up_file_1.stat().st_size,
            sha256_hash=hashes_1['sha256'],
            md5_hash=hashes_1['md5'],
            description="SYNTHETIC DEMONSTRATION DATA - Chrome browser SQLite history & download database.",
            integrity_status="VERIFIED"
        )
        db.session.add(ev1)
        evidences_created.append(ev1)

        # -------------------------------------------------------------
        # Sample 2: Linux Auth Log File
        # -------------------------------------------------------------
        auth_log_path = sample_dir / "auth.log"
        time_str_1 = (now_utc - datetime.timedelta(minutes=45)).strftime("%b %d %H:%M:%S")
        time_str_2 = (now_utc - datetime.timedelta(minutes=44)).strftime("%b %d %H:%M:%S")
        time_str_3 = (now_utc - datetime.timedelta(minutes=43)).strftime("%b %d %H:%M:%S")
        time_str_4 = (now_utc - datetime.timedelta(minutes=40)).strftime("%b %d %H:%M:%S")
        time_str_5 = (now_utc - datetime.timedelta(minutes=35)).strftime("%b %d %H:%M:%S")

        log_content = f"""{time_str_1} server sshd[1042]: Failed password for invalid user admin from 192.168.1.100 port 41200 ssh2
{time_str_2} server sshd[1043]: Failed password for invalid user admin from 192.168.1.100 port 41202 ssh2
{time_str_3} server sshd[1044]: Failed password for invalid user admin from 192.168.1.100 port 41204 ssh2
{time_str_4} server sshd[1050]: Accepted password for analyst from 192.168.1.50 port 50122 ssh2
{time_str_5} server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/su - root
"""
        with open(auth_log_path, 'w', encoding='utf-8') as f:
            f.write(log_content)

        up_file_2 = upload_dir / "auth.log"
        work_file_2 = working_dir / "auth.log"
        shutil.copy2(auth_log_path, up_file_2)
        shutil.copy2(auth_log_path, work_file_2)

        hashes_2 = calculate_file_hashes(up_file_2)
        ev2 = Evidence(
            evidence_number=next_ev_num(2),
            case_id=demo_case.id,
            original_filename="auth.log",
            stored_filename="auth.log",
            file_path=str(up_file_2),
            working_copy_path=str(work_file_2),
            file_type="Log / Text File",
            mime_type="text/plain",
            file_size=up_file_2.stat().st_size,
            sha256_hash=hashes_2['sha256'],
            md5_hash=hashes_2['md5'],
            description="SYNTHETIC DEMONSTRATION DATA - Linux authentication log containing SSH attempts and sudo escalation.",
            integrity_status="VERIFIED"
        )
        db.session.add(ev2)
        evidences_created.append(ev2)

        # -------------------------------------------------------------
        # Sample 3: Suspicious Double Extension Executable File
        # -------------------------------------------------------------
        exe_spoof_path = sample_dir / "invoice.pdf.exe"
        # Write PE magic bytes "MZ" followed by dummy bytes
        with open(exe_spoof_path, 'wb') as f:
            f.write(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00SYNTHETIC_EXECUTABLE_PAYLOAD_DATA')

        up_file_3 = upload_dir / "invoice.pdf.exe"
        work_file_3 = working_dir / "invoice.pdf.exe"
        shutil.copy2(exe_spoof_path, up_file_3)
        shutil.copy2(exe_spoof_path, work_file_3)

        hashes_3 = calculate_file_hashes(up_file_3)
        ev3 = Evidence(
            evidence_number=next_ev_num(3),
            case_id=demo_case.id,
            original_filename="invoice.pdf.exe",
            stored_filename="invoice.pdf.exe",
            file_path=str(up_file_3),
            working_copy_path=str(work_file_3),
            file_type="Executable / Script",
            mime_type="application/x-dsexec",
            file_size=up_file_3.stat().st_size,
            sha256_hash=hashes_3['sha256'],
            md5_hash=hashes_3['md5'],
            description="SYNTHETIC DEMONSTRATION DATA - Executable payload disguised with document extension.",
            integrity_status="VERIFIED"
        )
        db.session.add(ev3)
        evidences_created.append(ev3)

        # -------------------------------------------------------------
        # Sample 4: Image File with EXIF Metadata
        # -------------------------------------------------------------
        img_path = sample_dir / "exif_evidence.jpg"
        img = Image.new('RGB', (400, 300), color=(20, 30, 45))
        d = ImageDraw.Draw(img)
        d.text((20, 20), "FORENSIX SAMPLE IMAGE", fill=(255, 255, 255))
        
        # Add basic EXIF info
        exif = img.getexif()
        exif[271] = "Forensic Cam X1" # Make
        exif[272] = "CyberShot 2026"  # Model
        exif[305] = "ForensiX Evidence Exchanger" # Software
        img.save(img_path, exif=exif)

        up_file_4 = upload_dir / "exif_evidence.jpg"
        work_file_4 = working_dir / "exif_evidence.jpg"
        shutil.copy2(img_path, up_file_4)
        shutil.copy2(img_path, work_file_4)

        hashes_4 = calculate_file_hashes(up_file_4)
        ev4 = Evidence(
            evidence_number=next_ev_num(4),
            case_id=demo_case.id,
            original_filename="exif_evidence.jpg",
            stored_filename="exif_evidence.jpg",
            file_path=str(up_file_4),
            working_copy_path=str(work_file_4),
            file_type="Image File",
            mime_type="image/jpeg",
            file_size=up_file_4.stat().st_size,
            sha256_hash=hashes_4['sha256'],
            md5_hash=hashes_4['md5'],
            description="SYNTHETIC DEMONSTRATION DATA - Sample image file containing camera EXIF metadata.",
            integrity_status="VERIFIED"
        )
        db.session.add(ev4)
        evidences_created.append(ev4)

        db.session.commit()

        # Record Initial Chain of Custody Log
        for ev in evidences_created:
            db.session.add(ChainOfCustodyEvent(
                case_id=demo_case.id,
                evidence_id=ev.id,
                event_action="Evidence Ingestion",
                investigator="Forensic Analyst (Demo)",
                description=f"Ingested synthetic evidence file {ev.original_filename}. SHA-256 baseline hash computed."
            ))
        db.session.commit()

        # -------------------------------------------------------------
        # Parse Evidence into Artifacts
        # -------------------------------------------------------------
        # 1. Parse Browser History DB
        browser_res = ForensicBrowserParser.parse_browser_database(ev1.working_copy_path)
        if browser_res['supported']:
            for item in browser_res['artifacts']:
                ts_dt = datetime.datetime.fromisoformat(item['timestamp']) if item.get('timestamp') else now_utc
                db.session.add(Artifact(
                    evidence_id=ev1.id,
                    case_id=demo_case.id,
                    artifact_type=item['artifact_type'],
                    timestamp=ts_dt,
                    source=item['browser'],
                    url=item.get('url'),
                    title=item.get('title'),
                    visit_count=item.get('visit_count', 1),
                    message=f"{item['activity']}: {item['title']}",
                    details_json=json.dumps(item)
                ))

        # 2. Parse Auth Log
        log_res = ForensicLogAnalyzer.parse_log_file(ev2.working_copy_path)
        for entry in log_res['entries']:
            ts_dt = datetime.datetime.fromisoformat(entry['timestamp']) if entry.get('timestamp') else now_utc
            db.session.add(Artifact(
                evidence_id=ev2.id,
                case_id=demo_case.id,
                artifact_type='log_entry',
                timestamp=ts_dt,
                source='Linux Auth Log',
                username=entry.get('username'),
                ip_address=entry.get('ip_address'),
                event_type=entry.get('event_type'),
                message=entry['message'],
                details_json=json.dumps(entry)
            ))

        db.session.commit()

        # -------------------------------------------------------------
        # Rebuild Timeline & Run Transparent Rule Engine
        # -------------------------------------------------------------
        ForensicTimelineBuilder.rebuild_case_timeline(demo_case.id)
        ForensicSuspiciousActivityEngine.run_case_analysis(demo_case.id)

        # Add initial investigator notes
        db.session.add(InvestigatorNote(
            case_id=demo_case.id,
            evidence_id=ev3.id,
            note="Synthetic Demo Note: Executable file disguised as PDF identified. SHA-256 hash verified.",
            investigator="Forensic Analyst (Demo)"
        ))
        db.session.commit()

        return demo_case
