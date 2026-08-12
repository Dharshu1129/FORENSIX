# FORENSIX — Digital Forensics Evidence Analyzer

**FORENSIX** is a local, desktop-ready, web-based digital forensics evidence analysis platform engineered for digital investigators, cybersecurity researchers, and academic demonstrations.

---

## 1. Executive Summary & Problem Statement

Modern cybersecurity incidents require rigorous digital evidence handling. Investigators must ingest heterogeneous evidence sources (browser history databases, system event logs, executable files, documents, and media), establish strict cryptographic chain-of-custody, parse structural artifacts, correlate unified forensic timelines, and identify malicious anomalies—all without altering the original evidence.

**FORENSIX** solves this challenge by providing a modular, local, read-only evidence processing engine that automatically computes SHA-256 and MD5 hashes upon ingestion, preserves evidence integrity, parses SQLite browser databases & text logs, reconstructs unified event timelines, executes transparent rule-based threat detection, and compiles professional PDF forensic reports.

---

## 2. Technology Stack

- **Backend Framework**: Python 3.11+ & Flask
- **Database & ORM**: SQLite & SQLAlchemy
- **Data Analysis**: Pandas, Python Standard Library (`hashlib`, `sqlite3`, `mimetypes`, `pathlib`)
- **Image Metadata**: Pillow (PIL)
- **PDF Report Generation**: ReportLab
- **Frontend Interface**: HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
- **Automated Testing**: Pytest

---

## 3. Key Forensic Capabilities

1. **Case Management**: Unique automated case numbering (`FX-YYYY-XXXX`), tracking investigators, status (`Open`, `Under Investigation`, `Closed`), and evidence counts.
2. **Cryptographic Hashing & Integrity**: Streaming SHA-256 and MD5 hash baseline calculation on evidence upload; on-demand verification against current working copy with explicit `VERIFIED` or `FAILED` status flags.
3. **Immutable Chain of Custody**: Audit logging tracking evidence ingestion, hash calculations, integrity checks, analysis, and notes.
4. **Metadata & Signature Analysis**: System timestamps (created, modified, accessed), file permissions, hidden flags, header magic byte identification (`PDF`, `MZ`, `PNG`, `ZIP`, `SQLite`), and EXIF camera metadata extraction.
5. **Structural Anomaly & Extension Spoofing**: Static file property detection flagging double extensions (`invoice.pdf.exe`), extension mismatches (executable headers disguised as document files), and zero-byte files without code execution.
6. **SQLite Browser Artifact Parser**: Read-only Chrome/Edge and Firefox browser history and download parser converting microsecond timestamps to UTC ISO format.
7. **System & App Log Analyzer**: Parsing Linux `auth.log`, web server access logs (Apache/Nginx COMBINED format), and text logs. Classifies events into `NORMAL`, `INTERESTING`, `SUSPICIOUS`, and `CRITICAL`.
8. **Unified Forensic Timeline**: Normalized UTC event correlation across file operations, browser sessions, system log lines, and custody logs. Visual activity trend graphs powered by Chart.js.
9. **Transparent Rule Engine**: 10-rule deterministic detection engine flagging failed login spikes, double extension spoofing, off-hours activity, root escalation, suspicious downloads, and integrity mismatches with explicit reasons, confidence scores, and investigator recommendations.
10. **Entity Investigation**: Multi-field search correlating IP addresses, domain URLs, filenames, usernames, or email addresses across evidence files, artifacts, timeline, and rule findings.
11. **Professional PDF Reports**: Multi-page court-ready PDF compilation via ReportLab with cover page, executive summary, hash inventory, custody timeline, rule findings, investigator notes, conclusions, and scope limitations.
12. **Synthetic Demo Case Generator**: One-click generation (`"Generate Demo Case"`) creating case `FX-2026-DEMO` populated with sample SQLite browser databases, Linux auth logs, double-extension payload files, and EXIF images for instant testing.

---

## 4. Installation & Setup

### Prerequisites
- Python 3.11 or higher
- Git

### Windows Setup (PowerShell)

```powershell
# Clone or navigate to the project directory
cd "c:\Users\dhars\Desktop\Digital forensics"

# Create a virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch the application
python app.py
```

### Linux Setup (Bash)

```bash
# Navigate to project directory
cd Digital\ forensics

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Launch application
python3 app.py
```

---

## 5. Running the Application & Quick Demo

1. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```
2. Click the **"Generate Demo Case"** button on the top navbar or sidebar.
3. Case **`FX-2026-DEMO`** will be generated instantly with synthetic evidence files (`browser_history.db`, `auth.log`, `invoice.pdf.exe`, `exif_evidence.jpg`).
4. Inspect Evidence Details, verify baseline SHA-256 hashes, view extracted browser history & SSH logs, inspect the unified visual timeline, review transparent rule findings, and download the compiled PDF report!

---

## 6. Project Architecture

```
Digital forensics/
├── app.py                      # Application entry point & Flask initialization
├── config.py                   # Global configuration & directory setup
├── requirements.txt            # Python dependencies
├── README.md                   # Technical documentation & guide
├── .gitignore                  # Git ignore rules
│
├── database/
│   ├── __init__.py             # Database package exports
│   ├── database.py             # SQLAlchemy instance initialization
│   └── models.py               # ORM Models (Case, Evidence, Artifact, Timeline, Finding, Custody, Notes)
│
├── forensic/
│   ├── __init__.py
│   ├── hashing.py              # Cryptographic streaming hash calculation & verification
│   ├── evidence_manager.py     # Read-only file storage & archive handling
│   ├── metadata_analyzer.py    # Stat metadata, magic byte signatures, EXIF extraction
│   ├── file_analyzer.py        # Static structural anomaly & extension spoofing detector
│   ├── browser_parser.py       # Read-only SQLite browser history & download parser
│   ├── log_analyzer.py         # Log parser (Linux auth, Apache combined, Windows event text)
│   ├── keyword_search.py       # Evidence text & regex search engine with highlighted snippets
│   ├── timeline.py             # Unified timeline aggregation and normalization
│   ├── suspicious_activity.py  # Transparent 10-rule suspicious activity engine
│   ├── integrity.py            # Automated integrity check workflows
│   └── sample_generator.py     # Synthetic demonstration evidence generator (FX-2026-DEMO)
│
├── reports/
│   ├── __init__.py
│   └── report_generator.py     # ReportLab PDF report compiler
│
├── routes/
│   ├── __init__.py
│   ├── dashboard.py            # SOC Command dashboard & Chart.js API
│   ├── cases.py                # Case management CRUD & demo trigger
│   ├── evidence.py             # Evidence ingestion, hash calculation, detail view
│   ├── artifacts.py            # Extracted artifact browser
│   ├── timeline.py             # Unified timeline view & filter API
│   ├── investigation.py        # Entity correlation & search
│   ├── findings.py             # Suspicious findings triage
│   ├── reports.py              # PDF report preview & download
│   └── audit.py                # Chain of custody audit log viewer
│
├── uploads/                    # Read-only original evidence storage
├── working_evidence/          # Read-only working copy directory
├── generated_reports/         # Compiled PDF forensic reports
├── sample_evidence/           # Generated synthetic demo data
│
├── templates/                  # Bootstrap 5 dark SOC HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── cases.html
│   ├── create_case.html
│   ├── case_detail.html
│   ├── evidence.html
│   ├── evidence_detail.html
│   ├── artifacts.html
│   ├── timeline.html
│   ├── investigation.html
│   ├── findings.html
│   ├── chain_of_custody.html
│   └── report.html
│
├── static/                     # CSS & JS assets
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── dashboard.js
│       ├── timeline.js
│       └── investigation.js
│
└── tests/                      # Automated test suite
    ├── test_hashing.py
    ├── test_metadata.py
    ├── test_search.py
    ├── test_log_analyzer.py
    └── test_demo_case.py
```

---

## 7. Forensic Methodology

### Evidence Integrity & Read-Only Handling
- Uploaded evidence is stored in `uploads/<case_number>/` and marked read-only.
- A working copy is placed in `working_evidence/<case_number>/` for static parsing.
- Original evidence files are strictly **never executed or modified**.

### Hash Verification Workflow
1. Upon ingestion, SHA-256 and MD5 hashes are computed using 64KB streaming chunks.
2. Baseline hashes are saved in the database `evidence` record.
3. During re-verification, working copy hashes are recomputed and matched against baseline hashes. If mismatched, an explicit `FAILED` badge and critical alert are triggered.

### Rule-Based Suspicious Activity Engine
Findings are generated deterministically using transparent security rules:
- **Rule 1**: Failed authentication burst threshold (>= 3 failures from an IP within 5 mins).
- **Rule 2**: Extension spoofing / double extension detection (`invoice.pdf.exe`).
- **Rule 3**: Executable or script downloads via browser sessions.
- **Rule 4**: Cryptographic hash mismatch / evidence tampering.
- **Rule 5**: Direct root login or privilege escalation (`sudo /bin/su`).
- **Rule 6**: Significant off-hours activity (23:00 - 05:00 UTC).
- **Rule 7**: Suspicious keyword matches (`mimikatz`, `shadow`, `sql injection`).
- **Rule 8**: Username enumeration / invalid user attempts.

---

## 8. Running Automated Tests

Run all unit and integration tests using pytest:

```powershell
python -m pytest tests/ -v
```

---

## 9. Limitations & Future Enhancements

### Limitations
- Supported browser history databases currently cover SQLite schemas for Chromium (Chrome/Edge) and Mozilla Firefox.
- Memory forensics and RAM dump analysis require dedicated volatile memory tools (Volatility 3 integration).
- Unallocated space deleted file carving is not included in this release.

### Future Enhancements
- Volatility 3 RAM dump integration.
- Windows Registry hive parser (`NTUSER.DAT`, `SYSTEM`).
- YARA static signature rule scanning.
