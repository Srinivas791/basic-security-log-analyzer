# Basic Security Log Analyzer – BUILDERS Phase 2
### Defensive Cybersecurity & Authentication Incident Analysis System
**Domain: Cybersecurity / Defensive Security (MITRE ATT&CK T1110 Framework Alignment)**

---

## 1. Project Objective & Abstract

The **Basic Security Log Analyzer** is a Python-based security log analysis and defensive monitoring application engineered to ingest fictional and approved public authentication logs (.txt and .csv) and automatically detect suspicious login behavior.

The system focuses on identifying:
* **Repeated Failed Login Attempts** targeting high-value or privileged accounts (e.g., `admin`, `root`).
* **Unusual Bursts of Failed Authentication Attempts** within configurable sliding time windows.
* **Horizontal Credential Spraying Patterns** originating from individual IP addresses across multiple accounts.
* **Corrupted, Blank, and Malformed Records** without crashing, cleanly segregating valid and invalid data.

Designed strictly as a **defensive security intelligence and reporting platform**, the tool empowers Security Operations Center (SOC) analysts, incident responders, and system administrators to evaluate threat levels, inspect forensic audit trails, and export multi-format reports without collecting real credentials or disrupting production account states.

---

## 2. Core Features

### 1. Log File Reader & Resilient Parser (`log_parser.py`)
* **Multi-Format Ingestion**: Supports `.txt` (Syslog, Key-Value, Apache auth, bracketed formats) and `.csv` files.
* **Field Extraction**: Accurately extracts `timestamp`, `username`, `status` (normalized to `SUCCESS` or `FAILED`), `source_ip` (IPv4 and IPv6), and `service` (SSH, Web-Portal, VPN, API).
* **Fault Tolerance**: Safely handles empty lines, missing timestamps, corrupted status strings, and malformed characters without crashing.
* **Segregation of Records**: Displays valid records and invalid/malformed records in separate, dedicated diagnostic views with exact line numbers and explanatory error reasons.

### 2. Failed Login Detection & Alerting (`failed_login.py`)
* **User-Level Aggregation**: Counts unsuccessful logins, successful logins, failure-to-success percentages, and associated source IPs for every account.
* **Configurable Alert Threshold**: Interactive slider (1 to 10 failures) dynamically flags accounts that exceed the alert threshold.
* **IP Origin Analysis**: Computes total failed requests per IP, counts distinct targeted accounts, and flags **Horizontal Credential Spraying Bots** vs **Targeted Brute-Force Origins**.
* **Severity Grading**: Classifies threats into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.

### 3. Timestamp & Burst Detection (`burst_detector.py`)
* **Temporal Velocity Analysis**: Chronologically sorts failed events and applies a sliding-window clustering algorithm.
* **Configurable Window & Threshold**: Allows analysts to adjust burst thresholds (3 to 10 attempts) and sliding time windows (10 to 300 seconds).
* **Cluster Deduplication**: Merges overlapping sub-windows into unified incident clusters (`BURST-001`, `BURST-002`, etc.) to prevent duplicate alert noise.
* **Pattern Classification**: Differentiates between *Targeted Account Bursts*, *High-Volume Automated Brute-Force*, and *Horizontal Credential Spraying*.

### 4. Interactive Summary Dashboard
* **Real-Time KPI Metric Cards**:
  * Total Log Records (Valid vs Invalid breakdown).
  * Successful Login Attempts.
  * Failed Login Attempts & Failure Rate Percentage.
  * Number of Affected Accounts.
  * Number of Active Suspicious Alerts.
* **Interactive Visualizations (Chart.js)**:
  * *Authentication Outcomes* (Doughnut chart: Success vs Failed vs Malformed).
  * *Authentication Velocity Timeline* (Line chart over time buckets).
  * *Top Targeted User Accounts* (Horizontal bar chart).
  * *Top Malicious Source IPs* (Horizontal bar chart).
* **Recent Activity Stream**: Displays latest parsed log records with live status pills and raw extracts.

### 5. Multi-Format Security Reports & Testing (`report_and_tests.py`)
* **Objective Threat Score**: Calculates a composite 0–100 Risk Score (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) based on failure ratio, burst volume, and high-risk targets.
* **Actionable Defensive Recommendations**: Synthesizes concrete perimeter and IAM mitigations (IP rate-limiting, MFA enforcement, CAPTCHA challenges, SIEM correlation).
* **Download Formats**:
  * `JSON Report` (`/api/download/report/json`) – Machine-readable schema.
  * `CSV Audit` (`/api/download/report/csv`) – Multi-table spreadsheet export.
  * `Executive Text Report` (`/api/download/report/text`) – Formatted ASCII/text audit summary.
* **Automated Verification Test Suite**: In-browser and CLI test runner covering 5 comprehensive test cases.

---

## 3. Technology Stack

* **Backend**: Python 3.10+
* **Web Framework**: Flask 3.1+
* **Frontend**: HTML5, CSS3, Modern Dark Cyber Theme, JavaScript (ES6)
* **Visualizations**: Chart.js 4.4+ (interactive responsive charts)
* **Data Processing**: Python Standard Libraries (`csv`, `re`, `datetime`, `collections`, `io`, `time`)
* **Architecture**: Modular Python service with REST API endpoints

---

## 4. Project Architecture

The codebase is organized into modular Python files adhering to clean separation of concerns:

```text
├── main.py                 # Main Flask application, routing, and REST API controllers
├── log_parser.py           # Ingestion, regex parsing, sanitization, valid/invalid separation
├── failed_login.py         # Failure aggregation by user/IP, threshold breach detection, severity
├── burst_detector.py       # Sliding-window algorithm, temporal burst clustering, velocity calculation
├── report_and_tests.py     # Threat scoring, multi-format report generation, 5 automated test cases
├── sample_logs.txt         # Fictional text authentication log dataset with attack scenarios
├── sample_logs.csv         # Fictional CSV authentication log dataset
├── requirements.txt        # Python package dependencies
├── run.bat                 # One-click Windows application launcher
├── test_runner.bat         # One-click Windows test suite executor
├── templates/              # Jinja2 HTML templates (Cybersecurity Dark UI)
│   ├── base.html           # Common layout shell, responsive sidebar, status header
│   ├── dashboard.html      # 1. Home / Dashboard with KPI cards and Chart.js graphs
│   ├── upload.html         # 2. Upload Log Files with Drag & Drop and Malformed record inspection
│   ├── logs.html           # 3. Log Analysis with live search, status filtering, and service filters
│   ├── failed_logins.html  # 4. Failed Login Detection with interactive threshold slider
│   ├── bursts.html         # 5. Burst Detection with sliding window controls and incident table
│   ├── reports.html        # 6. Security Reports with threat gauge, mitigations, and downloads
│   ├── tests.html          # 7. Testing Results with live automated test runner
│   └── about.html          # 8. About Project with defensive principles and MITRE ATT&CK mapping
└── static/
    ├── css/
    │   └── cyber_theme.css # Cyber dark aesthetic, glassmorphism, responsive sidebar
    └── js/
        └── dashboard.js    # Interactive frontend engine, Chart.js config, test runner, filters
```

---

## 5. Main Pages (8 Core Views)

| # | Page Name | Route | Description |
|---|---|---|---|
| 1 | **Home / Dashboard** | `/` or `/dashboard` | Executive KPI cards, threat risk meter, 4 Chart.js interactive charts, and recent activity log stream. |
| 2 | **Upload Log Files** | `/upload` | Drag-and-drop file upload for `.txt` and `.csv`, sample log loaders, and split diagnostic tabs for Valid vs Invalid/Malformed records. |
| 3 | **Log Analysis** | `/logs` | Searchable, filterable table of all parsed authentication records with status badges (SUCCESS/FAILED) and service tags. |
| 4 | **Failed Login Detection** | `/failed-logins` | Threshold slider, accounts with repeated failures, target accounts table, and credential spraying detection by IP. |
| 5 | **Burst Detection** | `/bursts` | Sliding-window threshold and window controls, peak velocity metrics, and burst incidents table with event counts. |
| 6 | **Security Reports** | `/reports` | Overall threat score (0–100), actionable defensive mitigations, live report preview, and download buttons (JSON, CSV, Text). |
| 7 | **Testing Results** | `/tests` | Interactive test runner displaying status (PASS/FAIL), duration in milliseconds, and individual assertions for all 5 test cases. |
| 8 | **About Project** | `/about` | Project scope, defensive security constraints, ethical rules, and MITRE ATT&CK matrix alignment. |

---

## 6. Security Requirements & Ethical Safeguards

1. **Defensive Analysis Scope**:
   * The tool operates exclusively as an observational, analytical, and audit platform.
   * It **does not** automatically lock user accounts, change credentials, or modify directory services.
2. **Zero Credential Harvesting**:
   * The parser extracts only metadata (`timestamp`, `username`, `status`, `source_ip`, `service`).
   * Passwords, tokens, and secret credentials are never captured, parsed, or stored.
3. **Fictional & Sanctioned Data**:
   * All default sample logs employ RFC 5737 documentation address ranges:
     * `192.0.2.0/24` (TEST-NET-1)
     * `198.51.100.0/24` (TEST-NET-2)
     * `203.0.113.0/24` (TEST-NET-3)
     * RFC 1918 Private Ranges (`192.168.x.x`, `10.x.x.x`, `172.16.x.x`).
   * No real production systems or identifiable personal credentials are used.

---

## 7. Automated Test Suite (5 Comprehensive Test Cases)

The project includes an automated test engine in `report_and_tests.py` fulfilling all prompt requirements:

```text
================================================================================
TEST CASE BREAKDOWN & VERIFICATION CRITERIA
================================================================================
TC-01: Normal Activity Verification
  - Purpose: Validates benign authentication patterns (legitimate logins, 1 isolated typo).
  - Assertions: 100% valid parsed, 0 accounts exceeding threshold, 0 bursts, low risk score.

TC-02: Repeated Failures & Threshold Alerting
  - Purpose: Simulates targeted brute-force attacks on privileged accounts (8 failures on 'admin').
  - Assertions: Target account flagged above threshold (4), severity marked HIGH/CRITICAL, source IP logged.

TC-03: High-Frequency Burst Detection
  - Purpose: Injects 7 rapid failed attempts within 21 seconds (< 60s window).
  - Assertions: Burst incident detected, event count == 7, velocity rate >= 14/min accurately calculated.

TC-04: Malformed Records Resilience
  - Purpose: Feeds logs with missing timestamps, blank lines, missing statuses, and corrupt characters.
  - Assertions: Zero unhandled crashes, valid records extracted, malformed lines separated into invalid records with line numbers and reasons.

TC-05: Time-Window Boundary Verification
  - Purpose: Tests mathematical sliding window boundaries.
  - Assertions: 4 attempts spaced 15s apart (span 45s <= 60s) -> TRIGGER BURST;
               4 attempts spaced 70s apart (span 210s > 60s) -> NO BURST.
================================================================================
```

---

## 8. Installation & Setup Instructions

### Prerequisites
* **Python 3.10** or higher.
* Python packages: `flask` (and standard library modules `csv`, `re`, `datetime`, `collections`, `io`).

### Quick Setup

1. **Clone or navigate to the project directory**:
   ```powershell
   cd "c:\Users\Srinivas\OneDrive\Documents\New folder"
   ```

2. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   * **Option A (Terminal)**:
     ```powershell
     python main.py
     ```
   * **Option B (Windows Batch Launcher)**:
     Double-click `run.bat`.

4. **Access the Web Dashboard**:
   Open your web browser and navigate to:
   ```text
   http://127.0.0.1:5000
   ```

5. **Run the Automated Tests**:
   * In the browser: Navigate to `http://127.0.0.1:5000/tests` and click **"Run Test Suite"**.
   * From the terminal:
     ```powershell
     python report_and_tests.py
     ```
   * Or double-click `test_runner.bat`.

---

## 9. API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/load-sample` | `POST` | Loads built-in fictional dataset (`sample_logs.txt` or `sample_logs.csv`). |
| `/api/run-tests` | `POST` | Executes all 5 test cases live and returns results with timings in JSON. |
| `/api/stats` | `GET` | Returns summary statistics, threat scores, and Chart.js payloads. |
| `/api/failed-logins?threshold=N` | `GET` | Computes failed login metrics for dynamic threshold `N`. |
| `/api/bursts?threshold=N&window=W` | `GET` | Computes sliding-window bursts for threshold `N` and window `W` (seconds). |
| `/api/download/report/json` | `GET` | Downloads full security audit report in structured JSON format. |
| `/api/download/report/csv` | `GET` | Downloads multi-table security audit report in CSV format. |
| `/api/download/report/text` | `GET` | Downloads executive security audit report in formatted text format. |
| `/api/download/sample-logs` | `GET` | Downloads the fictional sample authentication log file. |

---

*BUILDERS Phase 2 – Basic Security Log Analyzer – Cybersecurity / Defensive Security Domain*
