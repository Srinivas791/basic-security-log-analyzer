"""
Security Log Analyzer - Reports and Test Suite Module
Filename: report_and_tests.py
Description: Generates multi-format security audit reports (JSON, CSV, Executive Text)
             and implements the required automated test suite with at least 5 comprehensive test cases.
"""

import time
import json
import csv
import io
from datetime import datetime
from typing import Dict, Any, List

import log_parser
import failed_login
import burst_detector


# ==============================================================================
# REPORT GENERATION LOGIC
# ==============================================================================

def calculate_threat_score(
    summary: Dict[str, Any],
    failed_analysis: Dict[str, Any],
    burst_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes an objective, defensive security Risk Score (0-100)
    evaluating failure ratio, high-risk accounts, malicious IPs, and burst frequency.
    """
    score = 0.0

    # 1. Failure rate component (max 25 pts)
    fail_pct = summary.get('failure_rate_pct', 0.0)
    score += min(25.0, (fail_pct / 100.0) * 25.0)

    # 2. Flagged accounts component (max 25 pts)
    flagged_users = failed_analysis.get('flagged_accounts_count', 0)
    score += min(25.0, flagged_users * 7.5)

    # 3. Flagged malicious IPs component (max 25 pts)
    flagged_ips = failed_analysis.get('flagged_ips_count', 0)
    score += min(25.0, flagged_ips * 6.5)

    # 4. Burst incidents component (max 25 pts)
    bursts_count = burst_analysis.get('total_burst_incidents', 0)
    critical_bursts = burst_analysis.get('critical_bursts', 0)
    score += min(25.0, (bursts_count * 6.0) + (critical_bursts * 4.0))

    final_score = int(min(100.0, max(0.0, round(score))))

    if final_score >= 80:
        level = "CRITICAL"
        badge = "badge-danger"
        posture = "Severe threat posture: Active distributed attacks, repeated credential spraying, and high-frequency bursts detected."
    elif final_score >= 55:
        level = "HIGH"
        badge = "badge-warning"
        posture = "Elevated threat posture: Persistent authentication failures and localized brute-force activity observed."
    elif final_score >= 30:
        level = "MEDIUM"
        badge = "badge-info"
        posture = "Moderate threat posture: Abnormal failure volumes detected above baseline."
    else:
        level = "LOW"
        badge = "badge-success"
        posture = "Standard benign posture: Normal authentication patterns with minimal isolated failures."

    return {
        'score': final_score,
        'level': level,
        'badge': badge,
        'assessment': posture
    }


def generate_recommendations(
    failed_analysis: Dict[str, Any],
    burst_analysis: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    Synthesizes concrete defensive cybersecurity recommendations based on findings.
    """
    recs = []

    # Check for flagged IPs
    flagged_ips = failed_analysis.get('flagged_ips', [])
    if flagged_ips:
        top_ips = [ip['source_ip'] for ip in flagged_ips[:3]]
        recs.append({
            'category': 'Network Perimeter Defense',
            'severity': 'HIGH',
            'title': 'Implement Automated IP Rate Limiting & Firewall Drops',
            'action': f"Configure edge firewall/WAF rules to throttle or temporarily drop traffic from persistent failure origins: {', '.join(top_ips)}."
        })

    # Check for targeted accounts
    flagged_users = failed_analysis.get('flagged_accounts', [])
    if flagged_users:
        admin_targets = [u['username'] for u in flagged_users if u['username'] in ['admin', 'root', 'administrator', 'system', 'api_gateway']]
        if admin_targets:
            recs.append({
                'category': 'Identity & Access Management (IAM)',
                'severity': 'CRITICAL',
                'title': 'Privileged Account Hardening & MFA Enforcement',
                'action': f"Enforce mandatory Multi-Factor Authentication (MFA) and adaptive risk-based authentication for privileged accounts: {', '.join(admin_targets)}."
            })
        else:
            recs.append({
                'category': 'Identity & Access Management (IAM)',
                'severity': 'MEDIUM',
                'title': 'Account Lockout Policy Review',
                'action': 'Review progressive lockout policies (e.g., 5-minute exponential backoff) for accounts experiencing repeated failures.'
            })

    # Check for bursts
    if burst_analysis.get('total_burst_incidents', 0) > 0:
        recs.append({
            'category': 'Application Security',
            'severity': 'HIGH',
            'title': 'Deploy CAPTCHA & Proof-of-Work on Authentication Endpoints',
            'action': 'Trigger dynamic CAPTCHA challenges or CAPTCHA-less bot mitigation when request velocity exceeds 3 attempts per 10 seconds from any single client.'
        })

    # Default baseline recommendation
    recs.append({
        'category': 'Defensive Monitoring',
        'severity': 'INFO',
        'title': 'Centralized SIEM Log Ingestion & Continuous Alerting',
        'action': 'Ensure authentication audit streams are forwarded to a hardened centralized SIEM with near real-time correlation rules for MITRE ATT&CK T1110 (Brute Force).'
    })

    return recs


def generate_security_report(
    summary: Dict[str, Any],
    failed_analysis: Dict[str, Any],
    burst_analysis: Dict[str, Any],
    filename: str = "sample_logs.txt"
) -> Dict[str, Any]:
    """
    Assembles a comprehensive defensive security analysis report.
    """
    threat_info = calculate_threat_score(summary, failed_analysis, burst_analysis)
    recommendations = generate_recommendations(failed_analysis, burst_analysis)

    return {
        'report_metadata': {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'log_filename': filename,
            'analyzer_version': 'Security Log Analyzer v2.0 (BUILDERS Phase 2)',
            'threat_score': threat_info['score'],
            'threat_level': threat_info['level'],
            'threat_assessment': threat_info['assessment'],
        },
        'summary': summary,
        'failed_analysis_summary': {
            'threshold_used': failed_analysis.get('threshold', 3),
            'total_failed_logins': failed_analysis.get('total_failed_logins', 0),
            'flagged_accounts_count': failed_analysis.get('flagged_accounts_count', 0),
            'flagged_ips_count': failed_analysis.get('flagged_ips_count', 0),
        },
        'burst_analysis_summary': {
            'burst_threshold_used': burst_analysis.get('burst_threshold', 5),
            'window_seconds_used': burst_analysis.get('window_seconds', 60),
            'total_burst_incidents': burst_analysis.get('total_burst_incidents', 0),
            'critical_bursts': burst_analysis.get('critical_bursts', 0),
            'peak_rate_per_minute': burst_analysis.get('peak_burst_rate_per_min', 0.0),
        },
        'top_targeted_accounts': failed_analysis.get('top_targeted_accounts', []),
        'top_malicious_ips': failed_analysis.get('top_malicious_ips', []),
        'burst_incidents': burst_analysis.get('burst_incidents', []),
        'recommendations': recommendations,
    }


def export_report_json(report_data: Dict[str, Any]) -> str:
    """
    Exports security report into structured JSON string.
    """
    return json.dumps(report_data, indent=2, default=str)


def export_report_csv(
    records: List[Dict[str, Any]],
    failed_analysis: Dict[str, Any],
    burst_analysis: Dict[str, Any]
) -> str:
    """
    Exports findings and incident logs into CSV format.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["=== SECURITY LOG ANALYZER AUDIT EXPORT ==="])
    writer.writerow(["Generated At", datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])

    # Section 1: Flagged Accounts
    writer.writerow(["--- FLAGGED ACCOUNTS (EXCEEDING THRESHOLD) ---"])
    writer.writerow(["Username", "Failed Attempts", "Success Count", "Failure Rate (%)", "Severity", "Risk Label", "Source IPs"])
    for u in failed_analysis.get('flagged_accounts', []):
        writer.writerow([
            u['username'],
            u['failed_count'],
            u['success_count'],
            f"{u['failure_rate_pct']}%",
            u['severity'],
            u['risk_label'],
            "; ".join(u['source_ips'])
        ])
    writer.writerow([])

    # Section 2: Flagged Source IPs
    writer.writerow(["--- SUSPICIOUS SOURCE IPS ---"])
    writer.writerow(["Source IP", "Failed Attempts", "Targeted Accounts Count", "Severity", "Threat Type", "Targeted Accounts"])
    for ip in failed_analysis.get('flagged_ips', []):
        writer.writerow([
            ip['source_ip'],
            ip['failed_count'],
            ip['targeted_users_count'],
            ip['severity'],
            ip['threat_type'],
            "; ".join(ip['targeted_users'])
        ])
    writer.writerow([])

    # Section 3: Burst Incidents
    writer.writerow(["--- DETECTED BURST INCIDENTS ---"])
    writer.writerow(["Incident ID", "Pattern Type", "Severity", "Target User", "Source IP", "Event Count", "Rate/Min", "Start Time", "End Time"])
    for b in burst_analysis.get('burst_incidents', []):
        writer.writerow([
            b['incident_id'],
            b['pattern_type'],
            b['severity'],
            b['target_username'],
            b['source_ip'],
            b['event_count'],
            b['rate_per_minute'],
            b['start_time'],
            b['end_time']
        ])

    return output.getvalue()


def export_report_text(report_data: Dict[str, Any]) -> str:
    """
    Exports a clean executive text security report.
    """
    meta = report_data.get('report_metadata', {})
    summary = report_data.get('summary', {})
    failed_meta = report_data.get('failed_analysis_summary', {})
    burst_meta = report_data.get('burst_analysis_summary', {})
    top_users = report_data.get('top_targeted_accounts', [])
    top_ips = report_data.get('top_malicious_ips', [])
    bursts = report_data.get('burst_incidents', [])
    recs = report_data.get('recommendations', [])

    lines = [
        "================================================================================",
        "                     DEFENSIVE SECURITY LOG ANALYSIS REPORT                     ",
        "                BUILDERS Phase 2 - Basic Security Log Analyzer                  ",
        "================================================================================",
        f"Generated Timestamp : {meta.get('generated_at', 'N/A')}",
        f"Target Log File     : {meta.get('log_filename', 'N/A')}",
        f"Threat Score        : {meta.get('threat_score', 0)} / 100 [{meta.get('threat_level', 'UNKNOWN')}]",
        f"Posture Assessment  : {meta.get('threat_assessment', 'N/A')}",
        "--------------------------------------------------------------------------------",
        "1. EXECUTIVE SUMMARY METRICS",
        f"   * Total Log Records Analyzed : {summary.get('total_records', 0)}",
        f"   * Valid Formatted Records    : {summary.get('valid_records_count', 0)}",
        f"   * Malformed / Corrupted Rows : {summary.get('invalid_records_count', 0)}",
        f"   * Successful Authentications : {summary.get('successful_logins', 0)}",
        f"   * Failed Authentications     : {summary.get('failed_logins', 0)} ({summary.get('failure_rate_pct', 0.0)}%)",
        f"   * Total Accounts Targeted    : {summary.get('affected_accounts_count', 0)}",
        f"   * Accounts Exceeding Alert   : {failed_meta.get('flagged_accounts_count', 0)} (Threshold: {failed_meta.get('threshold_used', 3)})",
        f"   * Burst Incidents Detected   : {burst_meta.get('total_burst_incidents', 0)}",
        "--------------------------------------------------------------------------------",
        "2. TOP TARGETED ACCOUNTS",
    ]

    for u in top_users:
        lines.append(f"   - User: {u['username']:<15} | Failures: {u['failed_count']:<3} | Severity: {u['severity']:<8} | Label: {u['risk_label']}")

    lines.append("--------------------------------------------------------------------------------")
    lines.append("3. TOP SUSPICIOUS SOURCE IP ADDRESSES")
    for ip in top_ips:
        lines.append(f"   - IP: {ip['source_ip']:<18} | Failures: {ip['failed_count']:<3} | Targets: {ip['targeted_users_count']} | Threat: {ip['threat_type']}")

    lines.append("--------------------------------------------------------------------------------")
    lines.append("4. DETECTED AUTHENTICATION BURST INCIDENTS")
    if bursts:
        for b in bursts:
            lines.append(f"   [{b['incident_id']}] {b['pattern_type']} ({b['severity']})")
            lines.append(f"     Time Window : {b['start_time']} -> {b['end_time']} ({b['duration_seconds']}s)")
            lines.append(f"     Target User : {b['target_username']} | Origin: {b['source_ip']}")
            lines.append(f"     Events      : {b['event_count']} attempts ({b['rate_per_minute']} attempts/min)")
    else:
        lines.append("   No anomalous high-velocity burst activity identified.")

    lines.append("--------------------------------------------------------------------------------")
    lines.append("5. ACTIONABLE DEFENSIVE RECOMMENDATIONS")
    for idx, r in enumerate(recs, 1):
        lines.append(f"   [{idx}] [{r['severity']}] {r['title']} ({r['category']})")
        lines.append(f"       Action: {r['action']}")

    lines.append("================================================================================")
    lines.append("End of Defensive Security Analysis Report.")
    lines.append("Defensive Notice: This report was generated without credential collection.")

    return "\n".join(lines)


# ==============================================================================
# AUTOMATED TEST SUITE (5 REQUIRED TEST CASES)
# ==============================================================================

def test_case_1_normal_activity() -> Dict[str, Any]:
    """
    Test Case 1: Normal Activity
    Objective: Verify system correctly handles routine valid authentication logins
               with 0 false positive burst alerts or threshold triggers.
    """
    test_id = "TC-01"
    name = "Normal Activity Verification"
    start_t = time.perf_counter()
    assertions = []

    normal_logs = """
    2026-11-17 08:00:10 - USER: alice - STATUS: SUCCESS - IP: 192.168.1.10 - SERVICE: SSH
    2026-11-17 08:05:20 - USER: bob - STATUS: SUCCESS - IP: 192.168.1.15 - SERVICE: Web-Portal
    2026-11-17 08:10:30 - USER: charlie - STATUS: FAILED - IP: 192.168.1.25 - SERVICE: VPN
    2026-11-17 08:11:00 - USER: charlie - STATUS: SUCCESS - IP: 192.168.1.25 - SERVICE: VPN
    2026-11-17 08:20:00 - USER: david - STATUS: SUCCESS - IP: 10.0.0.12 - SERVICE: SSH
    2026-11-17 08:35:15 - USER: eva - STATUS: SUCCESS - IP: 172.16.0.40 - SERVICE: Web-Portal
    """

    valid_recs, invalid_recs = log_parser.parse_log_content(normal_logs)
    summary = log_parser.compute_parser_summary(valid_recs, invalid_recs)
    failed_res = failed_login.analyze_failed_logins(valid_recs, threshold=3)
    burst_res = burst_detector.detect_bursts(valid_recs, burst_threshold=3, window_seconds=60)

    # Assertions
    assertions.append(("Valid records count == 6", len(valid_recs) == 6))
    assertions.append(("Successful logins == 5", summary['successful_logins'] == 5))
    assertions.append(("Failed logins == 1", summary['failed_logins'] == 1))
    assertions.append(("Flagged accounts count == 0", failed_res['flagged_accounts_count'] == 0))
    assertions.append(("Burst incidents count == 0", burst_res['total_burst_incidents'] == 0))

    passed = all(cond for _, cond in assertions)
    duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return {
        'id': test_id,
        'name': name,
        'category': 'Normal Behavior',
        'status': 'PASSED' if passed else 'FAILED',
        'duration_ms': duration_ms,
        'assertions_checked': len(assertions),
        'assertions_details': [f"{desc}: {'PASS' if cond else 'FAIL'}" for desc, cond in assertions],
        'details': "Processed 6 benign records. Confirmed single isolated failure did not trigger false alarm."
    }


def test_case_2_repeated_failures() -> Dict[str, Any]:
    """
    Test Case 2: Repeated Failures
    Objective: Verify system detects and alerts when an account exceeds the configurable failure threshold.
    """
    test_id = "TC-02"
    name = "Repeated Failures & Threshold Alerting"
    start_t = time.perf_counter()
    assertions = []

    attack_logs = """
    2026-11-17 09:00:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:01:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:02:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:03:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:04:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:05:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:06:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:07:00 - USER: admin - STATUS: FAILED - IP: 198.51.100.23 - SERVICE: SSH
    2026-11-17 09:10:00 - USER: user_benign - STATUS: SUCCESS - IP: 10.0.0.5 - SERVICE: Web
    """

    valid_recs, _ = log_parser.parse_log_content(attack_logs)
    failed_res = failed_login.analyze_failed_logins(valid_recs, threshold=4)

    flagged_users = [u['username'] for u in failed_res['flagged_accounts']]
    admin_stat = next((u for u in failed_res['user_analysis'] if u['username'] == 'admin'), None)

    # Assertions
    assertions.append(("Admin account flagged above threshold (4)", 'admin' in flagged_users))
    assertions.append(("Admin total failures == 8", admin_stat and admin_stat['failed_count'] == 8))
    assertions.append(("Admin severity marked HIGH or CRITICAL", admin_stat and admin_stat['severity'] in ['HIGH', 'CRITICAL']))
    assertions.append(("Flagged source IP captured", '198.51.100.23' in [i['source_ip'] for i in failed_res['flagged_ips']]))

    passed = all(cond for _, cond in assertions)
    duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return {
        'id': test_id,
        'name': name,
        'category': 'Brute Force Detection',
        'status': 'PASSED' if passed else 'FAILED',
        'duration_ms': duration_ms,
        'assertions_checked': len(assertions),
        'assertions_details': [f"{desc}: {'PASS' if cond else 'FAIL'}" for desc, cond in assertions],
        'details': "Simulated targeted attack on 'admin' (8 failures vs threshold=4). Threshold flag and severity accurately evaluated."
    }


def test_case_3_burst_activity() -> Dict[str, Any]:
    """
    Test Case 3: Burst Activity
    Objective: Detect unusual high-frequency bursts of failed authentication attempts within a narrow time window.
    """
    test_id = "TC-03"
    name = "High-Frequency Burst Detection"
    start_t = time.perf_counter()
    assertions = []

    burst_logs = """
    2026-11-17 11:30:01 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    2026-11-17 11:30:04 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    2026-11-17 11:30:07 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    2026-11-17 11:30:10 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    2026-11-17 11:30:14 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    2026-11-17 11:30:18 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    2026-11-17 11:30:22 - USER: api_gateway - STATUS: FAILED - IP: 203.0.113.195 - SERVICE: API
    """

    valid_recs, _ = log_parser.parse_log_content(burst_logs)
    burst_res = burst_detector.detect_bursts(valid_recs, burst_threshold=5, window_seconds=60)

    incidents = burst_res['burst_incidents']
    primary_incident = incidents[0] if incidents else None

    assertions.append(("Burst incident detected", len(incidents) >= 1))
    assertions.append(("Burst event count == 7", primary_incident and primary_incident['event_count'] == 7))
    assertions.append(("Burst duration < 30 seconds", primary_incident and primary_incident['duration_seconds'] <= 30))
    assertions.append(("Burst rate per minute >= 14", primary_incident and primary_incident['rate_per_minute'] >= 14.0))

    passed = all(cond for _, cond in assertions)
    duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return {
        'id': test_id,
        'name': name,
        'category': 'Burst Detection',
        'status': 'PASSED' if passed else 'FAILED',
        'duration_ms': duration_ms,
        'assertions_checked': len(assertions),
        'assertions_details': [f"{desc}: {'PASS' if cond else 'FAIL'}" for desc, cond in assertions],
        'details': "Injected 7 failures within 21 seconds. Successfully triggered burst incident with accurate rate calculation."
    }


def test_case_4_malformed_records() -> Dict[str, Any]:
    """
    Test Case 4: Malformed and Corrupted Records
    Objective: Verify parser resilience against blank lines, missing fields, corrupted dates,
               and garbage text without crashing, properly separating valid from invalid.
    """
    test_id = "TC-04"
    name = "Malformed Records Resilience"
    start_t = time.perf_counter()
    assertions = []

    dirty_logs = """
    # Informational comment header
    
    2026-11-17 12:00:00 - USER: valid_user - STATUS: SUCCESS - IP: 192.168.1.99 - SERVICE: SSH
    
    CORRUPTED LINE WITHOUT TIMESTAMPS OR FIELDS
    2026-11-17 12:01:00 - USER: missing_status_user - IP: 10.0.0.1
    STATUS: FAILED - IP: 192.168.1.1 (missing user and timestamp)
    [BAD_TIME_STAMP] - USER: bad_date_user - STATUS: FAILED
    2026-11-17 12:05:00 - USER: valid_admin - STATUS: FAILED - IP: 192.168.1.100 - SERVICE: Web
    """

    # Parser execution - must not raise exception
    try:
        valid_recs, invalid_recs = log_parser.parse_log_content(dirty_logs)
        no_crash = True
    except Exception:
        no_crash = False
        valid_recs, invalid_recs = [], []

    assertions.append(("Parser executes without crashing", no_crash))
    assertions.append(("Valid records extracted == 2", len(valid_recs) == 2))
    assertions.append(("Invalid records identified >= 5", len(invalid_recs) >= 5))
    assertions.append(("Line numbers preserved on invalid records", all(r.get('line_number') > 0 for r in invalid_recs)))
    assertions.append(("Descriptive error reasons provided", all(len(r.get('reason', '')) > 0 for r in invalid_recs)))

    passed = all(cond for _, cond in assertions)
    duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return {
        'id': test_id,
        'name': name,
        'category': 'Parser Fault Tolerance',
        'status': 'PASSED' if passed else 'FAILED',
        'duration_ms': duration_ms,
        'assertions_checked': len(assertions),
        'assertions_details': [f"{desc}: {'PASS' if cond else 'FAIL'}" for desc, cond in assertions],
        'details': "Processed corrupted records with blank lines, missing fields, and bad timestamps. System remained 100% stable."
    }


def test_case_5_time_window_boundary() -> Dict[str, Any]:
    """
    Test Case 5: Time-Window Boundary
    Objective: Validate precise boundary conditions for sliding time windows:
               Events spaced outside the window must NOT trigger burst alert;
               Events spaced inside the window MUST trigger burst alert.
    """
    test_id = "TC-05"
    name = "Time-Window Boundary Verification"
    start_t = time.perf_counter()
    assertions = []

    # Window configuration: 60 seconds, burst_threshold = 4
    window_sec = 60
    burst_threshold = 4

    # Sub-case A: 4 failed logins spaced 15 seconds apart -> Total span 45 seconds (INSIDE 60s window)
    inside_window_logs = """
    2026-11-17 14:00:00 - USER: target_a - STATUS: FAILED - IP: 198.51.100.1 - SERVICE: SSH
    2026-11-17 14:00:15 - USER: target_a - STATUS: FAILED - IP: 198.51.100.1 - SERVICE: SSH
    2026-11-17 14:00:30 - USER: target_a - STATUS: FAILED - IP: 198.51.100.1 - SERVICE: SSH
    2026-11-17 14:00:45 - USER: target_a - STATUS: FAILED - IP: 198.51.100.1 - SERVICE: SSH
    """

    # Sub-case B: 4 failed logins spaced 70 seconds apart -> Total span 210 seconds (OUTSIDE 60s window)
    outside_window_logs = """
    2026-11-17 15:00:00 - USER: target_b - STATUS: FAILED - IP: 198.51.100.2 - SERVICE: SSH
    2026-11-17 15:01:10 - USER: target_b - STATUS: FAILED - IP: 198.51.100.2 - SERVICE: SSH
    2026-11-17 15:02:20 - USER: target_b - STATUS: FAILED - IP: 198.51.100.2 - SERVICE: SSH
    2026-11-17 15:03:30 - USER: target_b - STATUS: FAILED - IP: 198.51.100.2 - SERVICE: SSH
    """

    valid_inside, _ = log_parser.parse_log_content(inside_window_logs)
    valid_outside, _ = log_parser.parse_log_content(outside_window_logs)

    burst_inside = burst_detector.detect_bursts(valid_inside, burst_threshold=burst_threshold, window_seconds=window_sec)
    burst_outside = burst_detector.detect_bursts(valid_outside, burst_threshold=burst_threshold, window_seconds=window_sec)

    assertions.append(("Inside window (45s <= 60s) triggers burst", burst_inside['total_burst_incidents'] == 1))
    assertions.append(("Outside window (70s spacing > 60s) triggers 0 bursts", burst_outside['total_burst_incidents'] == 0))
    assertions.append(("Exact burst event count in inside case == 4", burst_inside['burst_incidents'][0]['event_count'] == 4 if burst_inside['burst_incidents'] else False))

    passed = all(cond for _, cond in assertions)
    duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

    return {
        'id': test_id,
        'name': name,
        'category': 'Mathematical Boundary Testing',
        'status': 'PASSED' if passed else 'FAILED',
        'duration_ms': duration_ms,
        'assertions_checked': len(assertions),
        'assertions_details': [f"{desc}: {'PASS' if cond else 'FAIL'}" for desc, cond in assertions],
        'details': "Tested temporal boundary at 60 seconds. Confirmed attempts within 45s flagged; attempts at 70s intervals ignored."
    }


def run_all_tests() -> Dict[str, Any]:
    """
    Executes all 5 comprehensive test cases, calculates pass rate, logs details, and returns structured summary.
    """
    start_all = time.perf_counter()

    test_functions = [
        test_case_1_normal_activity,
        test_case_2_repeated_failures,
        test_case_3_burst_activity,
        test_case_4_malformed_records,
        test_case_5_time_window_boundary,
    ]

    results = []
    passed_count = 0

    for test_fn in test_functions:
        res = test_fn()
        results.append(res)
        if res['status'] == 'PASSED':
            passed_count += 1

    total_duration_ms = round((time.perf_counter() - start_all) * 1000, 2)
    all_passed = (passed_count == len(results))

    return {
        'total_tests': len(results),
        'passed_tests': passed_count,
        'failed_tests': len(results) - passed_count,
        'pass_percentage': round((passed_count / len(results)) * 100, 1),
        'all_passed': all_passed,
        'total_duration_ms': total_duration_ms,
        'executed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'test_results': results
    }


if __name__ == "__main__":
    print("Executing Security Log Analyzer Automated Test Suite...")
    summary = run_all_tests()
    print(f"Results: {summary['passed_tests']}/{summary['total_tests']} tests passed in {summary['total_duration_ms']}ms.")
    for t in summary['test_results']:
        print(f"[{t['status']}] {t['id']}: {t['name']} ({t['duration_ms']}ms)")
