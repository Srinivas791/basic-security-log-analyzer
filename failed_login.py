"""
Security Log Analyzer - Failed Login Detection Module
Filename: failed_login.py
Description: Identifies unsuccessful authentication attempts, tallies failures by username and source IP,
             applies configurable alert thresholds, and flags repeated failure patterns.
"""

from collections import defaultdict
from typing import List, Dict, Any, Tuple


def determine_user_severity(failed_count: int, threshold: int) -> Tuple[str, str]:
    """
    Determines severity level and defensive risk label based on failure count vs threshold.
    """
    if failed_count >= threshold * 3:
        return "CRITICAL", "Critical Brute-Force Target"
    elif failed_count >= threshold * 2:
        return "HIGH", "High-Volume Authentication Failures"
    elif failed_count >= threshold:
        return "MEDIUM", "Repeated Failures Exceeding Threshold"
    elif failed_count > 1:
        return "LOW", "Minor Authentication Failures"
    else:
        return "INFO", "Single Isolated Failure"


def determine_ip_severity(failed_count: int, target_users_count: int, threshold: int) -> Tuple[str, str]:
    """
    Determines IP threat severity and classification (Brute-Force vs Credential Spraying).
    """
    if target_users_count >= 3 and failed_count >= threshold:
        return "CRITICAL", "Horizontal Credential Spraying Source"
    elif failed_count >= threshold * 3:
        return "CRITICAL", "Persistent High-Volume Attacker"
    elif failed_count >= threshold * 2:
        return "HIGH", "Aggressive Brute-Force Origin"
    elif failed_count >= threshold:
        return "MEDIUM", "Suspicious Activity Origin"
    else:
        return "LOW", "Standard Connection"


def analyze_failed_logins(records: List[Dict[str, Any]], threshold: int = 3) -> Dict[str, Any]:
    """
    Analyzes valid log records to detect unsuccessful logins, count failures per user and IP,
    and flag accounts exceeding configurable thresholds.
    """
    user_stats = defaultdict(lambda: {
        'username': '',
        'failed_count': 0,
        'success_count': 0,
        'source_ips': set(),
        'services': set(),
        'timestamps': [],
        'failed_records': []
    })

    ip_stats = defaultdict(lambda: {
        'source_ip': '',
        'failed_count': 0,
        'success_count': 0,
        'targeted_users': set(),
        'services': set(),
        'timestamps': [],
        'failed_records': []
    })

    total_failed = 0
    total_success = 0

    # Aggregate statistics
    for r in records:
        uname = r['username']
        status = r['status']
        ip = r['source_ip']
        service = r.get('service', 'AUTH')
        ts = r['timestamp']

        user_entry = user_stats[uname]
        user_entry['username'] = uname
        user_entry['services'].add(service)

        ip_entry = ip_stats[ip]
        ip_entry['source_ip'] = ip
        ip_entry['services'].add(service)

        if status == 'FAILED':
            total_failed += 1
            user_entry['failed_count'] += 1
            user_entry['source_ips'].add(ip)
            user_entry['timestamps'].append(ts)
            user_entry['failed_records'].append(r)

            ip_entry['failed_count'] += 1
            ip_entry['targeted_users'].add(uname)
            ip_entry['timestamps'].append(ts)
            ip_entry['failed_records'].append(r)
        else:
            total_success += 1
            user_entry['success_count'] += 1
            ip_entry['success_count'] += 1

    # Format user analysis results
    user_results = []
    for uname, data in user_stats.items():
        if data['failed_count'] == 0 and data['success_count'] == 0:
            continue
        
        failed = data['failed_count']
        success = data['success_count']
        total = failed + success
        fail_pct = round((failed / total * 100), 1) if total > 0 else 0.0
        exceeds = failed >= threshold
        severity, label = determine_user_severity(failed, threshold)

        sorted_ts = sorted(data['timestamps'])
        first_seen = sorted_ts[0].strftime('%Y-%m-%d %H:%M:%S') if sorted_ts else 'N/A'
        last_seen = sorted_ts[-1].strftime('%Y-%m-%d %H:%M:%S') if sorted_ts else 'N/A'

        user_results.append({
            'username': uname,
            'failed_count': failed,
            'success_count': success,
            'total_attempts': total,
            'failure_rate_pct': fail_pct,
            'source_ips': sorted(list(data['source_ips'])),
            'services': sorted(list(data['services'])),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'exceeds_threshold': exceeds,
            'severity': severity,
            'risk_label': label,
        })

    # Sort users by failed count descending, then total attempts
    user_results.sort(key=lambda x: (x['failed_count'], x['total_attempts']), reverse=True)

    # Format IP analysis results
    ip_results = []
    for ip, data in ip_stats.items():
        if ip == 'UNKNOWN' and data['failed_count'] == 0:
            continue
        
        failed = data['failed_count']
        success = data['success_count']
        total = failed + success
        fail_pct = round((failed / total * 100), 1) if total > 0 else 0.0
        exceeds = failed >= threshold
        target_count = len(data['targeted_users'])
        severity, label = determine_ip_severity(failed, target_count, threshold)

        sorted_ts = sorted(data['timestamps'])
        first_seen = sorted_ts[0].strftime('%Y-%m-%d %H:%M:%S') if sorted_ts else 'N/A'
        last_seen = sorted_ts[-1].strftime('%Y-%m-%d %H:%M:%S') if sorted_ts else 'N/A'

        ip_results.append({
            'source_ip': ip,
            'failed_count': failed,
            'success_count': success,
            'total_attempts': total,
            'failure_rate_pct': fail_pct,
            'targeted_users': sorted(list(data['targeted_users'])),
            'targeted_users_count': target_count,
            'services': sorted(list(data['services'])),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'exceeds_threshold': exceeds,
            'severity': severity,
            'threat_type': label,
        })

    # Sort IPs by failed count descending
    ip_results.sort(key=lambda x: (x['failed_count'], x['targeted_users_count']), reverse=True)

    # Flagged entities
    flagged_users = [u for u in user_results if u['exceeds_threshold']]
    flagged_ips = [i for i in ip_results if i['exceeds_threshold']]

    return {
        'threshold': threshold,
        'total_failed_logins': total_failed,
        'total_successful_logins': total_success,
        'user_analysis': user_results,
        'ip_analysis': ip_results,
        'flagged_accounts': flagged_users,
        'flagged_accounts_count': len(flagged_users),
        'flagged_ips': flagged_ips,
        'flagged_ips_count': len(flagged_ips),
        'top_targeted_accounts': user_results[:5],
        'top_malicious_ips': ip_results[:5],
    }
