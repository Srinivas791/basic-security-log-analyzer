"""
Security Log Analyzer - Timestamp & Burst Detection Module
Filename: burst_detector.py
Description: Analyzes authentication timestamps, identifies rapid bursts of failed login attempts
             within configurable sliding time windows, clusters incidents, and evaluates threat severity.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any


def detect_sliding_window_bursts(
    failed_records: List[Dict[str, Any]],
    burst_threshold: int,
    window_seconds: int,
    group_key: str = None
) -> List[Dict[str, Any]]:
    """
    Finds burst clusters using a sliding window.
    group_key can be 'username', 'source_ip', or None (for global bursts).
    Merges overlapping windows to avoid duplicate incident reports.
    """
    if not failed_records or len(failed_records) < burst_threshold:
        return []

    # Sort records chronologically
    sorted_records = sorted(failed_records, key=lambda r: r['timestamp'])
    window_delta = timedelta(seconds=window_seconds)

    raw_burst_spans = []
    n = len(sorted_records)

    for i in range(n):
        current_span = [sorted_records[i]]
        t_start = sorted_records[i]['timestamp']
        t_max = t_start + window_delta

        for j in range(i + 1, n):
            if sorted_records[j]['timestamp'] <= t_max:
                current_span.append(sorted_records[j])
            else:
                break

        if len(current_span) >= burst_threshold:
            raw_burst_spans.append(current_span)

    if not raw_burst_spans:
        return []

    # Merge overlapping burst spans into cohesive incidents
    merged_incidents = []
    current_cluster = list(raw_burst_spans[0])

    for span in raw_burst_spans[1:]:
        cluster_end = max(r['timestamp'] for r in current_cluster)
        span_start = min(r['timestamp'] for r in span)

        # If the span starts within the window or overlaps with current cluster, merge
        if span_start <= cluster_end + window_delta:
            existing_ids = {r['id'] for r in current_cluster}
            for rec in span:
                if rec['id'] not in existing_ids:
                    current_cluster.append(rec)
                    existing_ids.add(rec['id'])
        else:
            merged_incidents.append(sorted(current_cluster, key=lambda r: r['timestamp']))
            current_cluster = list(span)

    if current_cluster:
        merged_incidents.append(sorted(current_cluster, key=lambda r: r['timestamp']))

    return merged_incidents


def detect_bursts(
    records: List[Dict[str, Any]],
    burst_threshold: int = 5,
    window_seconds: int = 60
) -> Dict[str, Any]:
    """
    Detects unusual bursts of failed authentication attempts within a configurable time window.
    Evaluates:
      1. Per-IP bursts (same source attacking)
      2. Per-User bursts (targeted account brute-force)
      3. Global / Distributed bursts (credential stuffing / distributed bots)
    """
    failed_records = [r for r in records if r.get('status') == 'FAILED']
    
    if not failed_records:
        return {
            'burst_threshold': burst_threshold,
            'window_seconds': window_seconds,
            'total_burst_incidents': 0,
            'burst_incidents': [],
            'critical_bursts': 0,
            'high_bursts': 0,
            'medium_bursts': 0,
            'max_burst_size': 0,
            'peak_burst_rate_per_min': 0.0,
            'affected_accounts_in_bursts': [],
            'attacker_ips_in_bursts': [],
        }

    # Group failed records by IP
    records_by_ip = {}
    records_by_user = {}
    for r in failed_records:
        ip = r.get('source_ip', 'UNKNOWN')
        uname = r.get('username', 'UNKNOWN')
        records_by_ip.setdefault(ip, []).append(r)
        records_by_user.setdefault(uname, []).append(r)

    discovered_incidents = []
    incident_counter = 1
    seen_event_signature = set()

    # 1. Detect Per-IP Bursts
    for ip, ip_recs in records_by_ip.items():
        if ip == 'UNKNOWN':
            continue
        clusters = detect_sliding_window_bursts(ip_recs, burst_threshold, window_seconds)
        for cluster in clusters:
            sig = tuple(r['id'] for r in cluster)
            if sig in seen_event_signature:
                continue
            seen_event_signature.add(sig)

            start_t = cluster[0]['timestamp']
            end_t = cluster[-1]['timestamp']
            duration = max(1, int((end_t - start_t).total_seconds()))
            event_count = len(cluster)
            rate_per_min = round(event_count / (duration / 60.0), 1)

            targeted_users = sorted(list({r['username'] for r in cluster}))
            
            # Pattern classification
            if len(targeted_users) >= 3:
                pattern = "Horizontal Credential Spraying"
                severity = "CRITICAL"
            elif event_count >= burst_threshold * 2:
                pattern = "High-Volume Automated Brute-Force"
                severity = "CRITICAL"
            elif event_count >= burst_threshold * 1.5:
                pattern = "Rapid Targeted Attack"
                severity = "HIGH"
            else:
                pattern = "Authentication Failure Burst"
                severity = "MEDIUM"

            discovered_incidents.append({
                'incident_id': f"BURST-{incident_counter:03d}",
                'pattern_type': pattern,
                'severity': severity,
                'target_username': ', '.join(targeted_users[:3]) + ('...' if len(targeted_users) > 3 else ''),
                'target_users_list': targeted_users,
                'source_ip': ip,
                'source_ips_list': [ip],
                'start_time': start_t.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_t.strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': duration,
                'event_count': event_count,
                'rate_per_minute': rate_per_min,
                'events': [{
                    'id': r['id'],
                    'timestamp': r['timestamp_str'],
                    'username': r['username'],
                    'source_ip': r['source_ip'],
                    'service': r.get('service', 'AUTH')
                } for r in cluster]
            })
            incident_counter += 1

    # 2. Detect Per-User Bursts (if not already captured by single IP, e.g. distributed against one account)
    for uname, user_recs in records_by_user.items():
        clusters = detect_sliding_window_bursts(user_recs, burst_threshold, window_seconds)
        for cluster in clusters:
            sig = tuple(r['id'] for r in cluster)
            if sig in seen_event_signature:
                continue
            seen_event_signature.add(sig)

            start_t = cluster[0]['timestamp']
            end_t = cluster[-1]['timestamp']
            duration = max(1, int((end_t - start_t).total_seconds()))
            event_count = len(cluster)
            rate_per_min = round(event_count / (duration / 60.0), 1)
            source_ips = sorted(list({r['source_ip'] for r in cluster}))

            pattern = "Distributed Account Brute-Force" if len(source_ips) > 1 else "Targeted Account Burst"
            severity = "CRITICAL" if event_count >= burst_threshold * 2 else ("HIGH" if event_count >= burst_threshold * 1.5 else "MEDIUM")

            discovered_incidents.append({
                'incident_id': f"BURST-{incident_counter:03d}",
                'pattern_type': pattern,
                'severity': severity,
                'target_username': uname,
                'target_users_list': [uname],
                'source_ip': ', '.join(source_ips[:3]) + ('...' if len(source_ips) > 3 else ''),
                'source_ips_list': source_ips,
                'start_time': start_t.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_t.strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': duration,
                'event_count': event_count,
                'rate_per_minute': rate_per_min,
                'events': [{
                    'id': r['id'],
                    'timestamp': r['timestamp_str'],
                    'username': r['username'],
                    'source_ip': r['source_ip'],
                    'service': r.get('service', 'AUTH')
                } for r in cluster]
            })
            incident_counter += 1

    # Sort incidents chronologically by start_time
    discovered_incidents.sort(key=lambda x: x['start_time'], reverse=True)

    # Compute metrics
    critical_count = sum(1 for inc in discovered_incidents if inc['severity'] == 'CRITICAL')
    high_count = sum(1 for inc in discovered_incidents if inc['severity'] == 'HIGH')
    medium_count = sum(1 for inc in discovered_incidents if inc['severity'] == 'MEDIUM')
    max_size = max([inc['event_count'] for inc in discovered_incidents], default=0)
    peak_rate = max([inc['rate_per_minute'] for inc in discovered_incidents], default=0.0)

    affected_accounts = set()
    attacker_ips = set()
    for inc in discovered_incidents:
        affected_accounts.update(inc['target_users_list'])
        attacker_ips.update(inc['source_ips_list'])

    return {
        'burst_threshold': burst_threshold,
        'window_seconds': window_seconds,
        'total_burst_incidents': len(discovered_incidents),
        'burst_incidents': discovered_incidents,
        'critical_bursts': critical_count,
        'high_bursts': high_count,
        'medium_bursts': medium_count,
        'max_burst_size': max_size,
        'peak_burst_rate_per_min': peak_rate,
        'affected_accounts_in_bursts': sorted(list(affected_accounts)),
        'attacker_ips_in_bursts': sorted(list(attacker_ips)),
    }
