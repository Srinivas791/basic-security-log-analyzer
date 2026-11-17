"""
Security Log Analyzer - Log Parser Module
Filename: log_parser.py
Description: Handles uploading, parsing, sanitizing, and validating .txt and .csv authentication logs.
             Resilient to blank, incomplete, and malformed records.
"""

import re
import csv
import io
from datetime import datetime
from typing import List, Dict, Tuple, Any, Optional

# IPv4 and IPv6 regex patterns
IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?\b')

# Datetime regex patterns for multiple log formats
DATE_PATTERNS = [
    (re.compile(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})'), '%Y-%m-%d %H:%M:%S'),
    (re.compile(r'(\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2})'), '%Y/%m/%d %H:%M:%S'),
    (re.compile(r'(\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2})'), '%d/%m/%Y %H:%M:%S'),
    (re.compile(r'(\d{2}-\d{2}-\d{4}[ T]\d{2}:\d{2}:\d{2})'), '%d-%m-%Y %H:%M:%S'),
    (re.compile(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), '%b %d %H:%M:%S'),
    (re.compile(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]'), '%Y-%m-%d %H:%M:%S'),
    (re.compile(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\]'), '%d/%b/%Y:%H:%M:%S'),
]

SUCCESS_KEYWORDS = {'success', 'successful', 'succeeded', 'accepted', 'ok', 'pass', 'allowed', '200', 'authenticated'}
FAILED_KEYWORDS = {'failed', 'failure', 'fail', 'denied', 'rejected', 'error', 'invalid', 'invalid_password', 'wrong', '401', '403'}


def normalize_status(raw_status: str) -> Optional[str]:
    """
    Normalizes variable status expressions into 'SUCCESS' or 'FAILED'.
    Returns None if status cannot be recognized.
    """
    if not raw_status:
        return None
    cleaned = re.sub(r'[^a-zA-Z0-9_]', '', str(raw_status)).strip().lower()
    
    if cleaned in SUCCESS_KEYWORDS:
        return 'SUCCESS'
    if cleaned in FAILED_KEYWORDS:
        return 'FAILED'
    
    # Substring checks
    for kw in SUCCESS_KEYWORDS:
        if kw in cleaned:
            return 'SUCCESS'
    for kw in FAILED_KEYWORDS:
        if kw in cleaned:
            return 'FAILED'
            
    return None


def extract_timestamp(text: str) -> Tuple[Optional[datetime], Optional[str]]:
    """
    Extracts datetime object and formatted string from text using standard formats.
    """
    for pattern, dt_format in DATE_PATTERNS:
        match = pattern.search(text)
        if match:
            ts_str = match.group(1).replace('T', ' ')
            # Handle single space day in syslog format like 'Nov  7'
            ts_cleaned = re.sub(r'\s+', ' ', ts_str)
            try:
                dt = datetime.strptime(ts_cleaned, dt_format)
                # If syslog format (no year), default to current year
                if '%Y' not in dt_format:
                    dt = dt.replace(year=datetime.now().year)
                return dt, dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
    return None, None


def extract_ip(text: str) -> str:
    """
    Extracts IPv4 or IPv6 address or returns 'UNKNOWN'.
    """
    ipv4_match = IPV4_PATTERN.search(text)
    if ipv4_match:
        return ipv4_match.group(0)
    ipv6_match = IPV6_PATTERN.search(text)
    if ipv6_match:
        return ipv6_match.group(0)
    return "UNKNOWN"


def parse_csv_line(line: str, headers: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """
    Attempts to parse line as CSV record.
    """
    try:
        reader = csv.reader(io.StringIO(line))
        row = next(reader)
        if not row or len(row) < 3:
            return None
        
        # If headers provided
        if headers and len(headers) == len(row):
            header_map = {h.strip().lower(): val.strip() for h, val in zip(headers, row)}
            
            ts_raw = header_map.get('timestamp') or header_map.get('time') or header_map.get('date') or ''
            user_raw = header_map.get('username') or header_map.get('user') or header_map.get('account') or ''
            status_raw = header_map.get('status') or header_map.get('result') or header_map.get('event') or ''
            ip_raw = header_map.get('source_ip') or header_map.get('ip') or header_map.get('source') or 'UNKNOWN'
            service_raw = header_map.get('service') or header_map.get('application') or 'SYSTEM'
            
            dt, dt_str = extract_timestamp(ts_raw)
            status = normalize_status(status_raw)
            ip = extract_ip(ip_raw) if ip_raw != 'UNKNOWN' else 'UNKNOWN'
            
            if dt and user_raw and status:
                return {
                    'timestamp': dt,
                    'timestamp_str': dt_str,
                    'username': user_raw.strip().lower(),
                    'status': status,
                    'source_ip': ip,
                    'service': service_raw.strip(),
                }
        
        # Positional fallback: timestamp, username, status, [source_ip], [service]
        dt, dt_str = extract_timestamp(row[0])
        if dt:
            user_raw = row[1].strip()
            status = normalize_status(row[2].strip())
            ip_raw = row[3].strip() if len(row) > 3 else "UNKNOWN"
            service_raw = row[4].strip() if len(row) > 4 else "AUTH"
            ip = extract_ip(ip_raw)
            if user_raw and status:
                return {
                    'timestamp': dt,
                    'timestamp_str': dt_str,
                    'username': user_raw.lower(),
                    'status': status,
                    'source_ip': ip,
                    'service': service_raw,
                }
    except Exception:
        pass
    return None


def parse_structured_text_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Parses unstructured and semi-structured text logs (Key-Value, Syslog, Apache, or Custom).
    Returns (record_dict, error_reason).
    """
    # Check 1: Extract timestamp
    dt, dt_str = extract_timestamp(line)
    if not dt:
        return None, "Missing or invalid timestamp format"

    # Check 2: Extract status
    status = None
    # Key-value extraction: STATUS:\s*(\w+) or status=(\w+)
    status_match = re.search(r'(?:status|result)\s*[:=]\s*([a-zA-Z0-9_]+)', line, re.IGNORECASE)
    if status_match:
        status = normalize_status(status_match.group(1))
    
    # Generic word search if key-value wasn't present
    if not status:
        if re.search(r'\b(failed|failure|denied|rejected|invalid)\b', line, re.IGNORECASE):
            status = 'FAILED'
        elif re.search(r'\b(success|successful|accepted|ok)\b', line, re.IGNORECASE):
            status = 'SUCCESS'

    if not status:
        return None, "Missing or unrecognized authentication status (SUCCESS/FAILED)"

    # Check 3: Extract username
    username = None
    # Key-value extraction: USER:\s*([^\s,]+) or user=([^\s,]+)
    user_match = re.search(r'(?:user|username|account)\s*[:=]\s*([a-zA-Z0-9_\-\.@]+)', line, re.IGNORECASE)
    if user_match:
        username = user_match.group(1).strip()
    
    # Syslog style: "for invalid user admin" or "for admin"
    if not username:
        syslog_user_match = re.search(r'(?:for\s+(?:invalid\s+user\s+|user\s+)?)([a-zA-Z0-9_\-\.@]+)', line, re.IGNORECASE)
        if syslog_user_match:
            username = syslog_user_match.group(1).strip()

    if not username:
        return None, "Missing username or target account identifier"

    # Check 4: Extract Source IP
    ip = extract_ip(line)

    # Check 5: Extract Service (optional)
    service = "AUTH"
    service_match = re.search(r'(?:service|app|service_name)\s*[:=]\s*([a-zA-Z0-9_\-]+)', line, re.IGNORECASE)
    if service_match:
        service = service_match.group(1).strip()
    elif 'sshd' in line.lower() or 'ssh' in line.lower():
        service = 'SSH'
    elif 'vpn' in line.lower():
        service = 'VPN'
    elif 'web' in line.lower() or 'portal' in line.lower():
        service = 'Web-Portal'
    elif 'api' in line.lower():
        service = 'API'

    return {
        'timestamp': dt,
        'timestamp_str': dt_str,
        'username': username.lower(),
        'status': status,
        'source_ip': ip,
        'service': service,
    }, None


def parse_log_content(content: str, filename: str = "logs.txt") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses full log text content (.txt or .csv).
    Separates records into valid_records and invalid_records without crashing.
    """
    valid_records: List[Dict[str, Any]] = []
    invalid_records: List[Dict[str, Any]] = []

    if not content:
        return valid_records, invalid_records

    lines = content.splitlines()
    csv_headers: Optional[List[str]] = None
    
    # Check if first line is CSV header
    is_csv_file = filename.lower().endswith('.csv')
    if lines:
        first_line = lines[0].strip()
        if (',' in first_line or '\t' in first_line) and any(kw in first_line.lower() for kw in ['timestamp', 'user', 'status', 'ip']):
            try:
                reader = csv.reader(io.StringIO(first_line))
                csv_headers = next(reader)
            except Exception:
                csv_headers = None

    record_counter = 1
    start_index = 1 if csv_headers and is_csv_file else 0

    for idx, raw_line in enumerate(lines[start_index:], start=start_index + 1):
        line = raw_line.strip()
        
        # Check for blank lines
        if not line:
            invalid_records.append({
                'line_number': idx,
                'raw': raw_line,
                'reason': 'Blank or empty record'
            })
            continue

        # Check for comment lines
        if line.startswith('#'):
            # Pure informational header comments can be logged as commented out / non-record
            invalid_records.append({
                'line_number': idx,
                'raw': raw_line,
                'reason': 'Header or comment line (ignored by analyzer)'
            })
            continue

        record_data = None
        error_reason = None

        # Attempt CSV parse if comma separated
        if ',' in line and not line.startswith('['):
            csv_result = parse_csv_line(line, headers=csv_headers)
            if csv_result:
                record_data = csv_result

        # If CSV parsing didn't succeed, attempt structured text parse
        if not record_data:
            text_result, err = parse_structured_text_line(line)
            if text_result:
                record_data = text_result
            else:
                error_reason = err or "Malformed record structure"

        if record_data:
            record_data['id'] = record_counter
            record_data['line_number'] = idx
            record_data['raw'] = line
            valid_records.append(record_data)
            record_counter += 1
        else:
            invalid_records.append({
                'line_number': idx,
                'raw': raw_line,
                'reason': error_reason or 'Malformed syntax or unparseable fields'
            })

    return valid_records, invalid_records


def parse_log_file(file_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Utility to read from a local file path and parse it.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return parse_log_content(content, filename=file_path)
    except Exception as e:
        return [], [{'line_number': 0, 'raw': file_path, 'reason': f"File read error: {str(e)}"}]


def compute_parser_summary(valid_records: List[Dict[str, Any]], invalid_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes statistical overview of parsed log records.
    """
    total = len(valid_records) + len(invalid_records)
    valid_count = len(valid_records)
    invalid_count = len(invalid_records)
    
    success_count = sum(1 for r in valid_records if r['status'] == 'SUCCESS')
    failed_count = sum(1 for r in valid_records if r['status'] == 'FAILED')
    
    affected_accounts = set(r['username'] for r in valid_records if r['status'] == 'FAILED')
    unique_users = set(r['username'] for r in valid_records)
    unique_ips = set(r['source_ip'] for r in valid_records if r['source_ip'] != 'UNKNOWN')

    failure_rate = round((failed_count / valid_count * 100), 2) if valid_count > 0 else 0.0

    return {
        'total_records': total,
        'valid_records_count': valid_count,
        'invalid_records_count': invalid_count,
        'successful_logins': success_count,
        'failed_logins': failed_count,
        'failure_rate_pct': failure_rate,
        'unique_users_count': len(unique_users),
        'affected_accounts_count': len(affected_accounts),
        'unique_ips_count': len(unique_ips),
    }
