"""
Basic Security Log Analyzer - Main Application Module
Filename: main.py
Description: Flask web application providing modern cybersecurity dashboard,
             REST API endpoints, multi-format report exports, and real-time defensive analysis.
"""

import os
import io
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, send_file
from werkzeug.utils import secure_filename

import log_parser
import failed_login
import burst_detector
import report_and_tests

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'defensive-security-log-analyzer-phase-2-key'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max log upload

# In-Memory Analysis State
class AnalyzerState:
    def __init__(self):
        self.filename = "sample_logs.txt"
        self.valid_records = []
        self.invalid_records = []
        self.summary = {}
        self.failed_data = {}
        self.burst_data = {}
        self.threat_info = {}
        self.recommendations = []
        self.test_suite_cache = None
        
        # Load default sample logs on startup
        self.load_default_sample()

    def load_default_sample(self, file_type='txt'):
        sample_path = "sample_logs.csv" if file_type == 'csv' else "sample_logs.txt"
        if os.path.exists(sample_path):
            self.filename = sample_path
            self.valid_records, self.invalid_records = log_parser.parse_log_file(sample_path)
            self.recompute_all()
        else:
            self.valid_records = []
            self.invalid_records = []
            self.recompute_all()

    def process_content(self, content_str: str, filename: str):
        self.filename = filename
        self.valid_records, self.invalid_records = log_parser.parse_log_content(content_str, filename=filename)
        self.recompute_all()

    def recompute_all(self, fail_threshold=3, burst_threshold=5, window_sec=60):
        self.summary = log_parser.compute_parser_summary(self.valid_records, self.invalid_records)
        self.failed_data = failed_login.analyze_failed_logins(self.valid_records, threshold=fail_threshold)
        self.burst_data = burst_detector.detect_bursts(self.valid_records, burst_threshold=burst_threshold, window_seconds=window_sec)
        self.threat_info = report_and_tests.calculate_threat_score(self.summary, self.failed_data, self.burst_data)
        self.recommendations = report_and_tests.generate_recommendations(self.failed_data, self.burst_data)

    def get_chart_payload(self):
        # 1. Outcomes
        outcomes = {
            'success': self.summary.get('successful_logins', 0),
            'failed': self.summary.get('failed_logins', 0),
            'malformed': self.summary.get('invalid_records_count', 0),
        }

        # 2. Timeline Aggregation (hourly or 30-min intervals)
        timeline_buckets = defaultdict(lambda: {'success': 0, 'failed': 0})
        sorted_records = sorted(self.valid_records, key=lambda r: r['timestamp'])
        
        for r in sorted_records:
            bucket_key = r['timestamp'].strftime('%H:%M')
            if r['status'] == 'FAILED':
                timeline_buckets[bucket_key]['failed'] += 1
            else:
                timeline_buckets[bucket_key]['success'] += 1

        timeline_labels = sorted(list(timeline_buckets.keys()))
        # Limit to 12 points for visual elegance if dataset is large
        if len(timeline_labels) > 12:
            step = len(timeline_labels) // 12
            timeline_labels = timeline_labels[::step]

        failed_series = [timeline_buckets[lbl]['failed'] for lbl in timeline_labels]
        success_series = [timeline_buckets[lbl]['success'] for lbl in timeline_labels]

        # 3. Top Users & Top IPs
        top_users = self.failed_data.get('top_targeted_accounts', [])[:5]
        top_ips = self.failed_data.get('top_malicious_ips', [])[:5]

        return {
            'outcome': outcomes,
            'timeline': {
                'labels': timeline_labels,
                'failed_series': failed_series,
                'success_series': success_series,
            },
            'top_users': top_users,
            'top_ips': top_ips,
        }


# Global state instance
state = AnalyzerState()


@app.context_processor
def inject_global_template_vars():
    """Injects summary, current filename, and threat level into all templates"""
    return {
        'current_filename': state.filename,
        'summary': state.summary,
        'threat': state.threat_info,
    }


# ==============================================================================
# PAGE ROUTES (8 MAIN PAGES)
# ==============================================================================

@app.route('/')
@app.route('/dashboard')
def dashboard():
    """1. Home / Dashboard Page"""
    chart_payload = state.get_chart_payload()
    recent_records = sorted(state.valid_records, key=lambda r: r['timestamp'], reverse=True)[:10]
    alerts_count = state.failed_data.get('flagged_accounts_count', 0) + state.burst_data.get('total_burst_incidents', 0)

    return render_template(
        'dashboard.html',
        active_page='dashboard',
        current_filename=state.filename,
        summary=state.summary,
        threat=state.threat_info,
        failed_data=state.failed_data,
        burst_data=state.burst_data,
        alerts_count=alerts_count,
        chart_payload=chart_payload,
        recent_records=recent_records
    )


@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    """2. Upload Log Files Page"""
    if request.method == 'POST':
        if 'logfile' in request.files:
            file = request.files['logfile']
            if file and file.filename != '':
                filename = secure_filename(file.filename) or "uploaded_logs.txt"
                content = file.read().decode('utf-8', errors='replace')
                state.process_content(content, filename=filename)
                return redirect(url_for('upload_page'))

    return render_template(
        'upload.html',
        active_page='upload',
        current_filename=state.filename,
        summary=state.summary,
        valid_records=state.valid_records,
        invalid_records=state.invalid_records
    )


@app.route('/logs')
def logs_page():
    """3. Log Analysis Page"""
    return render_template(
        'logs.html',
        active_page='logs',
        current_filename=state.filename,
        summary=state.summary,
        valid_records=state.valid_records
    )


@app.route('/failed-logins')
def failed_logins_page():
    """4. Failed Login Detection Page"""
    threshold = request.args.get('threshold', default=3, type=int)
    # Re-evaluate with specified threshold
    failed_analysis = failed_login.analyze_failed_logins(state.valid_records, threshold=threshold)

    return render_template(
        'failed_logins.html',
        active_page='failed_logins',
        current_filename=state.filename,
        threshold=threshold,
        failed_data=failed_analysis,
        summary=state.summary
    )


@app.route('/bursts')
def bursts_page():
    """5. Burst Detection Page"""
    burst_threshold = request.args.get('burst_threshold', default=5, type=int)
    window_seconds = request.args.get('window_seconds', default=60, type=int)

    burst_res = burst_detector.detect_bursts(
        state.valid_records,
        burst_threshold=burst_threshold,
        window_seconds=window_seconds
    )

    return render_template(
        'bursts.html',
        active_page='bursts',
        current_filename=state.filename,
        burst_threshold=burst_threshold,
        window_seconds=window_seconds,
        burst_data=burst_res,
        summary=state.summary
    )


@app.route('/reports')
def reports_page():
    """6. Security Reports Page"""
    report_data = report_and_tests.generate_security_report(
        state.summary,
        state.failed_data,
        state.burst_data,
        filename=state.filename
    )
    report_text = report_and_tests.export_report_text(report_data)

    return render_template(
        'reports.html',
        active_page='reports',
        current_filename=state.filename,
        report_metadata=report_data['report_metadata'],
        threat=state.threat_info,
        recommendations=report_data['recommendations'],
        report_text=report_text
    )


@app.route('/tests')
def tests_page():
    """7. Testing Results Page"""
    if not state.test_suite_cache:
        state.test_suite_cache = report_and_tests.run_all_tests()

    return render_template(
        'tests.html',
        active_page='tests',
        current_filename=state.filename,
        test_suite=state.test_suite_cache
    )


@app.route('/about')
def about_page():
    """8. About Project Page"""
    return render_template(
        'about.html',
        active_page='about',
        current_filename=state.filename,
        summary=state.summary
    )


# ==============================================================================
# REST API ENDPOINTS
# ==============================================================================

@app.route('/api/load-sample', methods=['POST'])
def api_load_sample():
    """Loads sample_logs.txt or sample_logs.csv"""
    data = request.get_json(silent=True) or {}
    file_type = data.get('file_type', 'txt')
    state.load_default_sample(file_type=file_type)
    return jsonify({
        'status': 'success',
        'filename': state.filename,
        'summary': state.summary,
        'threat': state.threat_info
    })


@app.route('/api/run-tests', methods=['POST'])
def api_run_tests():
    """Runs the 5 test cases live and returns results"""
    results = report_and_tests.run_all_tests()
    state.test_suite_cache = results
    return jsonify(results)


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Returns current summary statistics and charts"""
    return jsonify({
        'summary': state.summary,
        'threat': state.threat_info,
        'failed_analysis': state.failed_data,
        'burst_analysis': state.burst_data,
        'charts': state.get_chart_payload()
    })


@app.route('/api/failed-logins', methods=['GET'])
def api_failed_logins():
    """Calculates failed login analysis with custom threshold"""
    threshold = request.args.get('threshold', default=3, type=int)
    result = failed_login.analyze_failed_logins(state.valid_records, threshold=threshold)
    return jsonify(result)


@app.route('/api/bursts', methods=['GET'])
def api_bursts():
    """Calculates bursts with custom threshold and window"""
    burst_threshold = request.args.get('threshold', default=5, type=int)
    window_sec = request.args.get('window', default=60, type=int)
    result = burst_detector.detect_bursts(state.valid_records, burst_threshold=burst_threshold, window_seconds=window_sec)
    return jsonify(result)


# ==============================================================================
# REPORT DOWNLOAD ENDPOINTS
# ==============================================================================

@app.route('/api/download/report/json')
def download_report_json():
    """Downloads full JSON security audit report"""
    report_data = report_and_tests.generate_security_report(
        state.summary,
        state.failed_data,
        state.burst_data,
        filename=state.filename
    )
    json_str = report_and_tests.export_report_json(report_data)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
    )


@app.route('/api/download/report/csv')
def download_report_csv():
    """Downloads findings and alerts in CSV format"""
    csv_str = report_and_tests.export_report_csv(
        state.valid_records,
        state.failed_data,
        state.burst_data
    )
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


@app.route('/api/download/report/text')
def download_report_text():
    """Downloads formatted executive ASCII/Text security report"""
    report_data = report_and_tests.generate_security_report(
        state.summary,
        state.failed_data,
        state.burst_data,
        filename=state.filename
    )
    txt_str = report_and_tests.export_report_text(report_data)
    return Response(
        txt_str,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=security_executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"}
    )


@app.route('/api/download/sample-logs')
def download_sample_logs():
    """Downloads the fictional sample log file"""
    if os.path.exists("sample_logs.txt"):
        return send_file("sample_logs.txt", as_attachment=True, download_name="sample_logs.txt")
    return Response("sample_logs.txt not found", status=404)


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("  Basic Security Log Analyzer - BUILDERS Phase 2")
    print("  Domain: Cybersecurity / Defensive Security")
    print("  Starting Flask Server at: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
