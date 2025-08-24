import os
import uuid
import hashlib
import mimetypes
import logging
import tempfile
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from utils.scanner import SecurityScanner
from utils.gemini_analyzer import GeminiThreatAnalyzer
from database import SecuritaNovaDB

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Initialize database
instance_folder = os.path.join(os.getcwd(), 'instance')
db_path = os.path.join(instance_folder, 'SecuritaNova.db')
db = SecuritaNovaDB(db_path)

# Configuration
UPLOAD_FOLDER = tempfile.gettempdir()
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'exe', 'bat', 'sh', 'py', 'js', 'html', 'css', 'zip', 'rar', 'doc', 'docx', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def cleanup_old_files():
    """Background thread to cleanup old files every 10 minutes"""
    while True:
        try:
            db.cleanup_old_files(max_age_hours=24)
        except Exception as e:
            logging.error(f"Database cleanup error: {e}")
        
        time.sleep(600)  # Sleep for 10 minutes

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_old_files, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Secure filename and save
        filename = secure_filename(file.filename or 'unknown_file')
        safe_filename = f"{scan_id}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': 'File too large (max 500MB)'}), 400
        
        file.save(filepath)
        
        # Store file metadata in database
        db.store_file_info(scan_id, filepath, filename, file_size, time.time())
        
        # Initialize scan progress
        db.update_scan_progress(scan_id, 'uploaded', 0, 'File uploaded successfully')
        
        # Start scanning in background
        threading.Thread(target=perform_scan, args=(scan_id,), daemon=True).start()
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'File uploaded successfully, scan started'
        })
        
    except Exception as e:
        logging.error(f"Upload error: {e}")
        return jsonify({'error': 'Upload failed'}), 500

def perform_scan(scan_id):
    """Perform the complete scan pipeline"""
    try:
        file_data = db.get_file_info(scan_id)
        if not file_data:
            return
        
        filepath = file_data['filepath']
        original_name = file_data['original_name']
        file_size = file_data['file_size']
        
        # Initialize scanner
        scanner = SecurityScanner(database=db)
        gemini_analyzer = GeminiThreatAnalyzer()
        
        # Stage 1: File validation
        db.update_scan_progress(scan_id, 'validation', 10, 'Validating file integrity...')
        
        validation_result = scanner.validate_file(filepath, original_name)
        
        # Stage 2: Hashing
        db.update_scan_progress(scan_id, 'hashing', 25, 'Generating file hashes...')
        
        hash_result = scanner.generate_hashes(filepath)
        
        # Stage 3: Database lookup
        db.update_scan_progress(scan_id, 'lookup', 40, 'Checking threat database...')
        
        lookup_result = scanner.database_lookup(hash_result)
        
        # Stage 4: Sandbox simulation
        db.update_scan_progress(scan_id, 'sandbox', 55, 'Running sandbox analysis...')
        
        sandbox_result = scanner.sandbox_analysis(filepath, original_name)
        
        # Stage 5: Heuristic analysis
        db.update_scan_progress(scan_id, 'heuristics', 70, 'Performing heuristic analysis...')
        
        heuristic_result = scanner.heuristic_analysis(filepath, original_name, file_size)
        
        # Stage 6: Code analysis
        db.update_scan_progress(scan_id, 'code_analysis', 85, 'Analyzing code patterns...')
        
        code_result = scanner.static_code_analysis(filepath, original_name)
        
        # Stage 7: Gemini AI analysis
        db.update_scan_progress(scan_id, 'ai_analysis', 95, 'Running AI threat analysis...')
        
        # Prepare data for Gemini
        scan_summary = {
            'file_name': original_name,
            'file_type': mimetypes.guess_type(original_name)[0] or 'unknown',
            'hashes': hash_result,
            'sandbox_risk': sandbox_result['risk_level'],
            'behavior_score': heuristic_result['risk_score'],
            'code_analysis_findings': code_result.get('findings', []),
            'lookup_result': lookup_result['status']
        }
        
        gemini_result = gemini_analyzer.analyze_threat(scan_summary)
        
        # Complete scan
        db.update_scan_progress(scan_id, 'complete', 100, 'Scan completed successfully')
        
        # Store complete results
        results = {
            'scan_id': scan_id,
            'file_name': original_name,
            'file_size': file_size,
            'file_type': mimetypes.guess_type(original_name)[0] or 'unknown',
            'scan_timestamp': datetime.now().isoformat(),
            'validation': validation_result,
            'hashes': hash_result,
            'database_lookup': lookup_result,
            'sandbox_analysis': sandbox_result,
            'heuristic_analysis': heuristic_result,
            'code_analysis': code_result,
            'gemini_analysis': gemini_result,
            'overall_threat_level': determine_overall_threat(
                lookup_result, sandbox_result, heuristic_result, 
                code_result, gemini_result
            )
        }
        
        db.store_scan_results(scan_id, results)
        
    except Exception as e:
        logging.error(f"Scan error for {scan_id}: {e}")
        db.update_scan_progress(scan_id, 'error', 0, f'Scan failed: {str(e)}')

def determine_overall_threat(lookup, sandbox, heuristic, code, gemini):
    """Determine overall threat level based on all scan results"""
    threat_scores = []
    
    # Convert results to numeric scores
    if lookup['status'] == 'malicious':
        threat_scores.append(100)
    elif lookup['status'] == 'suspicious':
        threat_scores.append(70)
    else:
        threat_scores.append(0)
    
    # Sandbox risk scoring
    sandbox_score_map = {'Low': 20, 'Medium': 50, 'High': 80}
    threat_scores.append(sandbox_score_map.get(sandbox['risk_level'], 0))
    
    # Heuristic score
    threat_scores.append(heuristic['risk_score'])
    
    # Code analysis score
    threat_scores.append(code.get('risk_score', 0))
    
    # Gemini AI score
    gemini_score_map = {'Safe': 10, 'Suspicious': 60, 'Malicious': 90}
    threat_scores.append(gemini_score_map.get(gemini.get('classification', 'Safe'), 10))
    
    avg_score = sum(threat_scores) / len(threat_scores)
    
    if avg_score >= 70:
        return {'level': 'Malicious', 'score': avg_score, 'color': 'red'}
    elif avg_score >= 40:
        return {'level': 'Suspicious', 'score': avg_score, 'color': 'yellow'}
    else:
        return {'level': 'Safe', 'score': avg_score, 'color': 'green'}

@app.route('/scan/<scan_id>')
def scan_page(scan_id):
    return render_template('scan.html', scan_id=scan_id)

@app.route('/api/scan/<scan_id>/progress')
def get_scan_progress(scan_id):
    progress = db.get_scan_progress(scan_id)
    if not progress:
        progress = {
            'stage': 'not_found',
            'progress': 0,
            'message': 'Scan not found'
        }
    return jsonify(progress)

@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    results = db.get_scan_results(scan_id)
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    return jsonify(results)

@app.route('/api/scan/<scan_id>/report')
def download_report(scan_id):
    results = db.get_scan_results(scan_id)
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    
    try:
        # Generate text report
        report_content = generate_text_report(results)
        
        # Create temporary file for report
        report_filename = f"securitanova_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = os.path.join(tempfile.gettempdir(), report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return send_file(report_path, as_attachment=True, download_name=report_filename)
        
    except Exception as e:
        logging.error(f"Report generation error: {e}")
        return jsonify({'error': 'Report generation failed'}), 500

def generate_text_report(results):
    """Generate a detailed text report"""
    report = f"""
═══════════════════════════════════════════════════════════════
                    SECURITANOVA SCAN REPORT
═══════════════════════════════════════════════════════════════

File Information:
  Name: {results['file_name']}
  Size: {results['file_size']:,} bytes
  Type: {results['file_type']}
  Scan ID: {results['scan_id']}
  Scan Time: {results['scan_timestamp']}

Overall Threat Assessment:
  Level: {results['overall_threat_level']['level']}
  Score: {results['overall_threat_level']['score']:.1f}/100
  Status: {results['overall_threat_level']['color'].upper()}

═══════════════════════════════════════════════════════════════
                        SCAN MODULES
═══════════════════════════════════════════════════════════════

1. FILE VALIDATION
   Status: {results['validation']['status']}
   Message: {results['validation']['message']}

2. HASH ANALYSIS
   MD5: {results['hashes']['md5']}
   SHA256: {results['hashes']['sha256']}

3. DATABASE LOOKUP
   Status: {results['database_lookup']['status']}
   Message: {results['database_lookup']['message']}

4. SANDBOX ANALYSIS
   Risk Level: {results['sandbox_analysis']['risk_level']}
   Findings: {', '.join(results['sandbox_analysis']['findings'])}

5. HEURISTIC ANALYSIS
   Risk Score: {results['heuristic_analysis']['risk_score']}/100
   Findings: {', '.join(results['heuristic_analysis']['findings'])}

6. CODE ANALYSIS
   Risk Score: {results['code_analysis'].get('risk_score', 0)}/100
   Findings: {', '.join(results['code_analysis'].get('findings', []))}

7. GEMINI AI ANALYSIS
   Classification: {results['gemini_analysis'].get('classification', 'Unknown')}
   Explanation: {results['gemini_analysis'].get('explanation', 'No analysis available')}
   Recommendation: {results['gemini_analysis'].get('recommendation', 'No recommendation available')}

═══════════════════════════════════════════════════════════════
                        DISCLAIMER
═══════════════════════════════════════════════════════════════

This scan report is generated by SecuritaNova, a demonstration
antivirus system. Results are based on simulated scanning
techniques and should not be used as the sole basis for security
decisions in production environments.

Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    return report

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
