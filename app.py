from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, send_file
from werkzeug.utils import secure_filename
import os
import uuid
import threading
import json
from datetime import datetime
from models import (
    db, AnalysisSession, BehaviorEvent, NetworkEvent, ProcessEvent,
    DroppedFile, IOC, MitreAttack, StringAnalysis, MutexHandle,
    MemoryRegion, Screenshot, YaraMatch, Certificate
)
from advanced_analyzer import AdvancedAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///anyrun.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'docx', 'xlsx', 'zip', 'rar',
    'js', 'vbs', 'bat', 'ps1', 'py', 'jar', 'apk'
}

# Initialize database
db.init_app(app)

# Create upload and results directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

# Initialize advanced analyzer
analyzer = AdvancedAnalyzer()


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_in_background(filepath, filename, session_id):
    """Run analysis in background thread"""
    with app.app_context():
        analyzer.analyze_file(filepath, filename, session_id)


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    try:
        # Generate unique session ID
        session_id = str(uuid.uuid4())

        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_{filename}")
        file.save(filepath)

        # Start analysis in background
        thread = threading.Thread(
            target=analyze_in_background,
            args=(filepath, filename, session_id)
        )
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'File uploaded successfully. Analysis started.'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/session/<session_id>')
def view_session(session_id):
    """View analysis session details"""
    session = AnalysisSession.query.filter_by(session_id=session_id).first()
    if not session:
        return "Session not found", 404

    return render_template('session_advanced.html', session_id=session_id)


@app.route('/api/session/<session_id>')
def get_session_data(session_id):
    """API endpoint to get session data"""
    details = analyzer.get_session_details(session_id)
    if not details:
        return jsonify({'error': 'Session not found'}), 404

    return jsonify(details)


@app.route('/api/session/<session_id>/status')
def get_session_status(session_id):
    """API endpoint to check session status"""
    session = AnalysisSession.query.filter_by(session_id=session_id).first()
    if not session:
        return jsonify({'error': 'Session not found'}), 404

    return jsonify({
        'status': session.status,
        'session_id': session_id
    })


@app.route('/sessions')
def list_sessions():
    """List all analysis sessions"""
    sessions = AnalysisSession.query.order_by(AnalysisSession.created_at.desc()).limit(50).all()
    return render_template('sessions.html', sessions=sessions)


@app.route('/api/sessions')
def get_sessions():
    """API endpoint to get all sessions"""
    sessions = AnalysisSession.query.order_by(AnalysisSession.created_at.desc()).limit(50).all()
    return jsonify([s.to_dict() for s in sessions])


@app.route('/api/session/<session_id>/behaviors')
def get_behaviors(session_id):
    """Get behavioral events for a session"""
    behaviors = BehaviorEvent.query.filter_by(session_id=session_id).all()
    return jsonify([b.to_dict() for b in behaviors])


@app.route('/api/session/<session_id>/network')
def get_network_events(session_id):
    """Get network events for a session"""
    events = NetworkEvent.query.filter_by(session_id=session_id).all()
    return jsonify([e.to_dict() for e in events])


@app.route('/dashboard')
def dashboard():
    """Analysis dashboard"""
    return render_template('dashboard.html')


@app.route('/api/stats')
def get_stats():
    """Get overall statistics"""
    total_sessions = AnalysisSession.query.count()
    completed = AnalysisSession.query.filter_by(status='completed').count()
    analyzing = AnalysisSession.query.filter_by(status='analyzing').count()
    errors = AnalysisSession.query.filter_by(status='error').count()

    return jsonify({
        'total_sessions': total_sessions,
        'completed': completed,
        'analyzing': analyzing,
        'errors': errors
    })


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 100MB'}), 413


@app.route('/api/session/<session_id>/processes')
def get_processes(session_id):
    """Get process tree for a session"""
    processes = ProcessEvent.query.filter_by(session_id=session_id).all()
    return jsonify([p.to_dict() for p in processes])


@app.route('/api/session/<session_id>/dropped-files')
def get_dropped_files(session_id):
    """Get dropped files for a session"""
    files = DroppedFile.query.filter_by(session_id=session_id).all()
    return jsonify([f.to_dict() for f in files])


@app.route('/api/session/<session_id>/iocs')
def get_iocs(session_id):
    """Get IOCs for a session"""
    iocs = IOC.query.filter_by(session_id=session_id).all()
    return jsonify([i.to_dict() for i in iocs])


@app.route('/api/session/<session_id>/mitre')
def get_mitre(session_id):
    """Get MITRE ATT&CK mappings for a session"""
    mitre = MitreAttack.query.filter_by(session_id=session_id).all()
    return jsonify([m.to_dict() for m in mitre])


@app.route('/api/session/<session_id>/strings')
def get_strings(session_id):
    """Get extracted strings for a session"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    strings = StringAnalysis.query.filter_by(session_id=session_id).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'strings': [s.to_dict() for s in strings.items],
        'total': strings.total,
        'pages': strings.pages,
        'current_page': page
    })


@app.route('/api/session/<session_id>/mutexes')
def get_mutexes(session_id):
    """Get mutexes and handles for a session"""
    mutexes = MutexHandle.query.filter_by(session_id=session_id).all()
    return jsonify([m.to_dict() for m in mutexes])


@app.route('/api/session/<session_id>/memory')
def get_memory(session_id):
    """Get memory regions for a session"""
    regions = MemoryRegion.query.filter_by(session_id=session_id).all()
    return jsonify([r.to_dict() for r in regions])


@app.route('/api/session/<session_id>/screenshots')
def get_screenshots(session_id):
    """Get screenshots for a session"""
    screenshots = Screenshot.query.filter_by(session_id=session_id).all()
    return jsonify([s.to_dict() for s in screenshots])


@app.route('/api/session/<session_id>/screenshot/<filename>')
def get_screenshot_file(session_id, filename):
    """Download a specific screenshot"""
    screenshot_path = os.path.join(app.config['RESULTS_FOLDER'], session_id, 'screenshots', filename)
    if os.path.exists(screenshot_path):
        return send_file(screenshot_path, mimetype='image/png')
    return jsonify({'error': 'Screenshot not found'}), 404


@app.route('/api/session/<session_id>/yara')
def get_yara(session_id):
    """Get YARA matches for a session"""
    matches = YaraMatch.query.filter_by(session_id=session_id).all()
    return jsonify([m.to_dict() for m in matches])


@app.route('/api/session/<session_id>/certificates')
def get_certificates(session_id):
    """Get certificate information for a session"""
    certs = Certificate.query.filter_by(session_id=session_id).all()
    return jsonify([c.to_dict() for c in certs])


@app.route('/api/session/<session_id>/timeline')
def get_timeline(session_id):
    """Get complete timeline of all events"""
    timeline = []

    # Collect all events with timestamps
    behaviors = BehaviorEvent.query.filter_by(session_id=session_id).all()
    for b in behaviors:
        timeline.append({
            'timestamp': b.timestamp.isoformat() if b.timestamp else None,
            'type': 'behavior',
            'category': b.event_type,
            'description': b.description,
            'severity': b.severity
        })

    network = NetworkEvent.query.filter_by(session_id=session_id).all()
    for n in network:
        timeline.append({
            'timestamp': n.timestamp.isoformat() if n.timestamp else None,
            'type': 'network',
            'category': n.protocol,
            'description': f'{n.protocol} connection to {n.domain or n.destination_ip}',
            'severity': 'medium'
        })

    processes = ProcessEvent.query.filter_by(session_id=session_id).all()
    for p in processes:
        timeline.append({
            'timestamp': p.timestamp.isoformat() if p.timestamp else None,
            'type': 'process',
            'category': p.status,
            'description': f'{p.process_name} (PID: {p.pid})',
            'severity': 'medium'
        })

    dropped = DroppedFile.query.filter_by(session_id=session_id).all()
    for d in dropped:
        timeline.append({
            'timestamp': d.timestamp.isoformat() if d.timestamp else None,
            'type': 'file',
            'category': 'dropped_file',
            'description': f'Dropped file: {d.file_name}',
            'severity': 'high' if d.is_malicious else 'low'
        })

    # Sort by timestamp
    timeline.sort(key=lambda x: x['timestamp'] or '')

    return jsonify(timeline)


@app.route('/api/session/<session_id>/export/<format>')
def export_report(session_id, format):
    """Export analysis report in various formats"""
    details = analyzer.get_session_details(session_id)
    if not details:
        return jsonify({'error': 'Session not found'}), 404

    if format == 'json':
        return jsonify(details)

    elif format == 'html':
        # Generate HTML report
        return render_template('report.html', data=details, session_id=session_id)

    else:
        return jsonify({'error': 'Unsupported format. Use json or html'}), 400


@app.route('/session/<session_id>/report')
def view_report(session_id):
    """View comprehensive analysis report"""
    session = AnalysisSession.query.filter_by(session_id=session_id).first()
    if not session:
        return "Session not found", 404

    return render_template('report.html', session_id=session_id)


@app.route('/api/search')
def search_sessions():
    """Search sessions by various criteria"""
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'filename')

    if search_type == 'filename':
        sessions = AnalysisSession.query.filter(
            AnalysisSession.filename.like(f'%{query}%')
        ).limit(50).all()
    elif search_type == 'hash':
        sessions = AnalysisSession.query.filter(
            AnalysisSession.file_hash.like(f'%{query}%')
        ).limit(50).all()
    else:
        sessions = []

    return jsonify([s.to_dict() for s in sessions])


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("=" * 60)
    print("🔒 AnyRun Clone - Interactive Malware Analysis Sandbox")
    print("=" * 60)
    print("Server starting on http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
