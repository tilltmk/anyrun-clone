from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, send_file
from flask_socketio import SocketIO, emit
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
from real_analyzer import RealAnalyzer
from vm_manager import VMManager
from vnc_proxy import VNCWebSocketProxy
from setup_manager import SetupManager

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///anyrun.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'docx', 'xlsx', 'zip', 'rar',
    'js', 'vbs', 'bat', 'ps1', 'py', 'jar', 'apk', 'msi',
    'scr', 'com', 'pif', 'hta', 'cpl', 'msc'
}

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize database
db.init_app(app)

# Create upload and results directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

# Initialize components - REAL analyzer, no fake data
analyzer = None  # Will be initialized after socketio
vm_manager = VMManager()
vnc_proxy = VNCWebSocketProxy()
setup_manager = SetupManager()
active_sessions = {}  # Track active analysis sessions


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_in_background(filepath, filename, session_id, analysis_type='static', os_type='windows10'):
    """Run REAL analysis in background thread - NO FAKE DATA"""
    global analyzer
    with app.app_context():
        if analyzer is None:
            analyzer = RealAnalyzer(socketio=socketio)

        if analysis_type == 'dynamic':
            # Full dynamic analysis with KVM VM
            result = analyzer.analyze_file_dynamic(filepath, filename, session_id, os_type=os_type)
        else:
            # Static analysis only (no VM execution)
            result = analyzer.analyze_file_static(filepath, filename, session_id)

        # Store result in active sessions
        active_sessions[session_id] = result


@app.route('/')
def index():
    """Modern home page with KVM support"""
    # Check if setup is needed
    if setup_manager.needs_setup():
        return redirect(url_for('setup_wizard'))
    return render_template('modern_index.html')


@app.route('/setup')
def setup_wizard():
    """Initial setup wizard"""
    return render_template('setup.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start REAL analysis - NO FAKE DATA"""
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

        # Get analysis options from request
        analysis_type = request.form.get('analysis_type', 'static')  # 'static' or 'dynamic'
        os_type = request.form.get('os_type', 'windows10')  # OS for dynamic analysis

        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_{filename}")
        file.save(filepath)

        # Create results directory for this session
        os.makedirs(os.path.join(app.config['RESULTS_FOLDER'], session_id), exist_ok=True)

        # Start REAL analysis in background - NO FAKE DATA
        thread = threading.Thread(
            target=analyze_in_background,
            args=(filepath, filename, session_id, analysis_type, os_type)
        )
        thread.daemon = True
        thread.start()

        response_data = {
            'success': True,
            'session_id': session_id,
            'analysis_type': analysis_type,
            'message': f'File uploaded. Starting {analysis_type} analysis.'
        }

        # If dynamic analysis, start VNC proxy for KVM stream
        if analysis_type == 'dynamic':
            vnc_port = vm_manager.vm_configs.get(os_type, {}).get('vnc_port', 5900)
            proxy_result = vnc_proxy.start_proxy(session_id, vnc_port=vnc_port)
            if proxy_result['success']:
                response_data['vnc_ws_url'] = proxy_result['ws_url']
                response_data['vnc_ws_port'] = proxy_result['ws_port']

        return jsonify(response_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/session/<session_id>')
def view_session(session_id):
    """View analysis session details - REAL DATA"""
    session = AnalysisSession.query.filter_by(session_id=session_id).first()
    if not session:
        return "Session not found", 404

    # Use live interface for better any.run-style experience
    return render_template('session_live.html', session_id=session_id)


@app.route('/session/<session_id>/advanced')
def view_session_advanced(session_id):
    """View advanced session details"""
    session = AnalysisSession.query.filter_by(session_id=session_id).first()
    if not session:
        return "Session not found", 404

    return render_template('session_advanced.html', session_id=session_id)


@app.route('/api/session/<session_id>')
def get_session_data(session_id):
    """API endpoint to get REAL session data - NO FAKE DATA"""
    global analyzer
    if analyzer is None:
        analyzer = RealAnalyzer(socketio=socketio)

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


@app.route('/api/session/<session_id>/vnc')
def get_vnc_info(session_id):
    """Get VNC connection info for KVM stream"""
    proxy_info = vnc_proxy.get_proxy_info(session_id)
    if proxy_info:
        return jsonify({
            'success': True,
            'ws_port': proxy_info['ws_port'],
            'ws_url': f'ws://localhost:{proxy_info["ws_port"]}'
        })
    return jsonify({'success': False, 'error': 'No active VM for this session'}), 404


@app.route('/api/vm/status/<session_id>')
def get_vm_status(session_id):
    """Get VM status for a session"""
    # Find VM by session ID
    for vm in vm_manager.list_vms():
        if session_id in vm.get('name', ''):
            return jsonify(vm_manager.get_vm_status(vm['name']))
    return jsonify({'status': 'not_found'})


# ============================================
# SETUP API ENDPOINTS
# ============================================

@app.route('/api/setup/status')
def get_setup_status():
    """Get current setup status"""
    return jsonify(setup_manager.get_setup_status())


@app.route('/api/setup/network', methods=['POST'])
def create_network():
    """Create isolated network for VM analysis"""
    result = setup_manager.create_isolated_network()
    return jsonify(result)


@app.route('/api/setup/isos')
def list_isos():
    """Search for ISO files on the system"""
    isos = setup_manager.list_iso_files()
    return jsonify({'isos': isos})


@app.route('/api/setup/template', methods=['POST'])
def create_vm_template():
    """Create a VM template from an ISO"""
    data = request.get_json()
    iso_path = data.get('iso_path')
    os_type = data.get('os_type', 'windows10')
    memory = data.get('memory', 4096)
    disk_size = data.get('disk_size', 40)

    if not iso_path:
        return jsonify({'success': False, 'error': 'ISO path is required'}), 400

    result = setup_manager.create_vm_template(
        iso_path=iso_path,
        os_type=os_type,
        memory=memory,
        disk_size=disk_size
    )
    return jsonify(result)


@app.route('/api/setup/vm/<os_type>/start', methods=['POST'])
def start_vm_for_setup(os_type):
    """Start VM for OS installation"""
    result = setup_manager.start_vm_for_installation(os_type)
    return jsonify(result)


@app.route('/api/setup/vm/<os_type>/stop', methods=['POST'])
def stop_vm_for_setup(os_type):
    """Stop VM"""
    result = setup_manager.stop_vm(os_type)
    return jsonify(result)


@app.route('/api/setup/vm/<os_type>/complete', methods=['POST'])
def mark_vm_complete(os_type):
    """Mark VM installation as complete and create snapshot"""
    result = setup_manager.mark_installation_complete(os_type)
    return jsonify(result)


@app.route('/api/setup/complete', methods=['POST'])
def complete_setup():
    """Mark setup as complete"""
    status = setup_manager.get_setup_status()

    # Check if at least one template is ready
    ready_templates = [t for t in status['vm_templates'].values()
                      if t.get('status') == 'ready']

    if ready_templates:
        setup_manager.config['setup_complete'] = True
        setup_manager._save_config()
        return jsonify({'success': True, 'message': 'Setup complete!'})
    else:
        return jsonify({
            'success': False,
            'message': 'Please complete at least one VM template installation first'
        })


@app.route('/api/setup/skip', methods=['POST'])
def skip_setup():
    """Skip setup for static-only analysis"""
    setup_manager.config['setup_complete'] = True
    setup_manager.config['static_only'] = True
    setup_manager._save_config()
    return jsonify({'success': True, 'message': 'Setup skipped. Static analysis only.'})


@app.route('/api/setup/reset', methods=['POST'])
def reset_setup():
    """Reset setup to allow reconfiguration"""
    setup_manager.config['setup_complete'] = False
    setup_manager.config['static_only'] = False
    setup_manager._save_config()
    return jsonify({'success': True, 'message': 'Setup reset. Please reconfigure.'})


@app.route('/api/setup/validate-iso', methods=['POST'])
def validate_iso():
    """Validate that an ISO file exists and is readable"""
    data = request.get_json()
    iso_path = data.get('iso_path', '')

    if not iso_path:
        return jsonify({'valid': False, 'error': 'No path provided'})

    if not os.path.exists(iso_path):
        return jsonify({'valid': False, 'error': 'File does not exist'})

    if not iso_path.lower().endswith('.iso'):
        return jsonify({'valid': False, 'error': 'File is not an ISO'})

    if not os.access(iso_path, os.R_OK):
        return jsonify({'valid': False, 'error': 'File is not readable'})

    size = os.path.getsize(iso_path)
    if size < 100 * 1024 * 1024:  # Less than 100MB
        return jsonify({'valid': False, 'error': 'File is too small for an OS ISO'})

    return jsonify({
        'valid': True,
        'name': os.path.basename(iso_path),
        'size': size,
        'size_human': f"{size / (1024*1024*1024):.2f} GB"
    })


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ============================================
# WEBSOCKET EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected: {request.sid}')
    emit('connection_response', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f'Client disconnected: {request.sid}')


@socketio.on('join_session')
def handle_join_session(data):
    """Join a specific analysis session room"""
    session_id = data.get('session_id')
    if session_id:
        # Join room for this session
        from flask_socketio import join_room
        join_room(session_id)
        emit('joined_session', {'session_id': session_id})


@socketio.on('leave_session')
def handle_leave_session(data):
    """Leave analysis session room"""
    session_id = data.get('session_id')
    if session_id:
        from flask_socketio import leave_room
        leave_room(session_id)


def broadcast_session_update(session_id, event_type, data):
    """Broadcast update to all clients watching a session"""
    socketio.emit('session_update', {
        'session_id': session_id,
        'event_type': event_type,
        'data': data
    }, room=session_id)


def broadcast_stats():
    """Broadcast updated stats to all clients"""
    total_sessions = AnalysisSession.query.count()
    analyzing = AnalysisSession.query.filter_by(status='analyzing').count()

    socketio.emit('stats_update', {
        'total_sessions': total_sessions,
        'analyzing': analyzing
    })


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Initialize analyzer with socketio
    analyzer = RealAnalyzer(socketio=socketio)

    print("=" * 70)
    print("  AnyRun Clone v4.0 - REAL Analysis Edition")
    print("  NO FAKE DATA - All analysis is performed on actual files")
    print("=" * 70)
    print("Features:")
    print("  - Real KVM/QEMU Virtual Machines")
    print("  - Real YARA Rule Scanning")
    print("  - Real String Extraction & Analysis")
    print("  - Real Network Traffic Capture")
    print("  - Real PE File Analysis")
    print("  - VNC WebSocket Proxy for Live VM Stream")
    print("  - WebSocket Real-time Updates")
    print("=" * 70)

    # Check setup status
    setup_status = setup_manager.get_setup_status()
    if setup_manager.needs_setup():
        print("SETUP REQUIRED:")
        print("  First-time setup wizard will guide you through configuration.")
        print("  - Configure isolated network for VM analysis")
        print("  - Select ISO image and create VM template")
        print("  - Complete OS installation via VNC")
    else:
        print("SETUP STATUS: Complete")
        if setup_status.get('vm_templates'):
            print(f"  VM Templates: {len(setup_status['vm_templates'])} configured")
            for os_type, template in setup_status['vm_templates'].items():
                status = template.get('status', 'unknown')
                print(f"    - {os_type}: {status}")
        if setup_status.get('static_only'):
            print("  Mode: Static Analysis Only (KVM disabled)")

    print("=" * 70)
    print("IMPORTANT: This version performs REAL analysis.")
    print("  Static Analysis: Analyzes file without execution")
    print("  Dynamic Analysis: Executes file in isolated KVM VM")
    print("=" * 70)
    print("Server starting on http://localhost:5000")
    print("WebSocket enabled on ws://localhost:5000")
    print("=" * 70)

    # Run with SocketIO
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
