from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import os
import uuid
import threading
from datetime import datetime
from models import db, AnalysisSession, BehaviorEvent, NetworkEvent
from analyzer import SandboxAnalyzer

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

# Initialize analyzer
analyzer = SandboxAnalyzer()


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

    return render_template('session.html', session_id=session_id)


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
