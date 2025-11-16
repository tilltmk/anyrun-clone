// Modern AnyRun Clone - Main JavaScript
// Version 3.0 - Full Featured

// Initialize Socket.IO
const socket = io();

// State Management
const state = {
    selectedFile: null,
    selectedOS: 'windows10',
    uploadProgress: 0,
    currentTheme: 'dark'
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
    initializeUpload();
    initializeTabs();
    initializeTheme();
    loadRecentSessions();
    loadStats();
    setupSocketListeners();
});

// ============================================
// UPLOAD FUNCTIONALITY
// ============================================

function initializeUpload() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileSelected = document.getElementById('fileSelected');
    const uploadArea = document.querySelector('.drop-zone');

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });

    // Drag and drop events
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    // Click to upload
    dropZone.addEventListener('click', () => {
        fileInput.click();
    });

    // OS selection
    document.querySelectorAll('input[name="os"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            state.selectedOS = e.target.value;
        });
    });

    // Start analysis button
    const startBtn = document.getElementById('startAnalysisBtn');
    if (startBtn) {
        startBtn.addEventListener('click', startAnalysis);
    }
}

function handleFileSelect(file) {
    state.selectedFile = file;

    // Update UI
    document.querySelector('.drop-zone').style.display = 'none';
    document.getElementById('fileSelected').style.display = 'block';

    // Show file info
    document.getElementById('selectedFileName').textContent = file.name;
    document.getElementById('selectedFileSize').textContent = formatFileSize(file.size);

    // Add animation
    document.getElementById('fileSelected').classList.add('animate-slide-in');
}

function clearFile() {
    state.selectedFile = null;
    document.querySelector('.drop-zone').style.display = 'block';
    document.getElementById('fileSelected').style.display = 'none';
    document.getElementById('fileInput').value = '';
}

async function startAnalysis() {
    if (!state.selectedFile) {
        showNotification('Please select a file first', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', state.selectedFile);
    formData.append('os_type', state.selectedOS);

    // Get analysis options
    const networkMonitoring = document.querySelector('input[type="checkbox"]:nth-of-type(1)').checked;
    const recordVideo = document.querySelector('input[type="checkbox"]:nth-of-type(2)').checked;
    const extendedAnalysis = document.querySelector('input[type="checkbox"]:nth-of-type(3)').checked;

    formData.append('network_monitoring', networkMonitoring);
    formData.append('record_video', recordVideo);
    formData.append('extended_analysis', extendedAnalysis);

    // Show loading
    const startBtn = document.getElementById('startAnalysisBtn');
    const originalText = startBtn.innerHTML;
    startBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Starting Analysis...';
    startBtn.disabled = true;

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Analysis started successfully!', 'success');

            // Redirect to session view
            setTimeout(() => {
                window.location.href = `/session/${data.session_id}`;
            }, 1000);
        } else {
            showNotification(data.error || 'Upload failed', 'error');
            startBtn.innerHTML = originalText;
            startBtn.disabled = false;
        }
    } catch (error) {
        showNotification('Upload failed: ' + error.message, 'error');
        startBtn.innerHTML = originalText;
        startBtn.disabled = false;
    }
}

// ============================================
// TABS FUNCTIONALITY
// ============================================

function initializeTabs() {
    const tabButtons = document.querySelectorAll('.upload-tab');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.dataset.tab;

            // Remove active class from all
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Add active class to clicked tab
            button.classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
        });
    });
}

// ============================================
// THEME FUNCTIONALITY
// ============================================

function initializeTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    state.currentTheme = theme;

    // Update icon
    const themeToggle = document.querySelector('.theme-toggle i');
    if (themeToggle) {
        themeToggle.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// ============================================
// RECENT SESSIONS
// ============================================

async function loadRecentSessions() {
    try {
        const response = await fetch('/api/sessions');
        const sessions = await response.json();

        const grid = document.getElementById('recentGrid');

        if (sessions.length === 0) {
            grid.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: var(--text-secondary);">No recent sessions</p>';
            return;
        }

        grid.innerHTML = sessions.slice(0, 6).map(session => createSessionCard(session)).join('');
    } catch (error) {
        console.error('Error loading sessions:', error);
    }
}

function createSessionCard(session) {
    const statusColor = {
        'completed': 'var(--accent-success)',
        'analyzing': 'var(--accent-primary)',
        'pending': 'var(--accent-warning)',
        'error': 'var(--accent-danger)'
    }[session.status] || 'var(--text-secondary)';

    return `
        <div class="session-card modern-card" onclick="window.location.href='/session/${session.session_id}'" style="cursor: pointer;">
            <div class="session-card-header">
                <div class="session-icon">
                    <i class="fas fa-file-code"></i>
                </div>
                <div class="session-status" style="background: ${statusColor}; width: 8px; height: 8px; border-radius: 50%;"></div>
            </div>
            <h3 class="session-filename" style="font-size: 0.95rem; margin: var(--spacing-md) 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${session.filename}</h3>
            <div class="session-meta" style="display: flex; justify-content: space-between; font-size: 0.8rem; color: var(--text-secondary);">
                <span>${session.file_type}</span>
                <span>${formatDate(session.created_at)}</span>
            </div>
        </div>
    `;
}

// ============================================
// STATS
// ============================================

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();

        document.getElementById('activeSessions').textContent = stats.analyzing || 0;
        document.getElementById('totalAnalyzed').textContent = stats.total_sessions || 0;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// ============================================
// SOCKET.IO REAL-TIME UPDATES
// ============================================

function setupSocketListeners() {
    socket.on('connect', () => {
        console.log('Connected to server via WebSocket');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
    });

    socket.on('stats_update', (data) => {
        document.getElementById('activeSessions').textContent = data.analyzing || 0;
        document.getElementById('totalAnalyzed').textContent = data.total_sessions || 0;
    });

    socket.on('new_session', (data) => {
        loadRecentSessions();
    });

    socket.on('session_update', (data) => {
        // Update session card if visible
        updateSessionCard(data);
    });
}

function updateSessionCard(sessionData) {
    // Find and update session card in recent grid
    const cards = document.querySelectorAll('.session-card');
    cards.forEach(card => {
        if (card.getAttribute('data-session-id') === sessionData.session_id) {
            // Update status indicator
            const statusIndicator = card.querySelector('.session-status');
            if (statusIndicator) {
                const statusColor = {
                    'completed': 'var(--accent-success)',
                    'analyzing': 'var(--accent-primary)',
                    'pending': 'var(--accent-warning)',
                    'error': 'var(--accent-danger)'
                }[sessionData.status] || 'var(--text-secondary)';

                statusIndicator.style.background = statusColor;
            }
        }
    });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;

    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }

    // Less than 1 hour
    if (diff < 3600000) {
        const mins = Math.floor(diff / 60000);
        return `${mins} min${mins > 1 ? 's' : ''} ago`;
    }

    // Less than 1 day
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }

    // Format date
    return date.toLocaleDateString('de-DE', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? 'var(--accent-success)' : type === 'error' ? 'var(--accent-danger)' : 'var(--accent-primary)'};
        color: white;
        border-radius: var(--radius-lg);
        box-shadow: var(--shadow-xl);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        display: flex;
        align-items: center;
        gap: var(--spacing-md);
        min-width: 300px;
    `;

    const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle';
    notification.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;

    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// ============================================
// KEYBOARD SHORTCUTS
// ============================================

document.addEventListener('keydown', (e) => {
    // Ctrl+U - Upload
    if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        document.getElementById('fileInput').click();
    }

    // Ctrl+T - Toggle theme
    if (e.ctrlKey && e.key === 't') {
        e.preventDefault();
        toggleTheme();
    }

    // Esc - Clear file selection
    if (e.key === 'Escape' && state.selectedFile) {
        clearFile();
    }
});

// ============================================
// AUTO-REFRESH STATS
// ============================================

// Refresh stats every 30 seconds
setInterval(() => {
    loadStats();
}, 30000);

// Refresh recent sessions every 60 seconds
setInterval(() => {
    loadRecentSessions();
}, 60000);

// Log for debugging
console.log('%c🔒 AnyRun Clone v3.0', 'color: #667eea; font-size: 20px; font-weight: bold;');
console.log('%cFull-Featured Malware Analysis Platform', 'color: #764ba2; font-size: 14px;');
console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'color: #3b82f6;');
console.log('WebSocket:', socket.connected ? '✅ Connected' : '❌ Disconnected');
console.log('Theme:', state.currentTheme);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
