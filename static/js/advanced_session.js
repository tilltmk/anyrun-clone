// Advanced Session Analysis JavaScript

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
    return date.toLocaleString('de-DE');
}

function updateSessionInfo(data) {
    const fileDetails = document.getElementById('fileDetails');
    fileDetails.innerHTML = `
        <table class="info-table">
            <tr><td><strong>Filename:</strong></td><td>${data.session.filename}</td></tr>
            <tr><td><strong>SHA256:</strong></td><td><code class="hash-code">${data.session.file_hash}</code></td></tr>
            <tr><td><strong>File Size:</strong></td><td>${formatFileSize(data.session.file_size)}</td></tr>
            <tr><td><strong>File Type:</strong></td><td>${data.session.file_type}</td></tr>
            <tr><td><strong>Status:</strong></td><td><span class="status-badge status-${data.session.status}">${data.session.status}</span></td></tr>
            <tr><td><strong>Created:</strong></td><td>${formatDate(data.session.created_at)}</td></tr>
        </table>
    `;

    if (data.session.status === 'analyzing') {
        document.getElementById('statusBadge').textContent = 'Analyzing';
        document.getElementById('statusBadge').className = 'status-badge status-analyzing';
    }
}

function updateBehaviors(behaviors) {
    const container = document.getElementById('behaviorEvents');
    if (!behaviors || behaviors.length === 0) {
        container.innerHTML = '<p class="empty-message">No behavioral events recorded yet...</p>';
        return;
    }

    container.innerHTML = behaviors.map(event => `
        <div class="event-item severity-${event.severity}">
            <div class="event-header">
                <span class="event-type">${event.event_type}</span>
                <span class="severity-badge severity-${event.severity}">${event.severity}</span>
            </div>
            <p class="event-description">${event.description}</p>
            <p class="event-time">${formatDate(event.timestamp)}</p>
        </div>
    `).join('');
}

function updateNetworkEvents(events) {
    const container = document.getElementById('networkEvents');
    if (!events || events.length === 0) {
        container.innerHTML = '<p class="empty-message">No network activity recorded yet...</p>';
        return;
    }

    container.innerHTML = events.map(event => `
        <div class="event-item network-event">
            <div class="event-header">
                <span class="protocol-badge">${event.protocol}</span>
                ${event.domain ? `<span class="domain">${event.domain}</span>` : ''}
                ${event.method ? `<span class="method-badge">${event.method}</span>` : ''}
            </div>
            <div class="network-details">
                <p><strong>Source:</strong> ${event.source_ip}</p>
                <p><strong>Destination:</strong> ${event.destination_ip}:${event.destination_port || 'N/A'}</p>
                ${event.url ? `<p><strong>URL:</strong> <code>${event.url}</code></p>` : ''}
                ${event.response_code ? `<p><strong>Response:</strong> ${event.response_code}</p>` : ''}
            </div>
            <p class="event-time">${formatDate(event.timestamp)}</p>
        </div>
    `).join('');
}

function updateProcesses(processes) {
    const container = document.getElementById('processTree');
    if (!processes || processes.length === 0) {
        container.innerHTML = '<p class="empty-message">No processes recorded yet...</p>';
        return;
    }

    // Build process tree
    const processMap = new Map();
    processes.forEach(p => processMap.set(p.pid, p));

    const rootProcesses = processes.filter(p => !p.parent_pid || !processMap.has(p.parent_pid));

    function renderProcessTree(proc, level = 0) {
        const children = processes.filter(p => p.parent_pid === proc.pid);
        const statusClass = proc.status === 'running' ? 'process-running' : 'process-terminated';

        return `
            <div class="process-node" style="margin-left: ${level * 30}px">
                <div class="process-item ${statusClass}">
                    <div class="process-header">
                        <strong>${proc.process_name}</strong>
                        <span class="pid-badge">PID: ${proc.pid}</span>
                        <span class="status-badge status-small status-${proc.status}">${proc.status}</span>
                    </div>
                    <div class="process-details">
                        ${proc.command_line ? `<p><code>${proc.command_line}</code></p>` : ''}
                        <p><span class="label">User:</span> ${proc.user} | <span class="label">Integrity:</span> ${proc.integrity_level}</p>
                    </div>
                    <p class="event-time">${formatDate(proc.timestamp)}</p>
                </div>
                ${children.map(child => renderProcessTree(child, level + 1)).join('')}
            </div>
        `;
    }

    container.innerHTML = rootProcesses.map(proc => renderProcessTree(proc)).join('');
}

function updateDroppedFiles(files) {
    const container = document.getElementById('droppedFiles');
    if (!files || files.length === 0) {
        container.innerHTML = '<p class="empty-message">No dropped files detected...</p>';
        return;
    }

    container.innerHTML = files.map(file => `
        <div class="dropped-file-item ${file.is_malicious ? 'file-malicious' : ''}">
            <div class="file-icon">${file.is_malicious ? '⚠️' : '📄'}</div>
            <div class="file-info-detailed">
                <h4>${file.file_name}</h4>
                <p class="file-path">${file.file_path}</p>
                <div class="file-meta">
                    <span>Size: ${formatFileSize(file.file_size)}</span>
                    <span>Type: ${file.file_type}</span>
                    ${file.is_malicious ? '<span class="malicious-badge">MALICIOUS</span>' : ''}
                </div>
                ${file.file_hash ? `<p><code class="hash-code">${file.file_hash}</code></p>` : ''}
                <p class="event-time">${formatDate(file.timestamp)}</p>
            </div>
        </div>
    `).join('');
}

let allIOCs = [];

function updateIOCs(iocs) {
    allIOCs = iocs || [];
    const container = document.getElementById('iocsList');

    if (allIOCs.length === 0) {
        container.innerHTML = '<p class="empty-message">No IOCs extracted...</p>';
        return;
    }

    renderIOCs();
}

function renderIOCs() {
    const container = document.getElementById('iocsList');
    const filtered = currentFilter === 'all' ? allIOCs : allIOCs.filter(i => i.ioc_type === currentFilter);

    if (filtered.length === 0) {
        container.innerHTML = `<p class="empty-message">No ${currentFilter} IOCs found...</p>`;
        return;
    }

    const grouped = {};
    filtered.forEach(ioc => {
        if (!grouped[ioc.ioc_type]) grouped[ioc.ioc_type] = [];
        grouped[ioc.ioc_type].push(ioc);
    });

    container.innerHTML = Object.entries(grouped).map(([type, iocs]) => `
        <div class="ioc-group">
            <h4 class="ioc-type-header">${type.toUpperCase()} (${iocs.length})</h4>
            ${iocs.map(ioc => `
                <div class="ioc-item confidence-${ioc.confidence}">
                    <div class="ioc-value"><code>${ioc.value}</code></div>
                    <div class="ioc-meta">
                        <span class="confidence-badge confidence-${ioc.confidence}">${ioc.confidence}</span>
                        <span class="source-badge">${ioc.source}</span>
                    </div>
                    ${ioc.description ? `<p class="ioc-desc">${ioc.description}</p>` : ''}
                </div>
            `).join('')}
        </div>
    `).join('');
}

function updateMitre(attacks) {
    const container = document.getElementById('mitreList');
    if (!attacks || attacks.length === 0) {
        container.innerHTML = '<p class="empty-message">No MITRE ATT&CK techniques detected...</p>';
        return;
    }

    // Group by tactic
    const grouped = {};
    attacks.forEach(attack => {
        if (!grouped[attack.tactic]) grouped[attack.tactic] = [];
        grouped[attack.tactic].push(attack);
    });

    container.innerHTML = Object.entries(grouped).map(([tactic, techniques]) => `
        <div class="mitre-tactic-group">
            <h4 class="mitre-tactic">${tactic}</h4>
            ${techniques.map(tech => `
                <div class="mitre-item">
                    <div class="mitre-header">
                        <strong>${tech.technique_id}: ${tech.technique_name}</strong>
                    </div>
                    <p>${tech.description}</p>
                    ${tech.evidence ? `<div class="evidence-box"><strong>Evidence:</strong> ${tech.evidence}</div>` : ''}
                </div>
            `).join('')}
        </div>
    `).join('');
}

let allStrings = [];

function updateStrings(strings) {
    allStrings = strings || [];
    renderStrings();
}

function renderStrings() {
    const container = document.getElementById('stringsList');

    let filtered = allStrings;
    if (currentFilter !== 'all') {
        if (currentFilter === 'suspicious') {
            filtered = allStrings.filter(s => s.is_suspicious);
        } else {
            filtered = allStrings.filter(s => s.string_type === currentFilter);
        }
    }

    if (filtered.length === 0) {
        container.innerHTML = '<p class="empty-message">No strings found...</p>';
        return;
    }

    container.innerHTML = `
        <div class="strings-list">
            ${filtered.slice(0, 100).map(str => `
                <div class="string-item ${str.is_suspicious ? 'string-suspicious' : ''}">
                    <span class="string-type-badge">${str.string_type}</span>
                    <code class="string-value">${escapeHtml(str.value)}</code>
                    <span class="offset">@${str.offset}</span>
                </div>
            `).join('')}
        </div>
        ${filtered.length > 100 ? `<p class="more-indicator">Showing 100 of ${filtered.length} strings...</p>` : ''}
    `;
}

function updateMutexes(mutexes) {
    const container = document.getElementById('mutexesList');
    if (!mutexes || mutexes.length === 0) {
        container.innerHTML = '<p class="empty-message">No mutexes or handles detected...</p>';
        return;
    }

    container.innerHTML = mutexes.map(mutex => `
        <div class="mutex-item">
            <div class="mutex-header">
                <span class="handle-type-badge">${mutex.handle_type}</span>
                <span class="pid-badge">PID: ${mutex.pid}</span>
            </div>
            <p><strong>Name:</strong> <code>${mutex.name}</code></p>
            <p><strong>Access:</strong> ${mutex.access_rights}</p>
            <p class="event-time">${formatDate(mutex.timestamp)}</p>
        </div>
    `).join('');
}

function updateMemory(regions) {
    const container = document.getElementById('memoryList');
    if (!regions || regions.length === 0) {
        container.innerHTML = '<p class="empty-message">No memory regions recorded...</p>';
        return;
    }

    container.innerHTML = regions.map(region => `
        <div class="memory-item ${region.is_suspicious ? 'memory-suspicious' : ''}">
            <div class="memory-header">
                <strong>${region.base_address}</strong>
                <span class="protection-badge protection-${region.protection}">${region.protection}</span>
                ${region.is_suspicious ? '<span class="suspicious-badge">SUSPICIOUS</span>' : ''}
            </div>
            <div class="memory-details">
                <p>Size: ${formatFileSize(region.size)} | Type: ${region.region_type} | PID: ${region.pid}</p>
            </div>
            <p class="event-time">${formatDate(region.timestamp)}</p>
        </div>
    `).join('');
}

function updateScreenshots(screenshots) {
    const container = document.getElementById('screenshotsList');
    if (!screenshots || screenshots.length === 0) {
        container.innerHTML = '<p class="empty-message">No screenshots captured...</p>';
        return;
    }

    container.innerHTML = screenshots.map(screenshot => `
        <div class="screenshot-card">
            <img src="/api/session/${sessionId}/screenshot/${screenshot.filename}"
                 alt="${screenshot.description}"
                 class="screenshot-img"
                 onclick="viewScreenshotLarge(this.src)">
            <div class="screenshot-info">
                <p><strong>${screenshot.description}</strong></p>
                <p class="event-time">${formatDate(screenshot.timestamp)}</p>
            </div>
        </div>
    `).join('');
}

function updateYara(matches) {
    const container = document.getElementById('yaraList');
    if (!matches || matches.length === 0) {
        container.innerHTML = '<p class="empty-message">No YARA rules matched...</p>';
        return;
    }

    container.innerHTML = matches.map(match => `
        <div class="yara-match severity-${match.severity}">
            <div class="yara-header">
                <strong>${match.rule_name}</strong>
                <div>
                    <span class="category-badge">${match.category}</span>
                    <span class="severity-badge severity-${match.severity}">${match.severity}</span>
                </div>
            </div>
            <p>${match.description}</p>
            ${match.matched_strings && match.matched_strings.length > 0 ? `
                <div class="matched-strings">
                    <strong>Matched Strings:</strong>
                    ${match.matched_strings.map(s => `<code>@${s.offset}: ${s.string}</code>`).join(', ')}
                </div>
            ` : ''}
        </div>
    `).join('');
}

function updateCertificates(certs) {
    const container = document.getElementById('certificatesList');
    if (!certs || certs.length === 0) {
        container.innerHTML = '<p class="empty-message">No certificates found...</p>';
        return;
    }

    container.innerHTML = certs.map(cert => `
        <div class="certificate-item ${cert.is_valid ? 'cert-valid' : 'cert-invalid'}">
            <div class="cert-header">
                <h4>Code Signing Certificate</h4>
                <div>
                    ${cert.is_valid ? '<span class="valid-badge">✓ Valid</span>' : '<span class="invalid-badge">✗ Invalid</span>'}
                    ${cert.is_trusted ? '<span class="trusted-badge">Trusted</span>' : '<span class="untrusted-badge">Untrusted</span>'}
                </div>
            </div>
            <table class="cert-table">
                <tr><td><strong>Subject:</strong></td><td>${cert.subject}</td></tr>
                <tr><td><strong>Issuer:</strong></td><td>${cert.issuer}</td></tr>
                <tr><td><strong>Serial:</strong></td><td><code>${cert.serial_number}</code></td></tr>
                <tr><td><strong>Valid From:</strong></td><td>${formatDate(cert.valid_from)}</td></tr>
                <tr><td><strong>Valid To:</strong></td><td>${formatDate(cert.valid_to)}</td></tr>
                <tr><td><strong>Thumbprint:</strong></td><td><code class="hash-code">${cert.thumbprint}</code></td></tr>
            </table>
        </div>
    `).join('');
}

async function loadTimeline() {
    try {
        const response = await fetch(`/api/session/${sessionId}/timeline`);
        const timeline = await response.json();

        const container = document.getElementById('timelineView');
        if (!timeline || timeline.length === 0) {
            container.innerHTML = '<p class="empty-message">No timeline events...</p>';
            return;
        }

        container.innerHTML = timeline.map((event, index) => `
            <div class="timeline-event">
                <div class="timeline-marker type-${event.type}"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <span class="timeline-type">${event.type}</span>
                        <span class="timeline-time">${formatDate(event.timestamp)}</span>
                    </div>
                    <p class="timeline-desc">${event.description}</p>
                    <span class="severity-badge severity-${event.severity}">${event.severity}</span>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading timeline:', error);
    }
}

function updateThreatScore(score) {
    const card = document.getElementById('threatScoreCard');
    const fill = document.getElementById('threatFill');
    const label = document.getElementById('threatLabel');

    card.style.display = 'block';
    fill.style.width = score + '%';

    let threatLevel = 'Low';
    let colorClass = 'threat-low';

    if (score > 70) {
        threatLevel = 'Critical';
        colorClass = 'threat-critical';
    } else if (score > 40) {
        threatLevel = 'High';
        colorClass = 'threat-high';
    } else if (score > 20) {
        threatLevel = 'Medium';
        colorClass = 'threat-medium';
    }

    fill.className = `threat-fill ${colorClass}`;
    label.innerHTML = `<strong>${score}/100</strong> - ${threatLevel} Risk`;
}

function viewScreenshotLarge(src) {
    window.open(src, '_blank');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function applyFilter() {
    // Reapply filter based on current tab
    const activePanel = document.querySelector('.tab-panel.active');
    if (activePanel.id === 'iocs-panel') {
        renderIOCs();
    } else if (activePanel.id === 'strings-panel') {
        renderStrings();
    }
}
