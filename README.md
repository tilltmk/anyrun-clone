# AnyRun Clone - Advanced Interactive Malware Analysis Sandbox

Ein vollständiger, erweiterbarer Clone von AnyRun, entwickelt mit Python Flask. Dieses Projekt bietet eine umfassende Malware-Analyse-Plattform mit interaktiver Sandbox-Simulation und detaillierter Verhaltensanalyse.

## 🎯 Hauptmerkmale

### Core Features
- ✅ **File Upload & Analysis** - Multi-Format-Support (EXE, DLL, PDF, DOCX, ZIP, BAT, PS1, PY, JAR, APK, etc.)
- ✅ **Process Tree Visualization** - Vollständige Prozesshierarchie
- ✅ **Network Traffic Analysis** - DNS, HTTP/HTTPS, TCP/UDP Monitoring
- ✅ **IOC Extraction** - Automatische Indicators of Compromise
- ✅ **MITRE ATT&CK Mapping** - Framework-Integration
- ✅ **YARA Rule Scanning** - Malware-Pattern-Detection
- ✅ **String Analysis** - ASCII/Unicode Extraction & Classification
- ✅ **Memory Analysis** - Memory Region & Protection Tracking
- ✅ **Screenshot Capture** - Visual Sandbox Monitoring
- ✅ **Timeline View** - Chronological Event Analysis
- ✅ **Certificate Analysis** - Code Signing Validation
- ✅ **Dropped Files Tracking** - File System Monitoring
- ✅ **Mutex & Handle Detection** - Synchronization Analysis
- ✅ **Threat Scoring** - Automated Risk Assessment (0-100)
- ✅ **Report Export** - JSON & HTML Reports

### Advanced Analysis
- 🔍 **Behavioral Analysis**: API calls, Registry modifications, File operations
- 🌐 **Network Monitoring**: Full packet inspection, Payload analysis
- 📊 **Real-time Dashboard**: Live updates während der Analyse
- 🎯 **14 Analysis Tabs**: Umfassende Datenvisualisierung
- 🔐 **Security Features**: File validation, Size limits, Input sanitization

## 📊 Analyse-Kategorien

### 1. Overview
Zusammenfassung aller Analyse-Ergebnisse mit Threat Score

### 2. Behavioral Events
- File System Operations
- Registry Modifications
- API Call Detection
- Memory Operations

### 3. Network Activity
- DNS Queries
- HTTP/HTTPS Requests
- TCP/UDP Connections
- Payload Inspection

### 4. Process Tree
- Parent-Child Relationships
- Command Line Arguments
- Integrity Levels
- Exit Codes

### 5. Dropped Files
- Created Files
- Modified Files
- Malicious File Detection
- Hash Calculation

### 6. IOCs (Indicators of Compromise)
- IP Addresses
- Domains
- URLs
- Email Addresses
- Hashes

### 7. MITRE ATT&CK
- Technique Mapping
- Tactic Classification
- Evidence Tracking

### 8. String Analysis
- URL Extraction
- IP Detection
- Email Addresses
- File Paths
- Suspicious Strings

### 9. Mutexes & Handles
- Mutex Names
- Handle Types
- Access Rights

### 10. Memory Regions
- Base Addresses
- Protection Flags
- Suspicious Regions

### 11. Screenshots
- Time-stamped Captures
- Visual Analysis

### 12. YARA Matches
- Rule Name
- Category
- Severity
- Matched Strings

### 13. Timeline
- Chronological Events
- Multi-source Integration

### 14. Certificates
- Code Signing Info
- Validity Check
- Trust Chain

## 🚀 Quick Start

```bash
# Dependencies installieren
pip install -r requirements.txt

# Anwendung starten
python app.py
```

Die Anwendung läuft auf `http://localhost:5000`

## 📚 API Endpoints

```http
POST   /upload                                    # File upload
GET    /session/<id>                              # Session view
GET    /api/session/<id>                          # Full session data
GET    /api/session/<id>/processes                # Process tree
GET    /api/session/<id>/network                  # Network events
GET    /api/session/<id>/dropped-files            # Dropped files
GET    /api/session/<id>/iocs                     # IOCs
GET    /api/session/<id>/mitre                    # MITRE ATT&CK
GET    /api/session/<id>/strings                  # Strings
GET    /api/session/<id>/mutexes                  # Mutexes
GET    /api/session/<id>/memory                   # Memory regions
GET    /api/session/<id>/screenshots              # Screenshots
GET    /api/session/<id>/yara                     # YARA matches
GET    /api/session/<id>/certificates             # Certificates
GET    /api/session/<id>/timeline                 # Timeline
GET    /api/session/<id>/export/json              # JSON export
GET    /api/session/<id>/export/html              # HTML export
GET    /session/<id>/report                       # Full report view
```

## 🎯 Threat Scoring Algorithm

```
Score = Behaviors (max 60) + Network (max 20) + YARA (max 12) + MITRE (max 8)

Behavioral Events:
- Critical: +20 points
- High: +12 points
- Medium: +5 points
- Low: +1 point

Network Activity: +2 points per event
YARA Matches: +5-15 points based on severity
MITRE Techniques: +8 points per technique

Maximum Score: 100
```

## 🛡️ Security Notice

**⚠️ WICHTIG**: Dies ist ein Bildungsprojekt mit simulierten Analysen.

Für produktive Malware-Analyse:
1. Verwende echte VM/Container-Isolation
2. Implementiere Netzwerk-Segmentierung
3. Keine Ausführung auf produktiven Systemen
4. Befolge Sicherheitsrichtlinien

## 📁 Project Structure

```
anyrun-clone/
├── app.py                      # Flask application
├── models.py                   # Database models
├── advanced_analyzer.py        # Analysis engine
├── analyzer.py                 # Legacy analyzer
├── config.py                   # Configuration
├── requirements.txt            # Dependencies
├── templates/                  # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── session_advanced.html
│   ├── sessions.html
│   ├── dashboard.html
│   └── report.html
├── static/
│   ├── css/style.css          # Styles
│   └── js/
│       ├── main.js
│       └── advanced_session.js
├── uploads/                    # Uploaded files
└── results/                    # Analysis results
```

## 🔧 Configuration

Anpassung in `config.py`:

```python
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
ANALYSIS_TIMEOUT = 300                   # 5 minutes
MAX_STRINGS_PER_FILE = 1000
ENABLE_YARA_SCANNING = True
```

## 🌟 Features vs. AnyRun

| Feature | AnyRun Clone | AnyRun.com |
|---------|-------------|------------|
| File Upload | ✅ | ✅ |
| Process Tree | ✅ | ✅ |
| Network Analysis | ✅ (Simulated) | ✅ (Real) |
| IOC Extraction | ✅ | ✅ |
| MITRE ATT&CK | ✅ | ✅ |
| YARA Scanning | ✅ | ✅ |
| Screenshots | ✅ (Simulated) | ✅ (Real VM) |
| Timeline | ✅ | ✅ |
| Report Export | ✅ (JSON/HTML) | ✅ (PDF) |
| Interactive VM | ❌ (Simulated) | ✅ (Real) |
| Video Recording | ❌ | ✅ |
| Live Interaction | ❌ | ✅ |

## 📝 License

Educational purposes only. Use responsibly.

## 👨‍💻 Tech Stack

- **Backend**: Python 3, Flask, SQLAlchemy
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Analysis**: Custom Python Engine

## 🙏 Credits

Inspired by [any.run](https://any.run)

---

**Version**: 2.0.0 Extended Edition
**Disclaimer**: Nur für Bildungs- und Forschungszwecke. Verantwortungsvoller Gebrauch in autorisierten Umgebungen.
