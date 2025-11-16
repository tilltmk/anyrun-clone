# AnyRun Clone v4.0 - REAL Analysis Edition

## WICHTIG: KEINE FAKE-DATEN MEHR

Diese Version wurde komplett überarbeitet, um **echte Malware-Analyse** durchzuführen.
Alle vorherigen Fake-/Mock-Daten wurden entfernt.

## Was wurde geändert?

### Entfernte Fake-Daten:
- ❌ Hardcoded malicious domains (malicious-server.com, evil-cdn.net, etc.)
- ❌ Fake Prozessnamen mit random.choice()
- ❌ Generierte YARA-Matches mit random.randint()
- ❌ Fake Netzwerk-Events (192.168.1.100, 8.8.8.8)
- ❌ Simulierte Screenshots
- ❌ Zufällige MITRE ATT&CK Mappings
- ❌ Fake Mutex-Namen
- ❌ Generierte Zertifikate

### Neue echte Analyse-Funktionen:

1. **Echte String-Extraktion**
   - ASCII und Unicode Strings aus der Datei
   - Automatische Klassifizierung (URL, IP, Email, Pfad, Hash)
   - Erkennung verdächtiger Indikatoren

2. **Echtes YARA-Scanning**
   - Verwendet yara-python für echte Regel-Matches
   - Eigene YARA-Regeln in `/yara_rules/`
   - Erkennt: Ransomware, Keylogger, Shellcode, Anti-VM, etc.

3. **Echte PE-Datei-Analyse**
   - Verwendet pefile für Windows Executables
   - Extrahiert echte Zertifikatsinformationen
   - Analysiert Imports/Exports

4. **Echte IOC-Extraktion**
   - Aus tatsächlich gefundenen Strings
   - Keine erfundenen Domains oder IPs

5. **Echte KVM/QEMU VM-Integration**
   - Dynamische Analyse in isolierten VMs
   - VNC WebSocket Proxy für Live-Stream
   - Echte Screenshot-Capture

## Analyse-Typen

### Statische Analyse (Standard)
- Analysiert die Datei ohne Ausführung
- String-Extraktion
- YARA-Scanning
- PE-Datei-Analyse
- IOC-Extraktion

### Dynamische Analyse (mit VM)
- Führt Datei in isolierter KVM-VM aus
- Echte Verhaltensüberwachung
- Netzwerk-Traffic-Capture
- Echte Screenshots vom VM-Desktop
- Live VNC-Stream

## Installation

```bash
# Installiere echte Analyse-Tools
pip install yara-python pefile websockets

# Für KVM-VM-Support (optional)
sudo apt install libvirt-dev
pip install libvirt-python
```

## Dateien

- `real_analyzer.py` - Neuer echter Analyzer (KEINE Fake-Daten)
- `vnc_proxy.py` - VNC WebSocket Proxy für KVM-Stream
- `yara_rules/` - Echte YARA-Regeln
- `advanced_analyzer_FAKE_REMOVED.py.bak` - Alter Fake-Analyzer (Backup)
- `analyzer_FAKE_REMOVED.py.bak` - Alter Fake-Analyzer (Backup)

## Interface

Das Interface wurde im any.run-Stil vereinheitlicht:
- Live-Session-Ansicht mit KVM-Stream-Viewer
- Echtzeit-Updates via WebSocket
- Threat-Score basierend auf ECHTEN Findings
- Übersichtliche Tabs für alle Analyse-Ergebnisse

## Hinweis

Die dynamische Analyse erfordert:
1. KVM/QEMU installiert
2. Virtuelle Maschinen konfiguriert
3. libvirt-python installiert

Ohne diese Voraussetzungen funktioniert nur die statische Analyse, die aber ebenfalls echte Daten liefert (String-Extraktion, YARA-Scanning, etc.).

---

**Version 4.0 - REAL Analysis Edition**
Keine Fake-Daten. Nur echte Analyse.
