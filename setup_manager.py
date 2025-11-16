"""
Setup Manager for AnyRun Clone
Handles first-time setup, onboarding, and VM template creation
"""

import os
import json
import subprocess
import libvirt
from pathlib import Path


class SetupManager:
    """Manages initial setup and configuration for the analysis environment"""

    CONFIG_FILE = 'config/setup.json'
    IMAGES_DIR = '/var/lib/libvirt/images'
    NETWORK_NAME = 'isolated'

    def __init__(self):
        """Initialize setup manager"""
        self.config_dir = Path('config')
        self.config_dir.mkdir(exist_ok=True)
        self.config = self._load_config()

        try:
            self.conn = libvirt.open('qemu:///system')
        except libvirt.libvirtError:
            self.conn = None

    def _load_config(self):
        """Load configuration from file"""
        config_path = self.config_dir / 'setup.json'
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        return {
            'setup_complete': False,
            'network_configured': False,
            'vm_templates': {}
        }

    def _save_config(self):
        """Save configuration to file"""
        config_path = self.config_dir / 'setup.json'
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def needs_setup(self):
        """Check if initial setup is required"""
        if not self.config.get('setup_complete', False):
            return True

        # Verify network exists
        if not self._check_network_exists():
            return True

        # Check if at least one VM template exists
        if not self.config.get('vm_templates'):
            return True

        return False

    def get_setup_status(self):
        """Get detailed setup status"""
        status = {
            'setup_complete': self.config.get('setup_complete', False),
            'libvirt_connected': self.conn is not None,
            'network_exists': self._check_network_exists(),
            'network_active': self._check_network_active(),
            'vm_templates': self.config.get('vm_templates', {}),
            'images_dir_exists': os.path.exists(self.IMAGES_DIR),
            'images_dir_writable': os.access(self.IMAGES_DIR, os.W_OK) if os.path.exists(self.IMAGES_DIR) else False,
            'kvm_available': self._check_kvm_available(),
            'qemu_installed': self._check_qemu_installed()
        }
        return status

    def _check_kvm_available(self):
        """Check if KVM is available"""
        return os.path.exists('/dev/kvm')

    def _check_qemu_installed(self):
        """Check if QEMU is installed"""
        try:
            result = subprocess.run(['which', 'qemu-system-x86_64'],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

    def _check_network_exists(self):
        """Check if isolated network exists in libvirt"""
        if not self.conn:
            return False

        try:
            self.conn.networkLookupByName(self.NETWORK_NAME)
            return True
        except libvirt.libvirtError:
            return False

    def _check_network_active(self):
        """Check if isolated network is active"""
        if not self.conn:
            return False

        try:
            net = self.conn.networkLookupByName(self.NETWORK_NAME)
            return net.isActive()
        except libvirt.libvirtError:
            return False

    def create_isolated_network(self):
        """Create the isolated network for VM analysis"""
        if not self.conn:
            return {
                'success': False,
                'error': 'No libvirt connection. Is libvirtd running?'
            }

        if self._check_network_exists():
            # Network exists, just make sure it's active
            if not self._check_network_active():
                try:
                    net = self.conn.networkLookupByName(self.NETWORK_NAME)
                    net.create()
                except libvirt.libvirtError as e:
                    return {'success': False, 'error': f'Failed to start network: {e}'}

            self.config['network_configured'] = True
            self._save_config()
            return {'success': True, 'message': 'Network already exists and is active'}

        # Create new network
        network_xml = """
        <network>
          <name>isolated</name>
          <bridge name='virbr-isolated' stp='on' delay='0'/>
          <ip address='192.168.100.1' netmask='255.255.255.0'>
            <dhcp>
              <range start='192.168.100.100' end='192.168.100.200'/>
            </dhcp>
          </ip>
        </network>
        """

        try:
            net = self.conn.networkDefineXML(network_xml)
            if net is None:
                return {'success': False, 'error': 'Failed to define network'}

            # Set autostart
            net.setAutostart(True)

            # Start the network
            net.create()

            self.config['network_configured'] = True
            self._save_config()

            return {
                'success': True,
                'message': 'Isolated network created and started successfully'
            }

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def list_iso_files(self, search_paths=None):
        """Find ISO files on the system"""
        if search_paths is None:
            search_paths = [
                os.path.expanduser('~/'),
                '/home',
                '/var/lib/libvirt/images',
                '/tmp',
                os.path.expanduser('~/Downloads')
            ]

        iso_files = []

        for base_path in search_paths:
            if not os.path.exists(base_path):
                continue

            try:
                # Use find command for efficiency
                result = subprocess.run(
                    ['find', base_path, '-maxdepth', '3', '-name', '*.iso', '-type', 'f', '-size', '+100M'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line and line not in iso_files:
                            try:
                                size = os.path.getsize(line)
                                iso_files.append({
                                    'path': line,
                                    'name': os.path.basename(line),
                                    'size': size,
                                    'size_human': self._format_size(size)
                                })
                            except OSError:
                                pass
            except (subprocess.TimeoutExpired, Exception):
                continue

        return iso_files

    def _format_size(self, size_bytes):
        """Format file size to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def create_vm_template(self, iso_path, os_type, vm_name=None, memory=4096, vcpus=2, disk_size=40):
        """Create a VM template from an ISO file"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        if not os.path.exists(iso_path):
            return {'success': False, 'error': f'ISO file not found: {iso_path}'}

        # Generate VM name
        if not vm_name:
            vm_name = f'anyrun-{os_type}'

        # Create disk image path
        disk_path = os.path.join(self.IMAGES_DIR, f'{os_type}-analysis.qcow2')

        # Check if disk already exists
        if os.path.exists(disk_path):
            return {
                'success': False,
                'error': f'Disk image already exists: {disk_path}',
                'disk_path': disk_path
            }

        # Create the QCOW2 disk image
        try:
            result = subprocess.run(
                ['qemu-img', 'create', '-f', 'qcow2', disk_path, f'{disk_size}G'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                return {
                    'success': False,
                    'error': f'Failed to create disk image: {result.stderr}'
                }
        except Exception as e:
            return {'success': False, 'error': f'Error creating disk: {e}'}

        # Determine VNC port based on OS type
        vnc_ports = {
            'windows10': 5900,
            'windows11': 5900,
            'windows7': 5901,
            'ubuntu': 5902,
            'debian': 5903,
            'linux': 5902
        }
        vnc_port = vnc_ports.get(os_type, 5900)

        # Generate VM XML for installation
        vm_xml = f"""
        <domain type='kvm'>
          <name>{vm_name}</name>
          <memory unit='MiB'>{memory}</memory>
          <vcpu placement='static'>{vcpus}</vcpu>
          <os>
            <type arch='x86_64' machine='pc-q35-6.2'>hvm</type>
            <boot dev='cdrom'/>
            <boot dev='hd'/>
          </os>
          <features>
            <acpi/>
            <apic/>
            <vmport state='off'/>
          </features>
          <cpu mode='host-passthrough'/>
          <clock offset='localtime'>
            <timer name='rtc' tickpolicy='catchup'/>
            <timer name='pit' tickpolicy='delay'/>
            <timer name='hpet' present='no'/>
          </clock>
          <on_poweroff>destroy</on_poweroff>
          <on_reboot>restart</on_reboot>
          <on_crash>destroy</on_crash>
          <devices>
            <emulator>/usr/bin/qemu-system-x86_64</emulator>
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2' cache='writeback'/>
              <source file='{disk_path}'/>
              <target dev='vda' bus='virtio'/>
            </disk>
            <disk type='file' device='cdrom'>
              <driver name='qemu' type='raw'/>
              <source file='{iso_path}'/>
              <target dev='sda' bus='sata'/>
              <readonly/>
            </disk>
            <interface type='network'>
              <source network='{self.NETWORK_NAME}'/>
              <model type='virtio'/>
            </interface>
            <graphics type='vnc' port='{vnc_port}' autoport='no' listen='0.0.0.0'>
              <listen type='address' address='0.0.0.0'/>
            </graphics>
            <video>
              <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1'/>
            </video>
            <channel type='unix'>
              <target type='virtio' name='org.qemu.guest_agent.0'/>
            </channel>
            <input type='tablet' bus='usb'/>
            <serial type='pty'>
              <target port='0'/>
            </serial>
            <console type='pty'>
              <target type='serial' port='0'/>
            </console>
          </devices>
        </domain>
        """

        try:
            # Define the VM
            dom = self.conn.defineXML(vm_xml)
            if dom is None:
                return {'success': False, 'error': 'Failed to define VM'}

            # Save template info
            self.config['vm_templates'][os_type] = {
                'name': vm_name,
                'disk_path': disk_path,
                'disk_size': disk_size,
                'iso_path': iso_path,
                'memory': memory,
                'vcpus': vcpus,
                'vnc_port': vnc_port,
                'network': self.NETWORK_NAME,
                'status': 'created',
                'needs_installation': True
            }
            self._save_config()

            return {
                'success': True,
                'vm_name': vm_name,
                'disk_path': disk_path,
                'disk_size': disk_size,
                'vnc_port': vnc_port,
                'message': f'VM template created successfully!\n\nDisk Image: {disk_path} ({disk_size} GB)\nMemory: {memory} MB\nVNC Port: {vnc_port}\n\nStart the VM to begin OS installation via VNC.'
            }

        except libvirt.libvirtError as e:
            # Cleanup disk if VM creation failed
            if os.path.exists(disk_path):
                os.remove(disk_path)
            return {'success': False, 'error': str(e)}

    def start_vm_for_installation(self, os_type):
        """Start a VM to perform OS installation"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        template = self.config.get('vm_templates', {}).get(os_type)
        if not template:
            return {'success': False, 'error': f'No template found for {os_type}'}

        try:
            dom = self.conn.lookupByName(template['name'])

            if dom.isActive():
                return {
                    'success': True,
                    'message': 'VM is already running',
                    'vnc_port': template['vnc_port']
                }

            if dom.create() < 0:
                return {'success': False, 'error': 'Failed to start VM'}

            return {
                'success': True,
                'message': f'VM started. Connect via VNC to localhost:{template["vnc_port"]} to complete installation',
                'vnc_port': template['vnc_port'],
                'vm_name': template['name']
            }

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def stop_vm(self, os_type):
        """Stop a running VM"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        template = self.config.get('vm_templates', {}).get(os_type)
        if not template:
            return {'success': False, 'error': f'No template found for {os_type}'}

        try:
            dom = self.conn.lookupByName(template['name'])

            if not dom.isActive():
                return {'success': True, 'message': 'VM is already stopped'}

            dom.destroy()
            return {'success': True, 'message': 'VM stopped'}

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def mark_installation_complete(self, os_type):
        """Mark VM template as installation complete and create snapshot"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        template = self.config.get('vm_templates', {}).get(os_type)
        if not template:
            return {'success': False, 'error': f'No template found for {os_type}'}

        try:
            dom = self.conn.lookupByName(template['name'])

            # Create clean-state snapshot
            snapshot_xml = """
            <domainsnapshot>
              <name>clean-state</name>
              <description>Clean installation state for analysis</description>
            </domainsnapshot>
            """

            dom.snapshotCreateXML(snapshot_xml)

            # Update config
            self.config['vm_templates'][os_type]['needs_installation'] = False
            self.config['vm_templates'][os_type]['status'] = 'ready'
            self.config['vm_templates'][os_type]['snapshot'] = 'clean-state'

            # Check if setup is complete (at least one ready template)
            ready_templates = [t for t in self.config['vm_templates'].values()
                              if t.get('status') == 'ready']
            if ready_templates and self.config.get('network_configured'):
                self.config['setup_complete'] = True

            self._save_config()

            return {
                'success': True,
                'message': f'Installation complete. Snapshot "clean-state" created for {os_type}'
            }

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def remove_iso_from_vm(self, os_type):
        """Remove ISO from VM after installation"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        template = self.config.get('vm_templates', {}).get(os_type)
        if not template:
            return {'success': False, 'error': f'No template found for {os_type}'}

        try:
            dom = self.conn.lookupByName(template['name'])

            # Get current XML
            xml = dom.XMLDesc()

            # Update the boot order to only boot from HD
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)

            # Find and update boot order
            os_elem = root.find('os')
            if os_elem is not None:
                # Remove all boot elements
                for boot in os_elem.findall('boot'):
                    os_elem.remove(boot)
                # Add only HDD boot
                boot_elem = ET.SubElement(os_elem, 'boot')
                boot_elem.set('dev', 'hd')

            # Re-define VM with updated XML
            new_xml = ET.tostring(root, encoding='unicode')
            self.conn.defineXML(new_xml)

            return {'success': True, 'message': 'Boot order updated to HDD only'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_vm_console_url(self, os_type):
        """Get VNC connection URL for a VM"""
        template = self.config.get('vm_templates', {}).get(os_type)
        if not template:
            return None

        return {
            'vnc_port': template.get('vnc_port', 5900),
            'url': f'vnc://localhost:{template.get("vnc_port", 5900)}'
        }

    def cleanup(self):
        """Close libvirt connection"""
        if self.conn:
            self.conn.close()
