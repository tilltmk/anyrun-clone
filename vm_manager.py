"""
VM Manager for KVM/QEMU Virtual Machine Control
Handles VM lifecycle, snapshots, and monitoring
"""

import libvirt
import subprocess
import os
import json
import time
import threading
from datetime import datetime
import xml.etree.ElementTree as ET


class VMManager:
    """Manages KVM virtual machines for malware analysis"""

    def __init__(self, qemu_uri='qemu:///system'):
        """Initialize VM manager with libvirt connection"""
        try:
            self.conn = libvirt.open(qemu_uri)
            if self.conn is None:
                raise Exception('Failed to open connection to qemu:///system')
        except libvirt.libvirtError as e:
            print(f"Libvirt connection error: {e}")
            self.conn = None

        # Load VM configs from setup configuration
        self.vm_configs = self._load_vm_configs()

    def _load_vm_configs(self):
        """Load VM configurations from setup config file"""
        config_file = 'config/setup.json'

        # Default configurations (fallback)
        default_configs = {
            'windows10': {
                'name': 'anyrun-windows10',
                'memory': 4096,  # 4GB
                'vcpus': 2,
                'disk_path': '/var/lib/libvirt/images/windows10-analysis.qcow2',
                'snapshot': 'clean-state',
                'vnc_port': 5900,
                'network': 'isolated'
            },
            'windows7': {
                'name': 'anyrun-windows7',
                'memory': 2048,
                'vcpus': 2,
                'disk_path': '/var/lib/libvirt/images/windows7-analysis.qcow2',
                'snapshot': 'clean-state',
                'vnc_port': 5901,
                'network': 'isolated'
            },
            'ubuntu': {
                'name': 'anyrun-ubuntu',
                'memory': 2048,
                'vcpus': 2,
                'disk_path': '/var/lib/libvirt/images/ubuntu-analysis.qcow2',
                'snapshot': 'clean-state',
                'vnc_port': 5902,
                'network': 'isolated'
            }
        }

        # Try to load from setup config
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    setup_config = json.load(f)

                # Merge with templates from setup
                vm_templates = setup_config.get('vm_templates', {})
                for os_type, template in vm_templates.items():
                    if template.get('status') == 'ready':
                        default_configs[os_type] = {
                            'name': template.get('name', f'anyrun-{os_type}'),
                            'memory': template.get('memory', 4096),
                            'vcpus': 2,
                            'disk_path': template.get('disk_path'),
                            'snapshot': template.get('snapshot', 'clean-state'),
                            'vnc_port': template.get('vnc_port', 5900),
                            'network': template.get('network', 'isolated')
                        }
            except Exception as e:
                print(f"Warning: Could not load VM config from setup: {e}")

        return default_configs

    def reload_configs(self):
        """Reload VM configurations from setup config"""
        self.vm_configs = self._load_vm_configs()

    def create_vm(self, os_type='windows10', session_id=None):
        """Create and configure a new VM instance"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        config = self.vm_configs.get(os_type)
        if not config:
            return {'success': False, 'error': f'Unknown OS type: {os_type}'}

        vm_name = f"{config['name']}-{session_id}" if session_id else config['name']

        # Generate VM XML configuration
        xml_config = self._generate_vm_xml(vm_name, config)

        try:
            # Define and create the VM
            dom = self.conn.defineXML(xml_config)
            if dom is None:
                return {'success': False, 'error': 'Failed to define VM'}

            # Start the VM
            if dom.create() < 0:
                return {'success': False, 'error': 'Failed to start VM'}

            return {
                'success': True,
                'vm_name': vm_name,
                'vm_id': dom.ID(),
                'vnc_port': config['vnc_port'],
                'vnc_password': self._generate_vnc_password()
            }

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def _generate_vm_xml(self, vm_name, config):
        """Generate libvirt XML configuration for VM"""
        xml = f"""
        <domain type='kvm'>
          <name>{vm_name}</name>
          <memory unit='MiB'>{config['memory']}</memory>
          <vcpu placement='static'>{config['vcpus']}</vcpu>
          <os>
            <type arch='x86_64' machine='pc-i440fx-2.9'>hvm</type>
            <boot dev='hd'/>
          </os>
          <features>
            <acpi/>
            <apic/>
            <vmport state='off'/>
          </features>
          <cpu mode='host-model'/>
          <clock offset='localtime'>
            <timer name='rtc' tickpolicy='catchup'/>
            <timer name='pit' tickpolicy='delay'/>
            <timer name='hpet' present='no'/>
          </clock>
          <on_poweroff>destroy</on_poweroff>
          <on_reboot>restart</on_reboot>
          <on_crash>destroy</on_crash>
          <pm>
            <suspend-to-mem enabled='no'/>
            <suspend-to-disk enabled='no'/>
          </pm>
          <devices>
            <emulator>/usr/bin/qemu-system-x86_64</emulator>
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source file='{config['disk_path']}'/>
              <target dev='vda' bus='virtio'/>
            </disk>
            <interface type='network'>
              <source network='{config['network']}'/>
              <model type='virtio'/>
            </interface>
            <graphics type='vnc' port='{config['vnc_port']}' autoport='no' listen='0.0.0.0'>
              <listen type='address' address='0.0.0.0'/>
            </graphics>
            <video>
              <model type='vga' vram='16384' heads='1'/>
            </video>
            <serial type='pty'>
              <target port='0'/>
            </serial>
            <console type='pty'>
              <target type='serial' port='0'/>
            </console>
          </devices>
        </domain>
        """
        return xml

    def stop_vm(self, vm_name):
        """Stop and destroy a VM"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        try:
            dom = self.conn.lookupByName(vm_name)
            if dom.isActive():
                dom.destroy()
            dom.undefine()
            return {'success': True}
        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def create_snapshot(self, vm_name, snapshot_name='clean-state'):
        """Create a snapshot of the VM"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        try:
            dom = self.conn.lookupByName(vm_name)

            snapshot_xml = f"""
            <domainsnapshot>
              <name>{snapshot_name}</name>
              <description>Clean state for analysis</description>
            </domainsnapshot>
            """

            dom.snapshotCreateXML(snapshot_xml)
            return {'success': True, 'snapshot': snapshot_name}
        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def restore_snapshot(self, vm_name, snapshot_name='clean-state'):
        """Restore VM to a snapshot"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        try:
            dom = self.conn.lookupByName(vm_name)
            snap = dom.snapshotLookupByName(snapshot_name)
            dom.revertToSnapshot(snap)
            return {'success': True}
        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def get_vm_status(self, vm_name):
        """Get current status of VM"""
        if not self.conn:
            return {'status': 'disconnected'}

        try:
            dom = self.conn.lookupByName(vm_name)
            state, reason = dom.state()

            state_map = {
                libvirt.VIR_DOMAIN_RUNNING: 'running',
                libvirt.VIR_DOMAIN_BLOCKED: 'blocked',
                libvirt.VIR_DOMAIN_PAUSED: 'paused',
                libvirt.VIR_DOMAIN_SHUTDOWN: 'shutdown',
                libvirt.VIR_DOMAIN_SHUTOFF: 'shutoff',
                libvirt.VIR_DOMAIN_CRASHED: 'crashed'
            }

            return {
                'status': state_map.get(state, 'unknown'),
                'id': dom.ID(),
                'name': vm_name
            }
        except libvirt.libvirtError:
            return {'status': 'not_found'}

    def execute_in_vm(self, vm_name, command):
        """Execute command in VM using QEMU guest agent"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        try:
            dom = self.conn.lookupByName(vm_name)

            # Use QEMU guest agent to execute command
            # This requires guest agent to be installed in VM
            cmd_json = json.dumps({
                'execute': 'guest-exec',
                'arguments': {
                    'path': 'cmd.exe' if 'windows' in vm_name else '/bin/sh',
                    'arg': ['/c' if 'windows' in vm_name else '-c', command],
                    'capture-output': True
                }
            })

            result = dom.qemuAgentCommand(cmd_json, timeout=30)
            return {'success': True, 'result': json.loads(result)}

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def transfer_file_to_vm(self, vm_name, local_path, vm_path):
        """Transfer file to VM"""
        # Implementation depends on guest agent or other method
        # For now, return placeholder
        return {'success': False, 'error': 'Not implemented yet'}

    def capture_screenshot(self, vm_name, output_path):
        """Capture screenshot of VM display"""
        if not self.conn:
            return {'success': False, 'error': 'No libvirt connection'}

        try:
            dom = self.conn.lookupByName(vm_name)

            # Get screenshot stream
            stream = self.conn.newStream()
            mime = dom.screenshot(stream, 0)

            # Save to file
            with open(output_path, 'wb') as f:
                def handler(stream, data, file):
                    return file.write(data)

                stream.recvAll(handler, f)

            stream.finish()
            return {'success': True, 'path': output_path, 'mime': mime}

        except libvirt.libvirtError as e:
            return {'success': False, 'error': str(e)}

    def start_video_recording(self, vm_name, output_path):
        """Start recording VM display"""
        # Use ffmpeg to record VNC stream
        vnc_port = 5900  # Get from VM config

        cmd = [
            'ffmpeg',
            '-f', 'x11grab',
            '-video_size', '1920x1080',
            '-i', f':{vnc_port - 5900}',
            '-codec:v', 'libx264',
            '-preset', 'ultrafast',
            '-y',
            output_path
        ]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return {'success': True, 'process': process.pid}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def stop_video_recording(self, process_pid):
        """Stop video recording"""
        try:
            os.kill(process_pid, 2)  # SIGINT
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_vm_stats(self, vm_name):
        """Get VM resource statistics"""
        if not self.conn:
            return {}

        try:
            dom = self.conn.lookupByName(vm_name)

            info = dom.info()
            cpu_stats = dom.getCPUStats(True)

            return {
                'memory': {
                    'total': info[1],
                    'used': info[2]
                },
                'cpu': cpu_stats,
                'state': info[0]
            }
        except libvirt.libvirtError:
            return {}

    def _generate_vnc_password(self):
        """Generate random VNC password"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for i in range(12))

    def list_vms(self):
        """List all VMs"""
        if not self.conn:
            return []

        try:
            vms = []
            for domain in self.conn.listAllDomains():
                vms.append({
                    'name': domain.name(),
                    'id': domain.ID(),
                    'state': domain.state()[0]
                })
            return vms
        except libvirt.libvirtError:
            return []

    def cleanup(self):
        """Cleanup and close connections"""
        if self.conn:
            self.conn.close()
