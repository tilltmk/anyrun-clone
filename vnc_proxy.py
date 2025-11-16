"""
VNC WebSocket Proxy for KVM Stream
Provides real-time VM display to web browsers using noVNC protocol
"""

import asyncio
import websockets
import socket
import threading
import json
from flask_socketio import SocketIO


class VNCWebSocketProxy:
    """
    Proxy that bridges VNC connections to WebSocket for browser viewing.
    Uses noVNC protocol for web-based VNC access.
    """

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.active_proxies = {}  # session_id -> proxy info
        self.loop = None

    def start_proxy(self, session_id, vnc_host='localhost', vnc_port=5900, ws_port=None):
        """
        Start a WebSocket proxy for a specific VNC connection.

        Args:
            session_id: Analysis session ID
            vnc_host: VNC server host (usually localhost for KVM)
            vnc_port: VNC server port
            ws_port: WebSocket port (auto-assigned if None)
        """
        if ws_port is None:
            # Auto-assign port based on VNC port
            ws_port = 6000 + (vnc_port - 5900)

        proxy_thread = threading.Thread(
            target=self._run_proxy,
            args=(session_id, vnc_host, vnc_port, ws_port),
            daemon=True
        )
        proxy_thread.start()

        self.active_proxies[session_id] = {
            'vnc_host': vnc_host,
            'vnc_port': vnc_port,
            'ws_port': ws_port,
            'thread': proxy_thread
        }

        return {
            'success': True,
            'ws_port': ws_port,
            'ws_url': f'ws://localhost:{ws_port}'
        }

    def _run_proxy(self, session_id, vnc_host, vnc_port, ws_port):
        """Run the WebSocket to VNC proxy"""
        async def handle_websocket(websocket, path):
            # Connect to VNC server
            vnc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                vnc_socket.connect((vnc_host, vnc_port))
                vnc_socket.setblocking(False)

                # Bidirectional proxy
                async def vnc_to_ws():
                    while True:
                        try:
                            data = await asyncio.get_event_loop().run_in_executor(
                                None, lambda: vnc_socket.recv(4096)
                            )
                            if not data:
                                break
                            await websocket.send(data)
                        except Exception:
                            break

                async def ws_to_vnc():
                    while True:
                        try:
                            data = await websocket.recv()
                            if isinstance(data, str):
                                data = data.encode()
                            vnc_socket.sendall(data)
                        except Exception:
                            break

                await asyncio.gather(vnc_to_ws(), ws_to_vnc())

            except Exception as e:
                print(f"VNC proxy error: {e}")
            finally:
                vnc_socket.close()

        # Start WebSocket server
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            start_server = websockets.serve(handle_websocket, '0.0.0.0', ws_port)
            loop.run_until_complete(start_server)
            print(f"VNC WebSocket proxy started on port {ws_port}")
            loop.run_forever()
        except Exception as e:
            print(f"Failed to start VNC proxy: {e}")

    def stop_proxy(self, session_id):
        """Stop a specific proxy"""
        if session_id in self.active_proxies:
            # Thread will stop when main process exits
            del self.active_proxies[session_id]
            return {'success': True}
        return {'success': False, 'error': 'Proxy not found'}

    def get_proxy_info(self, session_id):
        """Get proxy information for a session"""
        if session_id in self.active_proxies:
            return self.active_proxies[session_id]
        return None


class SimpleVNCClient:
    """
    Simple VNC client for capturing frames from KVM VMs.
    Used for screenshot capture when full VNC proxy is not needed.
    """

    def __init__(self, host='localhost', port=5900):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self):
        """Connect to VNC server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

        # VNC handshake
        version = self.socket.recv(12)
        self.socket.send(b'RFB 003.008\n')

        # Security type
        num_types = self.socket.recv(1)[0]
        types = self.socket.recv(num_types)

        # Use no authentication (type 1) if available
        if 1 in types:
            self.socket.send(bytes([1]))
            result = self.socket.recv(4)
            if result != b'\x00\x00\x00\x00':
                raise Exception("VNC authentication failed")
        else:
            raise Exception("No supported authentication method")

        # Client init (shared flag)
        self.socket.send(bytes([1]))

        # Server init - get framebuffer info
        server_init = self.socket.recv(24)
        self.width = int.from_bytes(server_init[0:2], 'big')
        self.height = int.from_bytes(server_init[2:4], 'big')

        # Skip server name
        name_length = int.from_bytes(server_init[20:24], 'big')
        self.socket.recv(name_length)

        return True

    def capture_frame(self):
        """Capture current frame from VNC"""
        if not self.socket:
            return None

        # Request framebuffer update
        request = bytes([
            3,  # FramebufferUpdateRequest
            0,  # Incremental = false
            0, 0,  # x-position
            0, 0,  # y-position
            (self.width >> 8) & 0xff, self.width & 0xff,  # width
            (self.height >> 8) & 0xff, self.height & 0xff  # height
        ])
        self.socket.send(request)

        # Read response
        msg_type = self.socket.recv(1)[0]
        if msg_type != 0:  # Not a framebuffer update
            return None

        self.socket.recv(1)  # padding
        num_rects = int.from_bytes(self.socket.recv(2), 'big')

        # Read rectangle data (simplified - assumes raw encoding)
        frame_data = b''
        for _ in range(num_rects):
            rect_header = self.socket.recv(12)
            x = int.from_bytes(rect_header[0:2], 'big')
            y = int.from_bytes(rect_header[2:4], 'big')
            w = int.from_bytes(rect_header[4:6], 'big')
            h = int.from_bytes(rect_header[6:8], 'big')
            encoding = int.from_bytes(rect_header[8:12], 'big')

            if encoding == 0:  # Raw
                # 4 bytes per pixel (BGRA)
                rect_size = w * h * 4
                rect_data = b''
                while len(rect_data) < rect_size:
                    rect_data += self.socket.recv(rect_size - len(rect_data))
                frame_data += rect_data

        return frame_data

    def disconnect(self):
        """Disconnect from VNC server"""
        if self.socket:
            self.socket.close()
            self.socket = None
