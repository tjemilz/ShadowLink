# ShadowLink Phase 11 - Advanced Stealth Guide

## Vue d'ensemble

La Phase 11 implémente les techniques de survie **Priorité 1** identifiées lors de l'analyse Kill Chain :

| Module | Menace Neutralisée | Technique |
|--------|-------------------|-----------|
| HTTPS Transport | Détection réseau (port 4444) | WinHTTP + TLS sur port 443 |
| Stager/Loader | Analyse statique, taille | Reflective PE, ~10KB, fileless |
| Sleep Obfuscation | Memory scanning pendant idle | Ekko (ROP + timers), XOR encryption |
| Direct Syscalls | EDR hooks usermode | Hell's Gate, résolution dynamique |

## Architecture Phase 11

```
┌─────────────────────────────────────────────────────────────────┐
│                     STAGER (~10KB)                               │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │ HTTPS        │──▶│ RC4 Decrypt  │──▶│ Reflective PE Load   │ │
│  │ Download     │   │ Payload      │   │ (Memory Only)        │ │
│  └──────────────┘   └──────────────┘   └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     MAIN AGENT                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  HTTPS C2 TRANSPORT                       │   │
│  │  • WinHTTP API (évite socket raw)                        │   │
│  │  • Port 443 (blend avec trafic légitime)                 │   │
│  │  • Endpoints REST disguisés (/api/v1/health/status)      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           │                                      │
│  ┌────────────────────────┴─────────────────────────────────┐   │
│  │                   MAIN LOOP                               │   │
│  │                                                           │   │
│  │   ┌─────────────┐                                        │   │
│  │   │ 1. Beacon   │ ◀─────────────────────────────────────┐│   │
│  │   └──────┬──────┘                                       ││   │
│  │          │                                               ││   │
│  │          ▼                                               ││   │
│  │   ┌─────────────┐                                       ││   │
│  │   │ 2. Execute  │ (Commands via Direct Syscalls)        ││   │
│  │   └──────┬──────┘                                       ││   │
│  │          │                                               ││   │
│  │          ▼                                               ││   │
│  │   ┌─────────────┐     ┌──────────────────────────────┐  ││   │
│  │   │ 3. Sleep    │────▶│   SLEEP OBFUSCATION (Ekko)   │──┘│   │
│  │   └─────────────┘     │   • Encrypt .text/.data      │   │   │
│  │                       │   • ROP chain to NtContinue  │   │   │
│  │                       │   • Timer callback wakeup    │   │   │
│  │                       └──────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  DIRECT SYSCALLS                          │   │
│  │  • Hell's Gate: résolution depuis ntdll.dll propre       │   │
│  │  • Bypass tous les hooks EDR usermode                    │   │
│  │  • APIs: NtAllocate, NtProtect, NtWrite, NtCreateThread  │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Nouveaux Fichiers

### Agent
- `agent/https_transport.h` / `.c` - Transport HTTPS avec WinHTTP
- `agent/sleep_obfuscation.h` / `.c` - Technique Ekko
- `agent/syscalls.h` / `.c` - Hell's Gate syscalls
- `agent/syscalls_asm.asm` - Stubs assembleur pour syscalls directs

### Stager
- `stager/stager.h` / `.c` - Loader minimal reflectif
- `stager/Makefile` - Build séparé (~10KB output)

### Serveur
- `server/server_https.py` - Serveur Flask HTTPS

## Compilation

### Prérequis
```bash
# MinGW pour cross-compilation Windows
sudo apt install mingw-w64

# NASM pour l'assembleur (optionnel, syscalls avancés)
sudo apt install nasm

# OpenSSL pour les certificats
sudo apt install openssl
```

### Build Agent
```bash
# Mode debug (avec console)
make agent

# Mode stealth (sans console, pour production)
make agent-stealth
```

### Build Stager
```bash
make stager
# Output: stager/stager.exe (~10KB)
```

### Génération Certificats SSL
```bash
make certs
# Génère: server/server.crt, server/server.key
```

## Utilisation

### 1. Démarrer le serveur HTTPS
```bash
make server-https
# Écoute sur 0.0.0.0:443
```

### 2. Configurer l'agent
Modifier `agent/agent.h` :
```c
// IP du serveur (chiffrée XOR 0x5A)
// Utiliser le script de génération pour votre IP

// Transport: 1=HTTPS (défaut), 0=TCP legacy
#define USE_HTTPS_TRANSPORT 1

// Sleep obfuscation: 1=activé, 0=désactivé
#define SLEEP_OBFUSCATION_ENABLED 1

// Intervalle beacon par défaut (ms)
#define DEFAULT_BEACON_INTERVAL 60000  // 60 secondes
```

### 3. Déploiement avec Stager
```
1. Compiler l'agent complet → agent.exe (~200KB)
2. L'héberger sur le serveur HTTPS
3. Modifier stager.c avec l'URL de téléchargement
4. Compiler le stager → stager.exe (~10KB)
5. Déployer le stager sur la cible
6. Le stager télécharge et charge l'agent en mémoire (fileless)
```

## Nouvelles Commandes Serveur

| Commande | Description |
|----------|-------------|
| `sleep <ms>` | Change l'intervalle de beacon |
| `ps` | Liste processus (via syscalls directs) |
| `creds` | Dump credentials |
| `persist` | Installe persistance |
| `die` | Termine l'agent |

## Techniques Anti-Détection

### 1. HTTPS Transport
**Avant:** TCP direct sur port 4444 (flagrant)
**Après:** HTTPS sur port 443 avec User-Agent légitime

Les endpoints sont déguisés :
- `/api/v1/health/status` → Beacon (semble être un health check API)
- `/api/v1/config/update` → Upload résultats (semble être une mise à jour config)

### 2. Sleep Obfuscation (Ekko)
**Problème:** Memory scanners détectent le code malveillant pendant le sleep

**Solution:** 
1. Avant sleep: chiffrer .text et .data avec XOR
2. Créer ROP chain: `VirtualProtect → SystemFunction032 → NtContinue`
3. Utiliser `CreateTimerQueueTimer` pour réveiller
4. Au réveil: le timer callback exécute le ROP qui déchiffre et restaure

### 3. Direct Syscalls (Hell's Gate)
**Problème:** Les EDR hookent `ntdll.dll` pour intercepter les appels système

**Solution:**
1. Lire `ntdll.dll` propre depuis le disque (pas la version hookée en mémoire)
2. Parser les exports, trouver les numéros syscall (pattern `mov eax, <number>`)
3. Appeler `syscall` directement sans passer par ntdll hookée

APIs bypassées:
- `NtAllocateVirtualMemory` → Allocation mémoire
- `NtProtectVirtualMemory` → Changement permissions (RWX)
- `NtWriteVirtualMemory` → Écriture dans autre process
- `NtCreateThreadEx` → Création thread remote
- `NtOpenProcess` → Ouverture handle process

## Tests de Validation

### Test HTTPS
```python
# Vérifier que le serveur répond
curl -k https://localhost:443/api/v1/health/status
# Devrait retourner: {"status": "NOP"}
```

### Test Sleep Obfuscation
1. Lancer l'agent en debug
2. Pendant le sleep, faire un dump mémoire
3. Vérifier que .text/.data sont chiffrés (pas de strings lisibles)

### Test Syscalls
1. Activer un EDR/AV avec hooks usermode
2. Exécuter une injection process
3. Vérifier que l'injection réussit malgré les hooks

## Limitations Connues

1. **Certificats auto-signés**: Les proxies SSL enterprise pourraient alerter
2. **NASM requis**: Pour les syscalls assembleur avancés
3. **Windows 10/11 seulement**: Les numéros syscall varient par version
4. **Sleep obfuscation**: Peut échouer si DEP strict ou CFG activé

## Prochaines Étapes (Phase 12)

- [ ] Domain fronting pour C2
- [ ] Polymorphic stager (mutation à chaque exécution)
- [ ] Indirect syscalls (jump dans ntdll pour cacher l'origine)
- [ ] Stack spoofing complet
