# 📖 ShadowLink - Documentation Technique

## ⚠️ AVERTISSEMENT IMPORTANT

> **Ce projet est strictement ÉDUCATIF et destiné à la RECHERCHE EN SÉCURITÉ.**
> 
> ShadowLink a été développé pour :
> - 🎓 **Apprendre** le fonctionnement des malwares et des outils C2
> - 🔬 **Comprendre** les techniques d'attaque pour mieux s'en défendre
> - 🛡️ **Former** les professionnels de la cybersécurité (Blue Team / Red Team)
> - 📚 **Documenter** les méthodes de détection et de mitigation
>
> **L'utilisation de ce logiciel contre des systèmes sans autorisation explicite est ILLÉGALE.**

---

## 🎯 Objectifs Pédagogiques

Ce projet permet d'apprendre :

| Domaine | Concepts Abordés |
|---------|------------------|
| **Développement C** | Sockets, API Windows, manipulation mémoire |
| **Réseau** | Protocoles TCP, chiffrement, communication client-serveur |
| **Sécurité Offensive** | Techniques d'évasion, persistence, post-exploitation |
| **Sécurité Défensive** | Détection, IOCs, analyse forensique, mitigation |
| **Cryptographie** | AES-256-CBC, padding, génération d'IV |

---

## Vue d'ensemble

ShadowLink est un framework Command & Control (C2) éducatif composé de:
- **Agent** : Implant en C pour Windows
- **Server** : Serveur de contrôle en Python

---

## 📁 Structure du Projet

```
ShadowLink/
├── agent/
│   ├── agent.c          # Code source principal de l'agent
│   ├── agent.h          # Headers et configuration
│   ├── aes.c            # Bibliothèque tiny-AES-c
│   └── aes.h            # Headers AES
├── server/
│   ├── server.py        # Serveur C2 Python
│   └── requirements.txt # Dépendances Python
├── docs/
│   ├── README.md        # Ce fichier
│   ├── AGENT.md         # Documentation de l'agent
│   ├── SERVER.md        # Documentation du serveur
│   ├── DETECTION.md     # Guide de détection
│   ├── MITIGATION.md    # Contremesures
│   └── FUTURE.md        # Améliorations futures
├── downloads/           # Fichiers téléchargés depuis les agents
├── reports/             # Rapports de reconnaissance
└── Makefile            # Compilation
```

---

## 🔧 Compilation

### Prérequis

- **GCC** (via MSYS2/MinGW)
- **Python 3.8+**
- **pycryptodome** (`pip install pycryptodome`)

### Compiler l'agent

```bash
# Avec Make
make agent

# Ou directement
gcc -o agent/agent.exe agent/agent.c agent/aes.c -lws2_32 -ladvapi32 -DAES256=1
```

### Lancer le serveur

```bash
cd server
python server.py
```

---

## 🌐 Architecture

```
┌─────────────┐         TCP/4444          ┌─────────────┐
│   Agent 1   │◄─────────────────────────►│             │
└─────────────┘       AES-256-CBC         │             │
                                          │   Server    │
┌─────────────┐         TCP/4444          │   (Python)  │
│   Agent 2   │◄─────────────────────────►│             │
└─────────────┘       AES-256-CBC         │             │
                                          └─────────────┘
       │                                        │
       │                                        │
       ▼                                        ▼
  Exécute les                            Opérateur
  commandes                              (Shell interactif)
```

---

## 🔐 Sécurité des Communications

### Chiffrement

- **Algorithme**: AES-256-CBC
- **Clé**: 32 bytes hardcodée (à changer en production!)
- **IV**: Généré aléatoirement pour chaque message
- **Padding**: PKCS7

### Format des messages

```
┌────────────────┬──────────────────────────┐
│   IV (16 bytes)│   Encrypted Data         │
└────────────────┴──────────────────────────┘
```

---

## 📊 Fonctionnalités par Phase

| Phase | Fonctionnalité | Agent | Server |
|-------|----------------|-------|--------|
| 1 | Connexion TCP | ✅ | ✅ |
| 2 | Shell interactif | ✅ | ✅ |
| 3 | Chiffrement AES-256 | ✅ | ✅ |
| 4 | Reconnaissance | ✅ | ✅ |
| 5 | Reconnexion + Persistence | ✅ | ✅ |
| 6 | Multi-Agent | ✅ | ✅ |
| 7 | Anti-Debug / Anti-VM | ✅ | N/A |
| 8 | Évasion avancée | ✅ | N/A |
| 9 | File Transfer | ✅ | ✅ |
| 10 | Process Management | ✅ | ✅ |

---

## ⚠️ Avertissement Légal

**CE LOGICIEL EST FOURNI À DES FINS ÉDUCATIVES UNIQUEMENT.**

### Usage Autorisé ✅
- Laboratoires de test isolés
- Machines virtuelles personnelles
- Environnements de formation contrôlés
- Recherche en sécurité avec autorisation écrite
- Compétitions CTF (Capture The Flag)

### Usage Interdit ❌
- Systèmes sans autorisation explicite du propriétaire
- Réseaux d'entreprise sans accord formel
- Toute activité malveillante ou illégale
- Distribution à des fins malveillantes

### Responsabilité
Les auteurs déclinent **toute responsabilité** en cas d'utilisation malveillante ou illégale de ce logiciel. L'utilisateur assume l'entière responsabilité de ses actions.

L'utilisation non autorisée peut entraîner des poursuites pénales selon les lois en vigueur (Article 323-1 et suivants du Code pénal français, Computer Fraud and Abuse Act aux USA, etc.).

---

## 📚 Documentation Détaillée

- [Agent Documentation](AGENT.md) - Fonctionnement détaillé de l'implant
- [Server Documentation](SERVER.md) - Utilisation du serveur C2
- [Detection Guide](DETECTION.md) - **Comment détecter ces menaces**
- [Mitigation Guide](MITIGATION.md) - **Comment s'en protéger**
- [Future Improvements](FUTURE.md) - Techniques avancées (non implémentées)

---

## 🤝 Contribution à la Sécurité

Ce projet vise à **améliorer la sécurité** en :
1. Exposant les techniques utilisées par les attaquants
2. Fournissant des règles de détection (YARA, Sigma, Snort)
3. Documentant les contremesures efficaces
4. Formant la nouvelle génération de défenseurs

> *"Pour battre son ennemi, il faut le connaître"* - Sun Tzu
