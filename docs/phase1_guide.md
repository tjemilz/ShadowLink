# Phase 1 - Établir la connexion TCP

## Objectif
Créer une connexion TCP stable entre l'agent Windows (C) et le serveur Python.

## Architecture
```
[Agent Windows] --TCP--> [Serveur Python]
     (Client)              (Listener)
```

## Étapes à implémenter

### Côté Serveur Python (`server/server.py`)
1. **Import des modules**
   - Quel module Python gère les sockets ?
   
2. **Configuration**
   - Sur quelle interface écouter ? (0.0.0.0 pour toutes, 127.0.0.1 pour local)
   - Quel port utiliser ? (Évitez les ports < 1024)
   
3. **Création du socket**
   - Quel type de socket ? (SOCK_STREAM pour TCP)
   - Quelle famille d'adresses ? (AF_INET pour IPv4)
   
4. **Mise en écoute**
   - Comment réutiliser un port ? (option SO_REUSEADDR)
   - Combien de connexions en attente ?
   
5. **Acceptation des connexions**
   - Que retourne accept() ?
   - Comment afficher l'adresse du client ?

### Côté Agent C (`agent/agent.c`)
1. **Initialisation Winsock**
   - Quelle fonction appeler ? (WSAStartup)
   - Quelle version demander ? (MAKEWORD(2, 2) pour Winsock 2.2)
   
2. **Création du socket**
   - Fonction à utiliser ? (socket)
   - Paramètres : AF_INET, SOCK_STREAM, IPPROTO_TCP
   
3. **Configuration de l'adresse serveur**
   - Structure à utiliser ? (struct sockaddr_in)
   - Comment convertir l'IP ? (inet_addr)
   - Comment convertir le port ? (htons)
   
4. **Connexion**
   - Fonction à utiliser ? (connect)
   - Comment gérer l'échec ?
   
5. **Test basique**
   - Envoyer un message simple avec send()
   - Recevoir avec recv()

## Tests
1. Lancer le serveur Python
2. Lancer l'agent depuis Windows
3. Vérifier que la connexion est établie
4. Tester l'échange de messages simples

## Points d'attention
- Gestion des erreurs (vérifier les valeurs de retour)
- Ordre des opérations (serveur doit écouter avant que le client se connecte)
- Encodage des données (bytes en Python, char* en C)
- Fermeture propre des sockets

## Ressources
- Python socket: https://docs.python.org/3/library/socket.html
- Winsock2: https://docs.microsoft.com/en-us/windows/win32/winsock/
