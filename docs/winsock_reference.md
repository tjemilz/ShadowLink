# Documentation Winsock2 pour ShadowLink Agent

## 📚 Table des matières
1. [Headers nécessaires](#headers)
2. [WSAStartup - Initialisation](#wsastartup)
3. [socket() - Création du socket](#socket)
4. [struct sockaddr_in - Configuration](#sockaddr)
5. [connect() - Connexion au serveur](#connect)
6. [send() - Envoi de données](#send)
7. [recv() - Réception de données](#recv)
8. [closesocket() & WSACleanup()](#cleanup)
9. [Exemple complet annoté](#exemple)

---

## <a name="headers"></a>1. Headers nécessaires

```c
#include <stdio.h>      // Pour printf()
#include <winsock2.h>   // API Winsock2
#include <ws2tcpip.h>   // Fonctions TCP/IP avancées (inet_pton, etc.)

// IMPORTANT: Lier la bibliothèque ws2_32
// Avec gcc: -lws2_32
```

**⚠️ Ordre important** : `winsock2.h` AVANT `windows.h` !

---

## <a name="wsastartup"></a>2. WSAStartup - Initialiser Winsock

### Prototype
```c
int WSAStartup(
    WORD      wVersionRequested,  // Version de Winsock demandée
    LPWSADATA lpWSAData           // Pointeur vers structure WSADATA
);
```

### Paramètres

**`wVersionRequested`** : Version de Winsock à charger
- Créé avec la macro `MAKEWORD(majeur, mineur)`
- Pour Winsock 2.2 : `MAKEWORD(2, 2)`

**`lpWSAData`** : Pointeur vers une structure `WSADATA` qui recevra les détails

### Structure WSADATA
```c
typedef struct WSAData {
    WORD wVersion;        // Version retournée par la DLL
    WORD wHighVersion;    // Version max supportée
    // ... autres champs moins importants
} WSADATA;
```

### Retour
- `0` : Succès
- Autre : Code d'erreur

### Exemple d'utilisation
```c
WSADATA wsaData;
int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

if (result != 0) {
    printf("WSAStartup failed: %d\n", result);
    return 1;
}
printf("[+] Winsock initialized\n");
```

### 🔍 Explication
- `MAKEWORD(2, 2)` = demande Winsock version 2.2
- `&wsaData` = adresse de la structure à remplir
- **Obligatoire** avant toute utilisation de sockets Windows !

---

## <a name="socket"></a>3. socket() - Créer un socket

### Prototype
```c
SOCKET socket(
    int af,       // Address Family (famille d'adresses)
    int type,     // Type de socket
    int protocol  // Protocole
);
```

### Paramètres

**`af`** (Address Family) :
- `AF_INET` = IPv4
- `AF_INET6` = IPv6

**`type`** :
- `SOCK_STREAM` = TCP (orienté connexion, fiable)
- `SOCK_DGRAM` = UDP (sans connexion, non fiable)

**`protocol`** :
- `IPPROTO_TCP` = TCP
- `IPPROTO_UDP` = UDP
- `0` = Automatique (déterminé par type)

### Retour
- Succès : Handle de socket (type `SOCKET`)
- Échec : `INVALID_SOCKET`

### Exemple d'utilisation
```c
SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

if (clientSocket == INVALID_SOCKET) {
    printf("socket() failed: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
}
printf("[+] Socket created\n");
```

### 🔍 Explication
- `AF_INET` = IPv4
- `SOCK_STREAM` = TCP (flux de données fiable)
- `IPPROTO_TCP` = Protocole TCP explicite

---

## <a name="sockaddr"></a>4. struct sockaddr_in - Configuration de l'adresse

### Structure
```c
struct sockaddr_in {
    short          sin_family;   // Famille d'adresses (AF_INET)
    unsigned short sin_port;     // Port (en network byte order)
    struct in_addr sin_addr;     // Adresse IP
    char           sin_zero[8];  // Padding (non utilisé)
};

struct in_addr {
    unsigned long s_addr;  // Adresse IP en network byte order
};
```

### Fonctions de conversion

**`htons()` - Host TO Network Short**
```c
unsigned short htons(unsigned short hostshort);
```
Convertit un port de l'ordre d'octets de l'hôte vers l'ordre réseau (Big Endian).

**`inet_addr()` - Convertir IP string vers binaire**
```c
unsigned long inet_addr(const char *cp);
```
Convertit une adresse IP en chaîne ("127.0.0.1") en format binaire.

⚠️ **Retourne `INADDR_NONE` en cas d'erreur !**

### Exemple d'utilisation
```c
struct sockaddr_in serverAddr;

// Initialiser à zéro (bonne pratique)
memset(&serverAddr, 0, sizeof(serverAddr));

// Configurer la famille d'adresses
serverAddr.sin_family = AF_INET;

// Configurer le port (conversion en network byte order)
serverAddr.sin_port = htons(4444);

// Configurer l'adresse IP
serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

// Vérification
if (serverAddr.sin_addr.s_addr == INADDR_NONE) {
    printf("Invalid IP address\n");
    return 1;
}
```

### 🔍 Explication Network Byte Order
Les réseaux utilisent **Big Endian** (octet de poids fort en premier).
Les processeurs x86/x64 utilisent **Little Endian**.

**Sans conversion** :
- Port 4444 (0x115C) en Little Endian → envoyé tel quel → mauvais port côté serveur

**Avec htons()** :
- Port 4444 → converti en Big Endian → correct sur le réseau

---

## <a name="connect"></a>5. connect() - Se connecter au serveur

### Prototype
```c
int connect(
    SOCKET         s,        // Socket client
    const struct sockaddr *name,  // Adresse du serveur
    int            namelen   // Taille de la structure d'adresse
);
```

### Paramètres

**`s`** : Socket créé avec `socket()`

**`name`** : Pointeur vers `struct sockaddr_in` (casté en `struct sockaddr*`)

**`namelen`** : Taille de la structure (utilisez `sizeof()`)

### Retour
- `0` : Succès
- `SOCKET_ERROR` : Échec (utilisez `WSAGetLastError()` pour le code)

### Exemple d'utilisation
```c
int result = connect(
    clientSocket, 
    (struct sockaddr*)&serverAddr,  // Cast nécessaire
    sizeof(serverAddr)
);

if (result == SOCKET_ERROR) {
    printf("connect() failed: %d\n", WSAGetLastError());
    closesocket(clientSocket);
    WSACleanup();
    return 1;
}
printf("[+] Connected to server\n");
```

### 🔍 Explication du cast
`connect()` attend un pointeur générique `struct sockaddr*`, mais nous utilisons la structure spécifique IPv4 `struct sockaddr_in*`. Le cast est nécessaire pour la compatibilité.

---

## <a name="send"></a>6. send() - Envoyer des données

### Prototype
```c
int send(
    SOCKET     s,       // Socket connecté
    const char *buf,    // Buffer contenant les données
    int        len,     // Nombre d'octets à envoyer
    int        flags    // Options (généralement 0)
);
```

### Paramètres

**`s`** : Socket connecté

**`buf`** : Pointeur vers les données à envoyer

**`len`** : Nombre d'octets à envoyer

**`flags`** : Options (mettez `0` pour comportement normal)

### Retour
- Succès : Nombre d'octets réellement envoyés
- Échec : `SOCKET_ERROR`

### Exemple d'utilisation
```c
const char *message = "Hello from Windows agent!";
int bytesSent = send(clientSocket, message, strlen(message), 0);

if (bytesSent == SOCKET_ERROR) {
    printf("send() failed: %d\n", WSAGetLastError());
    closesocket(clientSocket);
    WSACleanup();
    return 1;
}
printf("[+] Sent %d bytes\n", bytesSent);
```

### ⚠️ Points importants
- `send()` peut envoyer **moins d'octets** que demandé !
- Pour être sûr, vérifiez la valeur de retour
- Pour des envois complets, utilisez une boucle :

```c
int totalSent = 0;
int remaining = strlen(message);
const char *ptr = message;

while (totalSent < strlen(message)) {
    int sent = send(clientSocket, ptr + totalSent, remaining, 0);
    if (sent == SOCKET_ERROR) {
        printf("send() failed\n");
        break;
    }
    totalSent += sent;
    remaining -= sent;
}
```

---

## <a name="recv"></a>7. recv() - Recevoir des données

### Prototype
```c
int recv(
    SOCKET s,       // Socket connecté
    char   *buf,    // Buffer pour stocker les données reçues
    int    len,     // Taille du buffer
    int    flags    // Options (généralement 0)
);
```

### Paramètres

**`s`** : Socket connecté

**`buf`** : Buffer où stocker les données reçues

**`len`** : Taille maximale du buffer

**`flags`** : Options (mettez `0` pour comportement normal)

### Retour
- Succès : Nombre d'octets reçus
- `0` : Connexion fermée proprement par l'autre côté
- `SOCKET_ERROR` : Erreur

### Exemple d'utilisation
```c
char buffer[1024];
int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

if (bytesReceived > 0) {
    buffer[bytesReceived] = '\0';  // Terminer la chaîne
    printf("[+] Received %d bytes: %s\n", bytesReceived, buffer);
    
} else if (bytesReceived == 0) {
    printf("[*] Connection closed by server\n");
    
} else {
    printf("recv() failed: %d\n", WSAGetLastError());
}
```

### ⚠️ Points importants
- Toujours laisser 1 octet pour le `\0` terminal : `sizeof(buffer) - 1`
- `recv()` est **bloquant** par défaut (attend des données)
- Peut recevoir **moins d'octets** que la taille du buffer
- Retour `0` = connexion fermée (pas une erreur !)

---

## <a name="cleanup"></a>8. Nettoyage - closesocket() & WSACleanup()

### closesocket()

```c
int closesocket(SOCKET s);
```

Ferme un socket et libère les ressources associées.

**Retour** :
- `0` : Succès
- `SOCKET_ERROR` : Échec

**Exemple** :
```c
closesocket(clientSocket);
printf("[*] Socket closed\n");
```

### WSACleanup()

```c
int WSACleanup(void);
```

Termine l'utilisation de Winsock. **Obligatoire** à la fin du programme.

**Retour** :
- `0` : Succès
- `SOCKET_ERROR` : Échec

**Exemple** :
```c
WSACleanup();
printf("[*] Winsock cleaned up\n");
```

### 🔍 Ordre de nettoyage
```c
// 1. Fermer tous les sockets
closesocket(clientSocket);

// 2. Terminer Winsock
WSACleanup();
```

---

## <a name="exemple"></a>9. Exemple complet annoté

```c
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444

int main() {
    printf("[*] ShadowLink Agent - Phase 1\n");
    
    // ===== 1. Initialiser Winsock =====
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    printf("[+] Winsock initialized\n");
    
    // ===== 2. Créer le socket =====
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket created\n");
    
    // ===== 3. Configurer l'adresse du serveur =====
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    
    if (serverAddr.sin_addr.s_addr == INADDR_NONE) {
        printf("Invalid IP address\n");
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Server address configured\n");
    
    // ===== 4. Se connecter au serveur =====
    result = connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Connected to %s:%d\n", SERVER_IP, SERVER_PORT);
    
    // ===== 5. Recevoir le message du serveur =====
    char recvBuffer[1024];
    int bytesReceived = recv(clientSocket, recvBuffer, sizeof(recvBuffer) - 1, 0);
    
    if (bytesReceived > 0) {
        recvBuffer[bytesReceived] = '\0';
        printf("[+] Received: %s", recvBuffer);
    } else if (bytesReceived == 0) {
        printf("[*] Connection closed by server\n");
    } else {
        printf("recv() failed: %d\n", WSAGetLastError());
    }
    
    // ===== 6. Envoyer une réponse au serveur =====
    const char *response = "Agent connected successfully!";
    int bytesSent = send(clientSocket, response, strlen(response), 0);
    
    if (bytesSent == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
    } else {
        printf("[+] Sent %d bytes\n", bytesSent);
    }
    
    // ===== 7. Nettoyage =====
    closesocket(clientSocket);
    WSACleanup();
    printf("[*] Cleanup complete\n");
    
    return 0;
}
```

---

## 📖 Ressources officielles

- **Microsoft Winsock Documentation** : https://docs.microsoft.com/en-us/windows/win32/winsock/
- **WSAStartup** : https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
- **socket()** : https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
- **connect()** : https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
- **send()** : https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send
- **recv()** : https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recv

---

## 🛠️ Compilation

```bash
# Depuis Linux avec MinGW
x86_64-w64-mingw32-gcc agent.c -o agent.exe -lws2_32 -static

# Depuis Windows avec gcc/MinGW
gcc agent.c -o agent.exe -lws2_32

# Avec le Makefile fourni
make agent
```

---

## ⚠️ Erreurs courantes

### 1. `undefined reference to WSAStartup`
**Solution** : Ajoutez `-lws2_32` à la compilation

### 2. `winsock2.h: No such file or directory`
**Solution** : Installez MinGW-w64 sur Linux

### 3. Port déjà utilisé
**Solution** : Changez le port ou tuez le processus qui l'utilise

### 4. Connection refused
**Solution** : Vérifiez que le serveur Python écoute sur le bon port

---

**Bon courage pour l'implémentation ! 🚀**
