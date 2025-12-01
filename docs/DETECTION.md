# 🔍 ShadowLink - Guide de Détection

Ce document décrit comment détecter l'agent ShadowLink et les indicateurs de compromission (IOCs).

---

## 📋 Table des Matières

1. [Indicateurs de Compromission (IOCs)](#indicateurs-de-compromission-iocs)
2. [Détection Réseau](#détection-réseau)
3. [Détection Système](#détection-système)
4. [Détection Mémoire](#détection-mémoire)
5. [Détection Comportementale](#détection-comportementale)
6. [Règles de Détection](#règles-de-détection)
7. [Outils Recommandés](#outils-recommandés)

---

## 🎯 Indicateurs de Compromission (IOCs)

### Fichiers

| Type | Indicateur | Description |
|------|------------|-------------|
| Nom | `agent.exe` | Nom par défaut (modifiable) |
| Taille | ~50-80 KB | Petit exécutable Windows |
| Hash | Variable | Compiler le binaire et hasher |

### Registre

| Clé | Valeur |
|-----|--------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `WindowsSecurityHealth` |

**Commande de vérification:**
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | 
    Select-Object WindowsSecurityHealth
```

### Réseau

| Indicateur | Valeur |
|------------|--------|
| Port | TCP 4444 (par défaut) |
| Protocole | TCP brut (pas HTTP) |
| Pattern | Beacon régulier toutes les ~5s |
| Payload | Chiffré AES-256-CBC |

### Strings dans le binaire

```
# Strings potentiellement détectables (si non chiffrées)
cmd.exe
/c
ShadowLink
WindowsSecurityHealth
Software\Microsoft\Windows\CurrentVersion\Run
SHADOWLINK
```

---

## 🌐 Détection Réseau

### Caractéristiques du trafic

1. **Connexion TCP persistante** vers un port non-standard
2. **Pas de HTTP/HTTPS** - trafic binaire
3. **Pattern de beacon** régulier
4. **Taille des paquets** variable mais petite pour les commandes

### Analyse Wireshark

```
# Filtre pour le port par défaut
tcp.port == 4444

# Filtre pour connexions TCP suspectes
tcp.flags.syn == 1 and tcp.flags.ack == 0 and 
!(tcp.dstport in {80, 443, 22, 21, 25, 53})
```

### Signature Snort/Suricata

```snort
# Détection de connexion au port 4444
alert tcp $HOME_NET any -> any 4444 (
    msg:"ShadowLink C2 - Potential Connection"; 
    flow:to_server,established;
    sid:1000001; 
    rev:1;
)

# Détection de beacon pattern
alert tcp $HOME_NET any -> any any (
    msg:"ShadowLink C2 - Beacon Pattern";
    flow:to_server,established;
    dsize:<100;
    detection_filter:track by_src, count 10, seconds 60;
    sid:1000002;
    rev:1;
)
```

### Zeek (Bro) Script

```zeek
event connection_established(c: connection)
{
    if (c$id$resp_p == 4444/tcp)
    {
        NOTICE([$note=Potential_C2,
                $msg="Connection to suspicious port 4444",
                $conn=c]);
    }
}
```

### Détection DNS

L'agent actuel n'utilise pas DNS (IP hardcodée), mais si modifié:

```
# Requêtes DNS suspectes
- Fréquence anormalement élevée
- Domaines avec haute entropie
- Sous-domaines très longs (DNS tunneling)
```

---

## 🖥️ Détection Système

### Processus

```powershell
# Recherche de processus suspects
Get-Process | Where-Object {
    $_.Path -notlike "C:\Windows\*" -and 
    $_.Path -notlike "C:\Program Files*" -and
    $_.Company -eq $null
}

# Vérifier les connexions du processus
Get-NetTCPConnection | Where-Object {
    $_.RemotePort -eq 4444 -or
    ($_.State -eq "Established" -and $_.RemotePort -notin @(80,443,22))
}
```

### Registre

```powershell
# Vérifier les clés Run
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    Write-Host "`n$key"
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
}

# Chercher spécifiquement WindowsSecurityHealth
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | 
    Select-Object WindowsSecurityHealth
```

### Fichiers

```powershell
# Recherche de fichiers récents dans des emplacements suspects
Get-ChildItem -Path $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA -Recurse |
    Where-Object { 
        $_.Extension -eq ".exe" -and 
        $_.CreationTime -gt (Get-Date).AddDays(-7)
    }

# Vérifier la signature des exécutables
Get-ChildItem -Path C:\Users -Recurse -Filter "*.exe" |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName
        if ($sig.Status -ne "Valid") {
            [PSCustomObject]@{
                Path = $_.FullName
                Status = $sig.Status
            }
        }
    }
```

### Services

```powershell
# Services suspects (si l'agent est modifié pour s'installer en service)
Get-Service | Where-Object {
    $_.Status -eq "Running" -and
    $_.StartType -eq "Automatic" -and
    $_.DisplayName -like "*Security*Health*"
}
```

---

## 🧠 Détection Mémoire

### Volatility 3

```bash
# Lister les processus
python3 vol.py -f memory.dmp windows.pslist

# Recherche de strings
python3 vol.py -f memory.dmp windows.strings --pattern "ShadowLink"
python3 vol.py -f memory.dmp windows.strings --pattern "WindowsSecurityHealth"

# Connexions réseau
python3 vol.py -f memory.dmp windows.netscan

# DLLs chargées
python3 vol.py -f memory.dmp windows.dlllist --pid <PID>

# Injection potentielle
python3 vol.py -f memory.dmp windows.malfind
```

### Process Hacker / Process Explorer

1. **Vérifier les strings** dans la mémoire du processus
2. **Analyser les handles** réseau
3. **Vérifier le parent process** (orphan process = suspect)
4. **Examiner les threads** pour du code injecté

### YARA Rules

```yara
rule ShadowLink_Agent
{
    meta:
        description = "Détecte l'agent ShadowLink C2"
        author = "Security Team"
        date = "2024-01-15"
    
    strings:
        $s1 = "ShadowLink" ascii wide
        $s2 = "WindowsSecurityHealth" ascii wide
        $s3 = "cmd.exe /c" ascii wide
        $s4 = "AES256SecretKey" ascii wide
        
        // Patterns de code
        $code1 = { 57 53 41 53 74 61 72 74 75 70 }  // WSAStartup
        $code2 = { 52 65 67 4F 70 65 6E 4B 65 79 }  // RegOpenKey
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize < 200KB and
        (2 of ($s*) or all of ($code*))
}

rule ShadowLink_Memory
{
    meta:
        description = "Détecte ShadowLink en mémoire"
    
    strings:
        $key = "ShadowLinkAES256SecretKey32Bytes"
        $persist = "WindowsSecurityHealth"
        $cmd = "cmd.exe /c chcp 65001"
        
    condition:
        any of them
}
```

---

## 🔬 Détection Comportementale

### Sysmon Configuration

```xml
<Sysmon schemaversion="4.50">
    <EventFiltering>
        <!-- Process Creation -->
        <RuleGroup name="ProcessCreate" groupRelation="or">
            <ProcessCreate onmatch="include">
                <!-- cmd.exe spawned by unknown process -->
                <Image condition="end with">cmd.exe</Image>
                
                <!-- Execution from temp folders -->
                <Image condition="contains">\Temp\</Image>
                <Image condition="contains">\AppData\</Image>
            </ProcessCreate>
        </RuleGroup>
        
        <!-- Network Connections -->
        <RuleGroup name="NetworkConnect" groupRelation="or">
            <NetworkConnect onmatch="include">
                <!-- Port 4444 -->
                <DestinationPort condition="is">4444</DestinationPort>
                
                <!-- Connections from non-browser processes -->
                <Image condition="excludes">chrome.exe</Image>
                <Image condition="excludes">firefox.exe</Image>
                <Image condition="excludes">msedge.exe</Image>
            </NetworkConnect>
        </RuleGroup>
        
        <!-- Registry Modifications -->
        <RuleGroup name="RegistryEvent" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
            </RegistryEvent>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

### Windows Event Logs

```powershell
# Process Creation (Event 4688)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Properties[5].Value -like "*cmd.exe*"
}

# Network Connections (avec Sysmon Event 3)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3
} | Where-Object {
    $_.Properties[13].Value -eq 4444
}

# Registry (Sysmon Event 12, 13, 14)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 12,13,14
} | Where-Object {
    $_.Message -like "*CurrentVersion\Run*"
}
```

### Sigma Rules

```yaml
title: ShadowLink C2 Agent Detection
status: experimental
description: Detects ShadowLink C2 agent activity
author: Security Team
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        ParentImage|endswith: '\agent.exe'
        Image|endswith: '\cmd.exe'
    selection_persist:
        TargetObject|contains: 
            - '\CurrentVersion\Run'
        Details|contains: 'WindowsSecurityHealth'
    condition: selection_cmd or selection_persist
level: high
---
title: ShadowLink Network Connection
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 4444
        Initiated: 'true'
    condition: selection
level: medium
```

---

## 🔧 Règles de Détection

### Windows Defender Custom Detection

```powershell
# Ajouter une exclusion inverse (bloc) pour le hash
# Note: Nécessite Windows Defender ATP/365

# Via Group Policy
# Computer Configuration > Administrative Templates > 
# Windows Components > Microsoft Defender Antivirus > 
# Threats > Specify threat alert levels
```

### CrowdStrike/Carbon Black IOC

```json
{
    "ioc_type": "query",
    "ioc_value": {
        "process_name": ["cmd.exe"],
        "parent_name": ["agent.exe"],
        "network_connections": {
            "remote_port": [4444]
        }
    },
    "severity": "high",
    "description": "ShadowLink C2 Agent Activity"
}
```

### Elastic Security

```json
{
    "rule": {
        "name": "ShadowLink C2 Detection",
        "query": "process.name:cmd.exe AND process.parent.name:*.exe AND destination.port:4444",
        "severity": "high"
    }
}
```

---

## 🛠️ Outils Recommandés

### Analyse Réseau

| Outil | Usage |
|-------|-------|
| Wireshark | Capture et analyse de paquets |
| Zeek (Bro) | Analyse de trafic réseau |
| Suricata | IDS/IPS avec règles |
| NetworkMiner | Forensics réseau |

### Analyse Système

| Outil | Usage |
|-------|-------|
| Sysmon | Logging avancé Windows |
| Process Monitor | Surveillance en temps réel |
| Process Explorer | Analyse détaillée des processus |
| Autoruns | Vérification de persistence |

### Analyse Mémoire

| Outil | Usage |
|-------|-------|
| Volatility 3 | Forensics mémoire |
| WinDbg | Debugging Windows |
| Process Hacker | Analyse mémoire live |

### Analyse Malware

| Outil | Usage |
|-------|-------|
| YARA | Règles de détection |
| PE-bear | Analyse PE |
| IDA Pro / Ghidra | Reverse engineering |
| x64dbg | Debugging dynamique |

### SIEM / EDR

| Outil | Usage |
|-------|-------|
| Elastic Security | SIEM open source |
| Splunk | Analyse de logs |
| CrowdStrike | EDR commercial |
| Microsoft Defender ATP | EDR Microsoft |

---

## 📊 Indicateurs Résumés

### Hash IOCs

```
MD5:    [À calculer après compilation]
SHA1:   [À calculer après compilation]
SHA256: [À calculer après compilation]
```

### Network IOCs

```
Port:       4444/tcp
Protocol:   TCP raw (not HTTP)
Beacon:     ~5 second interval
Payload:    AES-256-CBC encrypted
```

### File IOCs

```
Filename:   agent.exe (modifiable)
Size:       50-80 KB
Type:       PE32+ executable
Unsigned:   Yes
```

### Registry IOCs

```
Key:    HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value:  WindowsSecurityHealth
Data:   <path to agent.exe>
```

### Behavioral IOCs

```
- cmd.exe spawned with /c flag
- Persistent TCP connection to single IP
- Regular beacon pattern
- Registry Run key modification
- Process enumeration (CreateToolhelp32Snapshot)
- Unsigned executable in user directories
```
