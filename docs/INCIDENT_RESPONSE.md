# 🚨 Guide de Réponse à Incident - ShadowLink

> **Guide pour les équipes de sécurité** : Comment détecter, contenir et éradiquer l'agent ShadowLink.

---

## 📋 Table des matières

1. [Détection et Identification](#-1-détection-et-identification)
2. [Containment (Isolation)](#-2-containment-isolation)
3. [Éradication](#-3-éradication)
4. [Vérification](#-4-vérification-de-léradication)
5. [Forensics](#-5-forensics-investigation-approfondie)
6. [Checklist finale](#-checklist-de-confirmation)
7. [Points d'attention spécifiques](#️-points-dattention-spécifiques-à-shadowlink)

---

## 🔍 1. Détection et Identification

### Identifier le processus

```powershell
# Rechercher les connexions suspectes sur le port 4444
Get-NetTCPConnection -RemotePort 4444
Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 4444 -or $_.LocalPort -eq 4444}

# Lister les processus avec connexions réseau actives
Get-Process | Where-Object {$_.Id -in (Get-NetTCPConnection).OwningProcess} | Select-Object Id, ProcessName, Path

# Chercher des processus suspects (sans fenêtre, connexion active)
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*agent*" -or $_.ExecutablePath -like "*Temp*"}
```

### Vérifier la persistance (registre)

```powershell
# Clés de démarrage utilisateur
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List

# Clés de démarrage machine (admin requis)
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List

# Chercher spécifiquement "ShadowLink" ou "WindowsUpdate" (nom utilisé)
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Where-Object {$_.PSObject.Properties.Name -match "Windows|Shadow|Update"}
```

### Indicateurs de Compromission (IOCs)

| Type | Valeur | Description |
|------|--------|-------------|
| Port | 4444/TCP | Port C2 par défaut |
| Registry | `HKCU\...\Run\WindowsUpdate` | Clé de persistance |
| Network | Connexions TCP sortantes répétées | Tentatives de reconnexion (5s) |
| Behavior | `cmd.exe` spawné par processus inconnu | Exécution de commandes |

---

## 🛑 2. Containment (Isolation)

### Couper la connexion réseau immédiatement

```powershell
# Bloquer le port 4444 via firewall
New-NetFirewallRule -DisplayName "Block C2" -Direction Outbound -RemotePort 4444 -Action Block

# Bloquer aussi en entrée
New-NetFirewallRule -DisplayName "Block C2 Inbound" -Direction Inbound -LocalPort 4444 -Action Block

# Option radicale : désactiver le réseau
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
# ou
Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false
```

### Tuer le processus

```powershell
# Par PID (remplacer 1234 par le PID trouvé)
Stop-Process -Id 1234 -Force

# Par nom si connu
Get-Process | Where-Object {$_.Path -like "*agent*"} | Stop-Process -Force

# Via taskkill (plus agressif)
taskkill /F /IM agent.exe

# Vérifier que le processus est mort
Get-Process agent -ErrorAction SilentlyContinue
```

---

## 🧹 3. Éradication

### Supprimer la persistance

```powershell
# Supprimer les entrées de registre suspectes
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ShadowLink" -ErrorAction SilentlyContinue

# Vérifier les autres clés de persistance
$persistenceKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $persistenceKeys) {
    Write-Host "=== $key ===" -ForegroundColor Yellow
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Format-List
}
```

### Supprimer le binaire

```powershell
# Chercher l'agent dans les emplacements typiques
$searchPaths = @(
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "C:\Windows\Temp",
    "C:\ProgramData"
)

foreach ($path in $searchPaths) {
    Write-Host "Scanning: $path" -ForegroundColor Cyan
    Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object {$_.Length -lt 500KB -and $_.Length -gt 50KB} |
    Select-Object FullName, Length, LastWriteTime, @{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256).Hash}}
}

# Supprimer le fichier identifié
Remove-Item -Path "C:\chemin\vers\agent.exe" -Force
```

### Recherche exhaustive par signature

```powershell
# Rechercher par hash connu (remplacer par le hash réel)
$knownHash = "HASH_SHA256_DE_LAGENT"
Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | 
ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if ($hash -eq $knownHash) {
        Write-Host "FOUND: $($_.FullName)" -ForegroundColor Red
        # Remove-Item $_.FullName -Force  # Décommenter pour supprimer
    }
}
```

---

## ✅ 4. Vérification de l'éradication

### Confirmer l'absence de connexion

```powershell
# Aucune connexion sur 4444
$connections = Get-NetTCPConnection -RemotePort 4444 -ErrorAction SilentlyContinue
if ($connections) {
    Write-Host "⚠️ CONNEXIONS ACTIVES DÉTECTÉES!" -ForegroundColor Red
    $connections
} else {
    Write-Host "✅ Aucune connexion sur port 4444" -ForegroundColor Green
}

# Vérifier toutes les connexions établies vers l'extérieur
Get-NetTCPConnection -State Established | 
Where-Object {$_.RemoteAddress -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"} |
Select-Object LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

### Vérifier le registre

```powershell
# Script de vérification complète
$clean = $true

# Vérifier Run keys
$runValue = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
if ($runValue) {
    Write-Host "⚠️ Clé de persistance encore présente!" -ForegroundColor Red
    $clean = $false
} else {
    Write-Host "✅ Registre clean" -ForegroundColor Green
}

if ($clean) {
    Write-Host "`n✅ SYSTÈME NETTOYÉ" -ForegroundColor Green
}
```

### Scanner avec Windows Defender

```powershell
# Mettre à jour les définitions
Update-MpSignature

# Lancer un scan complet
Start-MpScan -ScanType FullScan

# Vérifier les menaces détectées
Get-MpThreatDetection | Select-Object ThreatID, ActionSuccess, Resources

# Historique des menaces
Get-MpThreat
```

### Test post-redémarrage

```powershell
# Créer un script de vérification post-reboot
$verifyScript = @'
Start-Sleep -Seconds 60  # Attendre que tout démarre
$results = @{
    Port4444 = (Get-NetTCPConnection -RemotePort 4444 -ErrorAction SilentlyContinue).Count
    RegistryKey = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue) -ne $null
    SuspiciousProcess = (Get-Process | Where-Object {$_.Path -like "*agent*"}).Count
}
$results | ConvertTo-Json | Out-File "C:\verify_results.json"
'@

$verifyScript | Out-File "C:\verify_after_reboot.ps1"

# Programmer l'exécution au démarrage
$trigger = New-ScheduledTaskTrigger -AtStartup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\verify_after_reboot.ps1"
Register-ScheduledTask -TaskName "VerifyCleanup" -Trigger $trigger -Action $action -RunLevel Highest

# Redémarrer
Restart-Computer -Force
```

---

## 🔬 5. Forensics (Investigation approfondie)

### Collecter les artefacts AVANT suppression

```powershell
# Créer un dossier d'investigation horodaté
$forensicsPath = "C:\Forensics_ShadowLink_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $forensicsPath -Force

# 1. Copier le binaire malveillant
Copy-Item -Path "C:\path\to\agent.exe" -Destination "$forensicsPath\agent.exe" -ErrorAction SilentlyContinue

# 2. Calculer les hashes
Get-FileHash -Path "$forensicsPath\agent.exe" -Algorithm SHA256 | Out-File "$forensicsPath\hashes.txt"
Get-FileHash -Path "$forensicsPath\agent.exe" -Algorithm MD5 | Out-File "$forensicsPath\hashes.txt" -Append

# 3. Exporter les clés de registre
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "$forensicsPath\run_keys.reg" /y

# 4. Capturer les connexions réseau
Get-NetTCPConnection | Export-Csv "$forensicsPath\tcp_connections.csv" -NoTypeInformation
Get-NetUDPEndpoint | Export-Csv "$forensicsPath\udp_endpoints.csv" -NoTypeInformation

# 5. Exporter la liste des processus
Get-Process | Select-Object Id, ProcessName, Path, StartTime, CPU, WorkingSet64 | 
Export-Csv "$forensicsPath\processes.csv" -NoTypeInformation

# 6. Capturer les services
Get-Service | Export-Csv "$forensicsPath\services.csv" -NoTypeInformation

# 7. Événements de sécurité récents
Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Csv "$forensicsPath\security_events.csv" -NoTypeInformation

# 8. Événements Sysmon si disponible
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue | 
Export-Csv "$forensicsPath\sysmon_events.csv" -NoTypeInformation

Write-Host "Artefacts collectés dans: $forensicsPath" -ForegroundColor Green
```

### Analyse du binaire

```powershell
# Extraire les strings (si Sysinternals disponible)
& "C:\Tools\Sysinternals\strings.exe" -a "$forensicsPath\agent.exe" > "$forensicsPath\strings.txt"

# Informations PE
$exe = [System.IO.File]::ReadAllBytes("$forensicsPath\agent.exe")
$pe = [System.BitConverter]::ToString($exe[0..1])
Write-Host "PE Signature: $pe" # Devrait être 4D-5A (MZ)

# Compiler timestamp
# À analyser avec des outils comme PEStudio, DIE, ou pestudio
```

### Timeline d'activité

```powershell
# Créer une timeline des fichiers récemment modifiés
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
Select-Object FullName, LastWriteTime, Length |
Sort-Object LastWriteTime -Descending |
Export-Csv "$forensicsPath\recent_files.csv" -NoTypeInformation
```

---

## 📋 Checklist de confirmation

| # | Vérification | Commande | Résultat attendu |
|---|--------------|----------|------------------|
| 1 | Processus tué | `Get-Process agent` | Erreur "Cannot find" |
| 2 | Connexion coupée | `Get-NetTCPConnection -RemotePort 4444` | Aucun résultat |
| 3 | Registre nettoyé | `Get-ItemProperty HKCU:\...\Run` | Pas d'entrée suspecte |
| 4 | Binaire supprimé | `Test-Path C:\path\agent.exe` | `False` |
| 5 | Firewall configuré | `Get-NetFirewallRule -DisplayName "Block C2"` | Règle présente |
| 6 | Scan AV clean | `Get-MpThreatDetection` | Aucune menace |
| 7 | Post-reboot clean | Toutes vérifications après redémarrage | Tout OK |

---

## ⚠️ Points d'attention spécifiques à ShadowLink

### Comportements connus

| Comportement | Détail | Impact |
|--------------|--------|--------|
| **Reconnexion** | Tente de se reconnecter toutes les 5 secondes | Couper le réseau AVANT de tuer le processus |
| **Self-delete** | Peut s'auto-supprimer si détecté | Capturer le binaire immédiatement |
| **Anti-debug** | Vérifie `IsDebuggerPresent` | Éviter de débugger directement |
| **Anti-VM** | Détecte VMware/VirtualBox | Analyse sur machine physique si possible |
| **Delayed start** | Peut attendre avant de s'activer | Surveiller pendant plusieurs minutes |

### Ce que ShadowLink N'utilise PAS

- ❌ Services Windows
- ❌ Tâches planifiées
- ❌ WMI Event Subscriptions
- ❌ DLL Hijacking
- ❌ Rootkit / drivers
- ❌ Injection de processus

> Cela simplifie le nettoyage : seules les clés de registre `Run` sont à vérifier.

---

## 🔄 Script de nettoyage automatisé

```powershell
# ShadowLink_Cleanup.ps1
# Script de nettoyage automatisé

param(
    [switch]$Force,
    [switch]$CollectForensics
)

Write-Host "=== ShadowLink Cleanup Script ===" -ForegroundColor Cyan

# 1. Collecter les artefacts si demandé
if ($CollectForensics) {
    $forensicsPath = "C:\Forensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $forensicsPath -Force | Out-Null
    Write-Host "[*] Collecting forensics to $forensicsPath" -ForegroundColor Yellow
    
    Get-NetTCPConnection | Export-Csv "$forensicsPath\connections.csv" -NoTypeInformation
    Get-Process | Export-Csv "$forensicsPath\processes.csv" -NoTypeInformation
    reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "$forensicsPath\run.reg" /y 2>$null
}

# 2. Bloquer le port C2
Write-Host "[*] Blocking port 4444..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "Block ShadowLink C2" -Direction Outbound -RemotePort 4444 -Action Block -ErrorAction SilentlyContinue | Out-Null

# 3. Trouver et tuer le processus
Write-Host "[*] Finding malicious processes..." -ForegroundColor Yellow
$suspects = Get-NetTCPConnection -RemotePort 4444 -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty OwningProcess -Unique

foreach ($pid in $suspects) {
    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
    Write-Host "[!] Killing process: $($proc.ProcessName) (PID: $pid)" -ForegroundColor Red
    Stop-Process -Id $pid -Force
}

# 4. Supprimer la persistance
Write-Host "[*] Removing persistence..." -ForegroundColor Yellow
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ShadowLink" -ErrorAction SilentlyContinue

# 5. Vérification
Write-Host "`n=== Verification ===" -ForegroundColor Cyan
$port4444 = Get-NetTCPConnection -RemotePort 4444 -ErrorAction SilentlyContinue
$regKey = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue

if (-not $port4444 -and -not $regKey) {
    Write-Host "✅ Cleanup successful!" -ForegroundColor Green
} else {
    Write-Host "⚠️ Manual intervention may be required" -ForegroundColor Red
}

Write-Host "`n[!] Recommend: Reboot and verify again" -ForegroundColor Yellow
```

---

## 📚 Références

- [MITRE ATT&CK - Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/)
- [Windows Event Log Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)

---

*Document créé pour ShadowLink - Projet éducatif uniquement*
