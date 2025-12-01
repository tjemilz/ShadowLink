# 🛡️ ShadowLink - Guide de Mitigation et Contremesures

Ce document fournit des recommandations pour se protéger contre ShadowLink et des menaces similaires (C2, RAT, Implants).

---

## 📋 Table des Matières

1. [Prévention](#prévention)
2. [Détection en Temps Réel](#détection-en-temps-réel)
3. [Réponse à Incident](#réponse-à-incident)
4. [Remédiation](#remédiation)
5. [Hardening Système](#hardening-système)
6. [Configuration Réseau](#configuration-réseau)
7. [Bonnes Pratiques](#bonnes-pratiques)

---

## 🔒 Prévention

### 1. Application Whitelisting

Empêcher l'exécution de binaires non autorisés:

```powershell
# Windows Defender Application Control (WDAC)
# Créer une politique de base
New-CIPolicy -FilePath "C:\Policies\BasePolicy.xml" -Level Publisher -UserPEs

# Déployer la politique
ConvertFrom-CIPolicy -XmlFilePath "C:\Policies\BasePolicy.xml" `
                     -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
```

**Alternatives:**
- AppLocker (Windows Pro/Enterprise)
- Carbon Black App Control
- Airlock Digital

### 2. Blocage des Ports Non-Standards

```powershell
# Bloquer le port 4444 sortant
New-NetFirewallRule -DisplayName "Block C2 Port 4444" `
    -Direction Outbound `
    -LocalPort 4444 `
    -Protocol TCP `
    -Action Block

# Bloquer tous les ports non-essentiels
$allowedPorts = @(80, 443, 53, 22, 21)
New-NetFirewallRule -DisplayName "Block Non-Standard Ports" `
    -Direction Outbound `
    -LocalPort Any `
    -RemotePort $allowedPorts `
    -Action Allow

# Par défaut bloquer tout le reste
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block
```

### 3. Signature de Code

Exiger que tous les exécutables soient signés:

```powershell
# Politique d'exécution PowerShell
Set-ExecutionPolicy AllSigned

# Windows Defender Application Control
# Autoriser uniquement les binaires signés Microsoft
```

### 4. Endpoint Protection

| Solution | Configuration Recommandée |
|----------|---------------------------|
| Windows Defender | Cloud protection ON, Real-time ON, PUA ON |
| CrowdStrike | Prevention mode, ML detection HIGH |
| Carbon Black | Block unknown executables |
| SentinelOne | Protect mode, Deep Visibility ON |

### 5. Registry Protection

```powershell
# Monitorer les clés Run
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Créer un audit rule
$acl = Get-Acl $runKey
$auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
    "Everyone",
    "SetValue",
    "None",
    "None", 
    "Success"
)
$acl.AddAuditRule($auditRule)
Set-Acl $runKey $acl

# Activer l'audit
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

---

## 🔔 Détection en Temps Réel

### 1. SIEM Rules

#### Splunk

```spl
# Détection de connexion au port 4444
index=network sourcetype=firewall 
| where dest_port=4444 
| stats count by src_ip, dest_ip, dest_port
| where count > 5

# Détection de persistence
index=windows sourcetype=sysmon EventCode=13
| where TargetObject LIKE "%CurrentVersion\\Run%"
| table _time, Image, TargetObject, Details
```

#### Elastic SIEM

```json
{
    "rule": {
        "name": "Suspicious Registry Run Key",
        "query": "registry.path:*CurrentVersion\\Run* AND event.action:modification",
        "risk_score": 75,
        "severity": "high"
    }
}
```

### 2. EDR Alerts

#### CrowdStrike Falcon

```
# Custom IOA (Indicator of Attack)
Process Creation:
- CommandLine contains "cmd.exe /c"
- ParentImage not in [known_good_list]
- NetworkConnection to non-standard port
```

#### Microsoft Defender for Endpoint

```kql
// KQL Query pour détection
DeviceProcessEvents
| where ProcessCommandLine contains "cmd.exe /c"
| where InitiatingProcessFileName !in ("explorer.exe", "services.exe")
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort == 4444
) on DeviceId
```

### 3. Network Monitoring

```bash
# Suricata rule
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Potential C2 Beacon - Regular Interval";
    flow:to_server,established;
    flowbits:set,beacon_detected;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:1000010;
)
```

### 4. Sysmon Alerting

```xml
<!-- Configuration Sysmon haute verbosité pour C2 -->
<Sysmon schemaversion="4.50">
    <HashAlgorithms>SHA256,MD5,IMPHASH</HashAlgorithms>
    <EventFiltering>
        <ProcessCreate onmatch="include">
            <Image condition="end with">cmd.exe</Image>
            <CommandLine condition="contains">/c</CommandLine>
        </ProcessCreate>
        <NetworkConnect onmatch="include">
            <DestinationPort condition="is not">80</DestinationPort>
            <DestinationPort condition="is not">443</DestinationPort>
        </NetworkConnect>
        <RegistryEvent onmatch="include">
            <TargetObject condition="contains">Run</TargetObject>
        </RegistryEvent>
    </EventFiltering>
</Sysmon>
```

---

## 🚨 Réponse à Incident

### Phase 1: Identification

```powershell
# 1. Identifier le processus
$suspectProcess = Get-Process | Where-Object {
    $_.MainModule.FileName -notlike "C:\Windows\*" -and
    $_.MainModule.FileName -notlike "C:\Program Files*"
}

# 2. Capturer les connexions
Get-NetTCPConnection | Where-Object {
    $_.OwningProcess -eq $suspectProcess.Id
} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort

# 3. Dumper la mémoire du processus
.\procdump.exe -ma $suspectProcess.Id C:\Investigation\memory.dmp
```

### Phase 2: Containment

```powershell
# 1. Isoler la machine du réseau (garder accès local admin)
Disable-NetAdapter -Name "Ethernet" -Confirm:$false

# Alternative: Bloquer tout le trafic sortant sauf investigation
New-NetFirewallRule -DisplayName "Block All Outbound" `
    -Direction Outbound -Action Block

# 2. Tuer le processus malveillant
Stop-Process -Id $suspectProcess.Id -Force

# 3. Préserver les preuves
Copy-Item $suspectProcess.MainModule.FileName C:\Investigation\
Copy-Item C:\Windows\Prefetch\*.pf C:\Investigation\Prefetch\
```

### Phase 3: Analysis

```powershell
# 1. Timeline analysis
Get-WinEvent -FilterHashtable @{
    LogName = 'Security','System','Application'
    StartTime = (Get-Date).AddDays(-7)
} | Export-Csv C:\Investigation\events.csv

# 2. Registry analysis
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\Investigation\run_keys.reg

# 3. Scheduled tasks
Get-ScheduledTask | Export-Csv C:\Investigation\scheduled_tasks.csv

# 4. Services
Get-Service | Export-Csv C:\Investigation\services.csv
```

### Phase 4: Eradication

Voir section [Remédiation](#remédiation).

### Phase 5: Recovery

```powershell
# 1. Restaurer le réseau après nettoyage
Enable-NetAdapter -Name "Ethernet"

# 2. Réactiver les règles firewall normales
Remove-NetFirewallRule -DisplayName "Block All Outbound"

# 3. Vérifier l'intégrité du système
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

# 4. Mettre à jour les signatures AV
Update-MpSignature
```

---

## 🧹 Remédiation

### Suppression de l'Agent

```powershell
# 1. Identifier le binaire
$agentPath = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run").WindowsSecurityHealth

# 2. Tuer le processus
$proc = Get-Process | Where-Object { $_.MainModule.FileName -eq $agentPath }
if ($proc) { Stop-Process -Id $proc.Id -Force }

# 3. Supprimer la clé de registre
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                    -Name "WindowsSecurityHealth" -ErrorAction SilentlyContinue

# 4. Supprimer le binaire
Remove-Item $agentPath -Force -ErrorAction SilentlyContinue

# 5. Vérifier autres emplacements de persistence
$persistenceLocations = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Startup"
)

foreach ($loc in $persistenceLocations) {
    Get-ItemProperty -Path $loc -ErrorAction SilentlyContinue | 
        ForEach-Object { $_.PSObject.Properties } | 
        Where-Object { $_.Value -like "*agent*" -or $_.Value -like "*suspicious*" }
}
```

### Script de Nettoyage Automatisé

```powershell
# cleanup_shadowlink.ps1
param(
    [switch]$DryRun = $false
)

$findings = @()

# Check registry
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $regPaths) {
    $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($props.WindowsSecurityHealth) {
        $findings += [PSCustomObject]@{
            Type = "Registry"
            Path = $path
            Value = "WindowsSecurityHealth"
            Data = $props.WindowsSecurityHealth
        }
        
        if (-not $DryRun) {
            Remove-ItemProperty -Path $path -Name "WindowsSecurityHealth" -Force
            Write-Host "[+] Removed: $path\WindowsSecurityHealth" -ForegroundColor Green
        }
    }
}

# Check for suspicious processes
$procs = Get-Process | Where-Object {
    $_.MainModule.FileName -like "*agent*" -or
    $_.MainModule.Company -eq $null
}

foreach ($proc in $procs) {
    $connections = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
    $c2Connection = $connections | Where-Object { $_.RemotePort -eq 4444 }
    
    if ($c2Connection) {
        $findings += [PSCustomObject]@{
            Type = "Process"
            Path = $proc.MainModule.FileName
            PID = $proc.Id
            Connection = "$($c2Connection.RemoteAddress):$($c2Connection.RemotePort)"
        }
        
        if (-not $DryRun) {
            Stop-Process -Id $proc.Id -Force
            Remove-Item $proc.MainModule.FileName -Force
            Write-Host "[+] Killed and removed: $($proc.MainModule.FileName)" -ForegroundColor Green
        }
    }
}

# Report findings
if ($DryRun) {
    Write-Host "`n[*] DRY RUN - No changes made" -ForegroundColor Yellow
}

$findings | Format-Table -AutoSize
```

---

## 🔐 Hardening Système

### Windows Hardening

```powershell
# 1. Désactiver PowerShell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# 2. Activer Credential Guard
# Via Group Policy ou:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1

# 3. Activer LAPS (Local Admin Password Solution)
# Télécharger et installer depuis Microsoft

# 4. Désactiver LLMNR et NetBIOS
# GPO: Computer Configuration > Administrative Templates > Network > DNS Client
# Turn off multicast name resolution = Enabled

# 5. Activer ASR (Attack Surface Reduction)
Set-MpPreference -AttackSurfaceReductionRules_Ids @(
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", # Block executable content from email
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block Office applications from creating child processes
    "3B576869-A4EC-4529-8536-B80A7769E899", # Block Office applications from creating executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Block Office applications from injecting code into other processes
    "D3E037E1-3EB8-44C8-A917-57927947596D", # Block JavaScript or VBScript from launching downloaded executable content
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Block execution of potentially obfuscated scripts
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"  # Block Win32 API calls from Office macros
) -AttackSurfaceReductionRules_Actions @(1,1,1,1,1,1,1)

# 6. Activer Windows Defender Tamper Protection
Set-MpPreference -DisableTamperProtection $false
```

### Network Segmentation

```
                    ┌─────────────────┐
                    │    Internet     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │    Firewall     │
                    │   (Block 4444)  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
    │   DMZ   │        │   LAN   │        │  ADMIN  │
    │         │        │         │        │         │
    │ - Web   │        │ - Users │        │ - Mgmt  │
    │ - Mail  │        │ - Print │        │ - SIEM  │
    └─────────┘        └─────────┘        └─────────┘
```

### Zero Trust Architecture

1. **Verify explicitly** - Toujours authentifier et autoriser
2. **Least privilege access** - Accès minimal requis
3. **Assume breach** - Minimiser le blast radius

```
Implémentation:
- MFA obligatoire
- Micro-segmentation réseau
- Just-in-time access (PIM/PAM)
- Continuous verification
- Encryption everywhere
```

---

## 🌐 Configuration Réseau

### Firewall Egress Rules

```powershell
# Stratégie: Deny by default, allow by exception

# 1. Bloquer tout le trafic sortant
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

# 2. Autoriser uniquement le nécessaire
$allowedRules = @(
    @{Name="Allow HTTP"; Port=80; Protocol="TCP"},
    @{Name="Allow HTTPS"; Port=443; Protocol="TCP"},
    @{Name="Allow DNS"; Port=53; Protocol="UDP"},
    @{Name="Allow NTP"; Port=123; Protocol="UDP"}
)

foreach ($rule in $allowedRules) {
    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Outbound `
        -LocalPort Any `
        -RemotePort $rule.Port `
        -Protocol $rule.Protocol `
        -Action Allow
}

# 3. Bloquer explicitement les ports C2 connus
$c2Ports = @(4444, 8080, 8443, 1337, 31337)
foreach ($port in $c2Ports) {
    New-NetFirewallRule -DisplayName "Block C2 Port $port" `
        -Direction Outbound `
        -RemotePort $port `
        -Protocol TCP `
        -Action Block
}
```

### DNS Filtering

```
Options:
1. Pi-hole / AdGuard Home (on-premise)
2. Cisco Umbrella (cloud)
3. Cloudflare Gateway (cloud)
4. NextDNS (cloud)

Configuration recommandée:
- Block newly registered domains
- Block DGA (Domain Generation Algorithm) domains
- Block known C2 domains
- Log all DNS queries
```

### Network Monitoring

```yaml
# Zeek configuration pour détecter C2
# local.zeek

@load base/protocols/conn
@load base/protocols/dns
@load policy/protocols/conn/known-hosts

redef Site::local_nets = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };

event connection_established(c: connection)
{
    if (c$id$resp_p in {4444/tcp, 8080/tcp, 8443/tcp})
    {
        NOTICE([
            $note=Potential_C2_Connection,
            $msg=fmt("Suspicious outbound connection to port %s", c$id$resp_p),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h)
        ]);
    }
}
```

---

## ✅ Bonnes Pratiques

### Checklist Sécurité

#### Endpoints
- [ ] EDR/XDR déployé et actif
- [ ] Application whitelisting configuré
- [ ] PowerShell Constrained Language Mode
- [ ] Windows Defender ASR rules activées
- [ ] LAPS pour les comptes admin locaux
- [ ] BitLocker activé
- [ ] Credential Guard activé

#### Réseau
- [ ] Firewall egress strict
- [ ] DNS filtering actif
- [ ] Network segmentation
- [ ] IDS/IPS déployé
- [ ] SSL/TLS inspection
- [ ] Proxy pour tout le trafic web

#### Monitoring
- [ ] SIEM centralisé
- [ ] Logs collectés (Windows, Firewall, DNS)
- [ ] Sysmon déployé
- [ ] Alertes configurées
- [ ] Threat hunting régulier

#### Processus
- [ ] Incident Response Plan documenté
- [ ] Exercices de réponse réguliers
- [ ] Threat Intelligence intégrée
- [ ] Vulnerability Management
- [ ] Patch Management

### Matrice de Contrôles MITRE ATT&CK

| Technique | ID | Mitigation |
|-----------|-----|------------|
| Command and Scripting Interpreter | T1059 | Application Whitelisting, Script Block Logging |
| Registry Run Keys | T1547.001 | Registry auditing, GPO restrictions |
| Exfiltration Over C2 Channel | T1041 | Network monitoring, DLP |
| Encrypted Channel | T1573 | SSL inspection, Network monitoring |
| Process Discovery | T1057 | Endpoint monitoring |
| System Information Discovery | T1082 | Endpoint monitoring |

### Formation et Sensibilisation

1. **Phishing awareness** - Principal vecteur d'entrée
2. **Reporting procedures** - Comment signaler un incident
3. **Clean desk policy** - Sécurité physique
4. **Password hygiene** - Gestionnaire de mots de passe, MFA
5. **Social engineering** - Reconnaissance des tentatives

---

## 📚 Ressources Supplémentaires

### Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

### Outils
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Tests de détection
- [CALDERA](https://github.com/mitre/caldera) - Adversary emulation
- [Sigma](https://github.com/SigmaHQ/sigma) - Règles de détection génériques

### Lectures
- [The Threat Hunter Playbook](https://threathunterplaybook.com/)
- [Windows Security Monitoring](https://www.ultimatewindowssecurity.com/)
- [SANS Reading Room](https://www.sans.org/reading-room/)
