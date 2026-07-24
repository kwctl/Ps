<#
.SYNOPSIS
    Windows Threat Audit

.DESCRIPTION
    Sammelt sicherheitsrelevante Informationen eines Windows Systems,
    markiert verdächtige Hinweise und schreibt einen Bericht.
    Das Skript löscht keine Dateien und deaktiviert keine Komponenten.

.REQUIREMENTS
    Windows 10 oder Windows 11
    PowerShell mit Administratorrechten ist optional, aber empfohlen.
#>

[CmdletBinding()]
param(
    [ValidateSet("None", "Quick", "Full")]
    [string]$ScanType = "None",

    [ValidateRange(1, 365)]
    [int]$LookbackDays = 7,

    [string]$OutputRoot = "$env:USERPROFILE\Desktop\WindowsThreatAudit",

    [switch]$SkipAdminCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Test-IsWindows {
    return [System.Environment]::OSVersion.Platform -eq
        [System.PlatformID]::Win32NT
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $principal = [Security.Principal.WindowsPrincipal]::new(
        $identity
    )

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Save-Json {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Data
    )

    $path = Join-Path $script:ReportDirectory "$Name.json"

    $Data |
        ConvertTo-Json -Depth 10 |
        Set-Content -Path $path -Encoding utf8
}

function Add-Finding {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Low", "Medium", "High", "Critical")]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Description,

        [string]$Evidence = ""
    )

    $script:Findings.Add(
        [PSCustomObject]@{
            Timestamp   = Get-Date
            Severity    = $Severity
            Category    = $Category
            Description = $Description
            Evidence    = $Evidence
        }
    )
}

function Test-SuspiciousLocation {
    param(
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $patterns = @(
        "\\AppData\\Local\\Temp\\",
        "\\Windows\\Temp\\",
        "\\Users\\Public\\",
        "\\Downloads\\",
        "\\Recycle\.Bin\\"
    )

    foreach ($pattern in $patterns) {
        if ($Path -match $pattern) {
            return $true
        }
    }

    return $false
}

function Test-SuspiciousCommand {
    param(
        [AllowNull()]
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    $patterns = @(
        "EncodedCommand",
        "FromBase64String",
        "DownloadString",
        "Invoke-Expression",
        "\biex\b",
        "mshta(\.exe)?\s+https?://",
        "regsvr32.*https?://",
        "rundll32.*https?://",
        "powershell.*-WindowStyle\s+Hidden"
    )

    foreach ($pattern in $patterns) {
        if ($CommandLine -match $pattern) {
            return $true
        }
    }

    return $false
}

if (-not (Test-IsWindows)) {
    throw "Dieses Skript muss auf Windows ausgeführt werden."
}

if (Test-IsAdministrator) {
    Write-Info "Administratorrechte: vorhanden."
}
else {
    if ($SkipAdminCheck) {
        Write-Warning "Administratorrechte fehlen. Das Skript läuft weiter, weil -SkipAdminCheck gesetzt wurde."
    }
    else {
        Write-Warning "Administratorrechte fehlen. Einige Prüfungen sind eingeschränkt."
    }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:ReportDirectory = Join-Path $OutputRoot $timestamp
$script:Findings = [System.Collections.Generic.List[object]]::new()

New-Item `
    -Path $script:ReportDirectory `
    -ItemType Directory `
    -Force |
    Out-Null

Write-Host "Berichtsverzeichnis: $script:ReportDirectory"

# ------------------------------------------------------------
# 1. Systeminformationen
# ------------------------------------------------------------

Write-Host "[1/10] Systeminformationen"

$computerSystem = Get-CimInstance Win32_ComputerSystem
$operatingSystem = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS

$systemInformation = [PSCustomObject]@{
    ComputerName       = $env:COMPUTERNAME
    CurrentUser        = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Manufacturer       = $computerSystem.Manufacturer
    Model              = $computerSystem.Model
    OperatingSystem    = $operatingSystem.Caption
    Version            = $operatingSystem.Version
    BuildNumber        = $operatingSystem.BuildNumber
    LastBootTime       = $operatingSystem.LastBootUpTime
    BIOSVersion        = $bios.SMBIOSBIOSVersion
    PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
    CollectionTime     = Get-Date
}

Save-Json -Name "SystemInformation" -Data $systemInformation

# ------------------------------------------------------------
# 2. Microsoft Defender
# ------------------------------------------------------------

Write-Host "[2/10] Microsoft Defender"

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    $defenderStatus = Get-MpComputerStatus
    Save-Json -Name "DefenderStatus" -Data $defenderStatus

    if (-not $defenderStatus.AntivirusEnabled) {
        Add-Finding `
            -Severity "Critical" `
            -Category "Defender" `
            -Description "Microsoft Defender Antivirus ist deaktiviert."
    }

    if (-not $defenderStatus.RealTimeProtectionEnabled) {
        Add-Finding `
            -Severity "High" `
            -Category "Defender" `
            -Description "Der Defender Echtzeitschutz ist deaktiviert."
    }

    if ($defenderStatus.AntivirusSignatureLastUpdated) {
        $signatureAge = (Get-Date) -
            $defenderStatus.AntivirusSignatureLastUpdated

        if ($signatureAge.TotalDays -gt 3) {
            Add-Finding `
                -Severity "Medium" `
                -Category "Defender" `
                -Description "Die Defender Signaturen sind älter als drei Tage." `
                -Evidence $defenderStatus.AntivirusSignatureLastUpdated
        }
    }

    $defenderPreferences = Get-MpPreference

    $exclusions = [PSCustomObject]@{
        ExclusionPath      = $defenderPreferences.ExclusionPath
        ExclusionProcess   = $defenderPreferences.ExclusionProcess
        ExclusionExtension = $defenderPreferences.ExclusionExtension
        ExclusionIpAddress = $defenderPreferences.ExclusionIpAddress
    }

    Save-Json -Name "DefenderExclusions" -Data $exclusions

    $allExclusions = @(
        $defenderPreferences.ExclusionPath
        $defenderPreferences.ExclusionProcess
        $defenderPreferences.ExclusionExtension
        $defenderPreferences.ExclusionIpAddress
    ) | Where-Object { $_ }

    if ($allExclusions.Count -gt 0) {
        Add-Finding `
            -Severity "Medium" `
            -Category "Defender" `
            -Description "Defender Ausnahmen wurden gefunden und müssen geprüft werden." `
            -Evidence ($allExclusions -join "; ")
    }

    $threatDetections = Get-MpThreatDetection -ErrorAction SilentlyContinue
    Save-Json -Name "DefenderThreatDetections" -Data $threatDetections

    if ($threatDetections) {
        Add-Finding `
            -Severity "High" `
            -Category "Defender" `
            -Description "Defender enthält erkannte Bedrohungen in seinem Verlauf." `
            -Evidence "DefenderThreatDetections.json prüfen"
    }

    if ($ScanType -ne "None") {
        Write-Host "Defender Signaturen werden aktualisiert."
        try {
            Update-MpSignature
        }
        catch {
            Add-Finding `
                -Severity "Info" `
                -Category "Defender" `
                -Description "Die Defender-Signaturen konnten nicht aktualisiert werden." `
                -Evidence $_.Exception.Message
        }

        Write-Host "Defender Scan wird gestartet: $ScanType"

        try {
            Start-MpScan -ScanType "${ScanType}Scan"
        }
        catch {
            Add-Finding `
                -Severity "Info" `
                -Category "Defender" `
                -Description "Der Defender-Scan konnte nicht gestartet werden." `
                -Evidence $_.Exception.Message
        }
    }
}
else {
    Add-Finding `
        -Severity "Critical" `
        -Category "Defender" `
        -Description "Die Microsoft Defender PowerShell Cmdlets sind nicht verfügbar."
}

# ------------------------------------------------------------
# 3. Laufende Prozesse
# ------------------------------------------------------------

Write-Host "[3/10] Laufende Prozesse"

$processResults = foreach ($process in Get-CimInstance Win32_Process) {
    $path = $process.ExecutablePath
    $signatureStatus = $null
    $signer = $null
    $sha256 = $null
    $riskScore = 0
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($path -and (Test-Path -LiteralPath $path)) {
        try {
            $signature = Get-AuthenticodeSignature `
                -FilePath $path `
                -ErrorAction Stop

            $signatureStatus = $signature.Status.ToString()
            $signer = $signature.SignerCertificate.Subject

            if ($signature.Status -ne "Valid") {
                $riskScore += 25
                $reasons.Add("Keine gültige digitale Signatur")
            }
        }
        catch {
            $signatureStatus = "CheckFailed"
        }

        try {
            $sha256 = (
                Get-FileHash `
                    -LiteralPath $path `
                    -Algorithm SHA256 `
                    -ErrorAction Stop
            ).Hash
        }
        catch {
            $sha256 = $null
        }

        if (Test-SuspiciousLocation -Path $path) {
            $riskScore += 30
            $reasons.Add("Ausführung aus einem ungewöhnlichen Verzeichnis")
        }
    }

    if (Test-SuspiciousCommand -CommandLine $process.CommandLine) {
        $riskScore += 40
        $reasons.Add("Verdächtiges Kommandozeilenmuster")
    }

    $result = [PSCustomObject]@{
        ProcessId       = $process.ProcessId
        ParentProcessId = $process.ParentProcessId
        Name            = $process.Name
        Path            = $path
        CommandLine     = $process.CommandLine
        SignatureStatus = $signatureStatus
        Signer           = $signer
        SHA256           = $sha256
        RiskScore        = $riskScore
        Reasons          = $reasons -join "; "
    }

    if ($riskScore -ge 50) {
        Add-Finding `
            -Severity "High" `
            -Category "Process" `
            -Description "Verdächtiger laufender Prozess: $($process.Name)" `
            -Evidence "$path | $($reasons -join '; ')"
    }
    elseif ($riskScore -ge 30) {
        Add-Finding `
            -Severity "Medium" `
            -Category "Process" `
            -Description "Prüfenswerter laufender Prozess: $($process.Name)" `
            -Evidence "$path | $($reasons -join '; ')"
    }

    $result
}

Save-Json -Name "Processes" -Data $processResults

# ------------------------------------------------------------
# 4. Netzwerkverbindungen
# ------------------------------------------------------------

Write-Host "[4/10] Netzwerkverbindungen"

$processLookup = @{}

foreach ($process in $processResults) {
    $processLookup[[int]$process.ProcessId] = $process
}

$networkConnections = @()

if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $networkConnections = foreach (
        $connection in Get-NetTCPConnection -ErrorAction SilentlyContinue
    ) {
        $process = $processLookup[[int]$connection.OwningProcess]

        [PSCustomObject]@{
            State         = $connection.State
            LocalAddress  = $connection.LocalAddress
            LocalPort     = $connection.LocalPort
            RemoteAddress = $connection.RemoteAddress
            RemotePort    = $connection.RemotePort
            ProcessId     = $connection.OwningProcess
            ProcessName   = $process.Name
            ProcessPath   = $process.Path
            ProcessRisk   = $process.RiskScore
        }
    }
}
else {
    Add-Finding `
        -Severity "Info" `
        -Category "Network" `
        -Description "Get-NetTCPConnection ist auf diesem System nicht verfügbar." 
}

Save-Json -Name "NetworkConnections" -Data $networkConnections

# ------------------------------------------------------------
# 5. Autostart
# ------------------------------------------------------------

Write-Host "[5/10] Autostart Einträge"

$startupEntries = Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User

Save-Json -Name "StartupEntries" -Data $startupEntries

foreach ($entry in $startupEntries) {
    if (
        (Test-SuspiciousLocation -Path $entry.Command) -or
        (Test-SuspiciousCommand -CommandLine $entry.Command)
    ) {
        Add-Finding `
            -Severity "High" `
            -Category "Startup" `
            -Description "Verdächtiger Autostart Eintrag: $($entry.Name)" `
            -Evidence $entry.Command
    }
}

# ------------------------------------------------------------
# 6. Geplante Aufgaben
# ------------------------------------------------------------

Write-Host "[6/10] Geplante Aufgaben"

$scheduledTasks = @()

if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $scheduledTasks = foreach ($task in Get-ScheduledTask) {
        foreach ($action in $task.Actions) {
            $command = "$($action.Execute) $($action.Arguments)".Trim()

            if (
                (Test-SuspiciousLocation -Path $command) -or
                (Test-SuspiciousCommand -CommandLine $command)
            ) {
                Add-Finding `
                    -Severity "High" `
                    -Category "ScheduledTask" `
                    -Description "Verdächtige geplante Aufgabe: $($task.TaskName)" `
                    -Evidence $command
            }

            [PSCustomObject]@{
                TaskName  = $task.TaskName
                TaskPath  = $task.TaskPath
                State     = $task.State
                Execute   = $action.Execute
                Arguments = $action.Arguments
                UserId    = $task.Principal.UserId
                RunLevel  = $task.Principal.RunLevel
            }
        }
    }
}
else {
    Add-Finding `
        -Severity "Info" `
        -Category "ScheduledTask" `
        -Description "Get-ScheduledTask ist auf diesem System nicht verfügbar." 
}

Save-Json -Name "ScheduledTasks" -Data $scheduledTasks

# ------------------------------------------------------------
# 7. Windows Dienste
# ------------------------------------------------------------

Write-Host "[7/10] Windows Dienste"

$services = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName

Save-Json -Name "Services" -Data $services

foreach ($service in $services) {
    if (Test-SuspiciousLocation -Path $service.PathName) {
        Add-Finding `
            -Severity "High" `
            -Category "Service" `
            -Description "Dienst startet aus einem ungewöhnlichen Verzeichnis: $($service.Name)" `
            -Evidence $service.PathName
    }
}

# ------------------------------------------------------------
# 8. Lokale Benutzer und Administratoren
# ------------------------------------------------------------

Write-Host "[8/10] Lokale Benutzerkonten"

if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    $localUsers = Get-LocalUser |
        Select-Object Name, Enabled, LastLogon, PasswordRequired, SID

    Save-Json -Name "LocalUsers" -Data $localUsers

    try {
        $administratorsGroup = Get-LocalGroup -SID "S-1-5-32-544"

        $localAdministrators = Get-LocalGroupMember `
            -Group $administratorsGroup.Name

        Save-Json `
            -Name "LocalAdministrators" `
            -Data $localAdministrators
    }
    catch {
        Add-Finding `
            -Severity "Info" `
            -Category "Accounts" `
            -Description "Die lokale Administratorgruppe konnte nicht vollständig gelesen werden." `
            -Evidence $_.Exception.Message
    }
}

# ------------------------------------------------------------
# 9. Defender Ereignisse
# ------------------------------------------------------------

Write-Host "[9/10] Defender Ereignisprotokoll"

$startTime = (Get-Date).AddDays(-$LookbackDays)
$defenderLog = "Microsoft-Windows-Windows Defender/Operational"

try {
    $defenderEvents = Get-WinEvent -FilterHashtable @{
        LogName   = $defenderLog
        StartTime = $startTime
    } -ErrorAction Stop |
    Where-Object {
        $_.Id -in @(1116, 1117, 5001, 5007, 5010)
    } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message

    Save-Json -Name "DefenderEvents" -Data $defenderEvents

    foreach ($event in $defenderEvents) {
        $severity = switch ($event.Id) {
            1116 { "High" }
            1117 { "High" }
            5001 { "High" }
            5010 { "High" }
            5007 { "Medium" }
            default { "Info" }
        }

        Add-Finding `
            -Severity $severity `
            -Category "DefenderEvent" `
            -Description "Defender Ereignis $($event.Id) wurde gefunden." `
            -Evidence "$($event.TimeCreated): $($event.Message)"
    }
}
catch {
    Add-Finding `
        -Severity "Info" `
        -Category "EventLog" `
        -Description "Das Defender Ereignisprotokoll konnte nicht gelesen werden." `
        -Evidence $_.Exception.Message
}

# ------------------------------------------------------------
# 10. Bericht
# ------------------------------------------------------------

Write-Host "[10/10] Bericht wird erstellt"

$severityOrder = @{
    Critical = 1
    High     = 2
    Medium   = 3
    Low      = 4
    Info     = 5
}

$sortedFindings = $script:Findings |
    Sort-Object {
        $severityOrder[$_.Severity]
    }, Category

$sortedFindings |
    Export-Csv `
        -Path (Join-Path $script:ReportDirectory "Findings.csv") `
        -NoTypeInformation `
        -Encoding utf8

Save-Json -Name "Findings" -Data $sortedFindings

$summary = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    ScanType     = $ScanType
    Collection   = Get-Date
    Findings     = @{
        Critical = @($sortedFindings |
            Where-Object Severity -eq "Critical").Count
        High = @($sortedFindings |
            Where-Object Severity -eq "High").Count
        Medium = @($sortedFindings |
            Where-Object Severity -eq "Medium").Count
        Low = @($sortedFindings |
            Where-Object Severity -eq "Low").Count
        Info = @($sortedFindings |
            Where-Object Severity -eq "Info").Count
    }
}

Save-Json -Name "Summary" -Data $summary

Write-Host ""
Write-Host "Audit abgeschlossen."
Write-Host "Bericht: $script:ReportDirectory"
Write-Host ""
Write-Host "Kritisch: $($summary.Findings.Critical)"
Write-Host "Hoch:     $($summary.Findings.High)"
Write-Host "Mittel:   $($summary.Findings.Medium)"
Write-Host "Niedrig:  $($summary.Findings.Low)"
Write-Host "Info:     $($summary.Findings.Info)"