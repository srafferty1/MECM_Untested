#Requires -Version 5.1
<#
.SYNOPSIS
    MECM Environment Configuration Snapshot - Read Only

.DESCRIPTION
    Collects MECM site configuration details for comparison across environments.
    No changes are made to the system. Output is saved as a JSON file.

    Compatible with MECM 2203 and later (tested on 2403 / 2409).
    Any section that cannot be queried is recorded as "Unable to retrieve data"
    rather than causing the script to abort.

    Run on the Primary Site Server or a machine with the SMS Provider role.

    ── DEPENDENCIES ────────────────────────────────────────────────────────────
    MANDATORY (script will not function without these):
      • PowerShell 5.1 or later (enforced by #Requires)
      • Run on or with -SMSProvider pointing to a machine that holds the SMS
        Provider role (WMI namespace root\SMS\site_<SiteCode> must be reachable)
      • The running account must be an MECM Full Administrator or have read
        rights to the SMS WMI namespace

    BUILT INTO WINDOWS SERVER — no download or install needed:
      • ServerManager module   (Get-WindowsFeature) — present on all WS editions
      • WebAdministration module (IIS:\ PSDrive)    — present when IIS is installed
      • IISAdministration module (Get-IISAppPool)   — present on WS 2016+ with IIS
      • gpresult.exe                                — present on all WS editions
      • System.Data.SqlClient (.NET 4.x)            — present on all WS editions
      • Cert:\ PSDrive / ADSI WinNT provider        — built-in PS providers

    CONDITIONAL — sections degrade gracefully when the role is absent:
      • IIS (Web-Server feature) — required for sections 39, 40, HC IIS checks
        and service account app pool data. Missing = partial/empty output.
      • WSUS (WSUS-Services feature) — section 40 returns a "not installed" note.
      • WDS  (WDS feature) — health check returns NotInstalled, not an error.
      • SQL access — section 20 (Database) and section 44 (Service Accounts /
        SQL logins) skip the SQL sub-queries and note the reason.

    NOT REQUIRED (no internet, no NuGet, no PowerShell Gallery installs needed):
      • ActiveDirectory module — not used
      • RSAT tools beyond ServerManager — not used
      • Any third-party modules — not used
    ────────────────────────────────────────────────────────────────────────────

.PARAMETER OutputPath
    Folder to save the JSON report. Default: current directory.

.PARAMETER SiteCode
    MECM site code. Auto-detected if omitted.

.PARAMETER SMSProvider
    SMS Provider server name. Default: local machine.

.EXAMPLE
    .\Get-MECMConfig.ps1

.EXAMPLE
    .\Get-MECMConfig.ps1 -OutputPath "C:\Reports" -SiteCode "P01" -SMSProvider "MECMSERVER01"
#>
[CmdletBinding()]
param(
    [string]$OutputPath    = (Get-Location).Path,
    [string]$SiteCode      = "",
    [string]$SMSProvider   = $env:COMPUTERNAME,
    [int]   $LogHoursBack  = 48,     # How far back to scan log files (hours)
    [int]   $LogMaxLines   = 5000,   # Max lines to read from the tail of each log
    [string]$SitePrefix    = "",     # Site/env prefix for cert template matching (e.g. "DIEP","DIES","FIES"). Auto-detected from computer name if blank.
    [switch]$SkipRemoteProbes,       # Skip section 45 remote role server probing entirely
    [int]   $RemoteTimeoutSec = 30   # WMI timeout (seconds) when probing remote role servers
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

#region ── Helpers ───────────────────────────────────────────────────────────────

$script:SectionErrors = [ordered]@{}

function Write-Section ([string]$Name) {
    Write-Host ("  [{0:HH:mm:ss}] Collecting: {1}" -f (Get-Date), $Name) -ForegroundColor Cyan
}

function Write-SectionError ([string]$Name, [string]$Message) {
    Write-Host ("  [!] {0} - {1}" -f $Name, $Message) -ForegroundColor Red
    $script:SectionErrors[$Name] = $Message
}

# Runs a scriptblock; returns its result or an error hashtable on failure.
# Usage: $report.Key = Invoke-Section "Label" { ... return value ... }
function Invoke-Section {
    param([string]$Name, [scriptblock]$Block)
    try {
        & $Block
    } catch {
        $msg = $_.Exception.Message
        Write-SectionError $Name $msg
        [ordered]@{ _Error = "Unable to retrieve data: $msg" }
    }
}

function Invoke-WMI {
    param(
        [string]$Class,
        [string]$Filter = "",
        [string]$NS     = $script:WmiNS
    )
    try {
        $q = if ($Filter) { "SELECT * FROM $Class WHERE $Filter" } else { "SELECT * FROM $Class" }
        @(Get-WmiObject -Namespace $NS -Query $q -ComputerName $SMSProvider -ErrorAction Stop)
    } catch { @() }
}

# Safe property read — returns $null instead of throwing if property missing.
function sprop ($obj, [string]$Prop) {
    if ($null -eq $obj) { return $null }
    try { $obj.$Prop } catch { $null }
}

function Get-EmbeddedProps ($wmiObj) {
    $h = [ordered]@{}
    if (-not $wmiObj) { return $h }
    foreach ($p in @($wmiObj.Props)) {
        try { $h[$p.PropertyName] = $p.Value } catch {}
    }
    return $h
}

function Get-EmbeddedPropLists ($wmiObj) {
    $h = [ordered]@{}
    if (-not $wmiObj) { return $h }
    foreach ($p in @($wmiObj.PropLists)) {
        try { $h[$p.PropertyListName] = @($p.Values) } catch {}
    }
    return $h
}

function Resolve-SiteType ([int]$t) {
    switch ($t) { 4{"CAS"}; 2{"Primary"}; 1{"Secondary"}; default{"Unknown($t)"} }
}

function Resolve-CollRefresh ([int]$r) {
    switch ($r) { 1{"Manual"};2{"Scheduled"};4{"Incremental"};6{"Scheduled+Incremental"};default{"$r"} }
}

# Probes a single remote role server using WMI (no WinRM required for core data),
# ADSI WinNT (local groups), remote registry (WSUS), and Invoke-Command (IIS/certs
# — graceful fallback when WinRM is unavailable).
function Probe-RoleServer {
    param(
        [string]   $Server,
        [string[]] $Roles,
        [int]      $TimeoutSec = 30
    )

    $result = [ordered]@{
        ServerName = $Server
        Roles      = $Roles
        ProbeTime  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }

    # ── OS + hardware (WMI — DCOM, no WinRM) ─────────────────────────────────────
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ComputerName $Server -ErrorAction Stop
        $cs = Get-WmiObject Win32_ComputerSystem  -ComputerName $Server -ErrorAction Stop
        $result.OS = [ordered]@{
            Caption      = $os.Caption
            BuildNumber  = $os.BuildNumber
            Architecture = $os.OSArchitecture
            TotalRAMGB   = [math]::Round([long]$cs.TotalPhysicalMemory / 1GB, 1)
            LastBoot     = $(try { [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime).ToString('yyyy-MM-dd HH:mm') } catch { $null })
        }
    } catch {
        $result.OS = [ordered]@{ _Error = "WMI unavailable: $($_.Exception.Message)" }
    }

    # ── Disk space (WMI) ──────────────────────────────────────────────────────────
    try {
        $result.Disks = @(Get-WmiObject Win32_LogicalDisk -ComputerName $Server `
            -Filter "DriveType=3" -ErrorAction Stop | Sort-Object DeviceID | ForEach-Object {
            [ordered]@{
                Drive   = $_.DeviceID
                SizeGB  = [math]::Round([long]$_.Size     / 1GB, 1)
                FreeGB  = [math]::Round([long]$_.FreeSpace / 1GB, 1)
                FreePct = if ($_.Size) { [math]::Round([long]$_.FreeSpace / [long]$_.Size * 100, 1) } else { 0 }
            }
        })
    } catch {
        $result.Disks = @([ordered]@{ _Error = "WMI disk query failed: $($_.Exception.Message)" })
    }

    # ── MECM-relevant services (WMI) ─────────────────────────────────────────────
    $svcWql = "Name LIKE 'SMS_%' OR Name LIKE 'CcmExec%' OR Name LIKE 'MSSQL%' OR " +
              "Name LIKE 'SQLAgent%' OR Name='W3SVC' OR Name='WAS' OR Name='IISADMIN' OR " +
              "Name='WsusService' OR Name='WDSServer' OR Name='ReportingServicesService' OR " +
              "Name='BITS' OR Name='wuauserv'"
    try {
        $result.Services = @(Get-WmiObject Win32_Service -ComputerName $Server `
            -Filter $svcWql -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            [ordered]@{
                Name      = $_.Name
                State     = $_.State
                StartMode = $_.StartMode
                StartName = $_.StartName
            }
        })
    } catch {
        $result.Services = @([ordered]@{ _Error = "WMI service query failed: $($_.Exception.Message)" })
    }

    # ── Local group membership (ADSI WinNT — no WinRM) ───────────────────────────
    $result.LocalGroups = @()
    foreach ($grpName in @('Administrators', 'SMS Admins')) {
        try {
            $grp     = [ADSI]"WinNT://$Server/$grpName,group"
            $members = @($grp.psbase.Invoke("Members") | ForEach-Object {
                try { $m = [ADSI]$_; "$($m.psbase.Parent.Name)\$($m.Name[0])" } catch { "?" }
            })
            $result.LocalGroups += [ordered]@{ Group=$grpName; Count=$members.Count; Members=$members -join '; ' }
        } catch {
            $result.LocalGroups += [ordered]@{ Group=$grpName; Count=0; Members="Unable to query: $($_.Exception.Message)" }
        }
    }

    # ── Windows Features (Get-WindowsFeature -ComputerName — requires WinRM) ──────
    try {
        $result.InstalledFeatures = @(Get-WindowsFeature -ComputerName $Server -ErrorAction Stop |
            Where-Object { $_.Installed } | Sort-Object Name | Select-Object -ExpandProperty Name)
        $result.FeaturesSource = "Get-WindowsFeature (WinRM)"
    } catch {
        $result.InstalledFeatures = @()
        $result.FeaturesNote      = "Requires WinRM/PSRemoting on target: $($_.Exception.Message)"
    }

    # ── IIS config (Invoke-Command — requires WinRM) ──────────────────────────────
    # Only probed for roles that host IIS
    $iisRoles = @('SMS Management Point','SMS Distribution Point','SMS Software Update Point',
                  'SMS Reporting Services Point','SMS Enrollment Point',
                  'SMS Enrollment Proxy Point','SMS Component Server')
    if ($Roles | Where-Object { $iisRoles -contains $_ }) {
        try {
            $result.IIS = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
                $mod = $false
                try { Import-Module WebAdministration -ErrorAction Stop; $mod = $true } catch {}
                if (-not $mod) { return [ordered]@{ _Note = "WebAdministration module not available on this server" } }
                [ordered]@{
                    Websites = @(Get-Website -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
                        [ordered]@{ Name=$_.Name; State=$_.State.ToString(); PhysicalPath=$_.PhysicalPath }
                    })
                    AppPools = @(Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
                        [ordered]@{
                            Name         = $_.Name
                            State        = $_.State.ToString()
                            IdentityType = $_.ProcessModel.IdentityType.ToString()
                            User         = $_.ProcessModel.UserName
                        }
                    })
                    SSLBindings = @(Get-ChildItem IIS:\SslBindings -ErrorAction SilentlyContinue | ForEach-Object {
                        [ordered]@{ IPPort = "$($_.IPAddress):$($_.Port)"; Thumbprint = $_.Thumbprint }
                    })
                }
            }
            $result.IISSource = "Invoke-Command (WinRM)"
        } catch {
            $result.IIS       = [ordered]@{ _Note = "WinRM unavailable or access denied: $($_.Exception.Message)" }
            $result.IISSource = "Unavailable"
        }
    }

    # ── Certificates (Invoke-Command — requires WinRM) ────────────────────────────
    $certRoles = @('SMS Management Point','SMS Distribution Point',
                   'SMS Software Update Point','SMS Component Server')
    if ($Roles | Where-Object { $certRoles -contains $_ }) {
        try {
            $result.Certificates = @(Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
                Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | ForEach-Object {
                    $ext = $_.Extensions | Where-Object { $_.Oid.FriendlyName -match "Certificate Template" }
                    $tpl = if ($ext) {
                        try { if ($ext.Format(0) -match '=\s*([^(]+)') { $Matches[1].Trim() } else { "" } } catch { "" }
                    } else { "" }
                    [ordered]@{
                        Subject    = $_.Subject
                        Thumbprint = $_.Thumbprint
                        NotAfter   = $_.NotAfter.ToString('yyyy-MM-dd')
                        DaysLeft   = ($_.NotAfter - (Get-Date)).Days
                        Template   = $tpl
                    }
                }
            })
            $result.CertSource = "Invoke-Command (WinRM)"
        } catch {
            $result.Certificates = @([ordered]@{ _Note = "WinRM unavailable: $($_.Exception.Message)" })
            $result.CertSource   = "Unavailable"
        }
    }

    # ── WSUS registry (remote registry API, fallback to Invoke-Command) ───────────
    if ($Roles -contains 'SMS Software Update Point') {
        $wsusRead = $false
        try {
            $hklm    = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
            $wsusKey = $hklm.OpenSubKey('SOFTWARE\Microsoft\Update Services\Server\Setup')
            if ($wsusKey) {
                $result.WSUSRegistry = [ordered]@{
                    ContentDir     = $wsusKey.GetValue('ContentDir')
                    PortNumber     = $wsusKey.GetValue('PortNumber')
                    UsingSSL       = $wsusKey.GetValue('UsingSSL')
                    ProductVersion = $wsusKey.GetValue('ProductVersion')
                    SqlServerName  = $wsusKey.GetValue('SqlServerName')
                }
                $wsusKey.Close()
                $result.WSUSRegistrySource = "Remote Registry"
                $wsusRead = $true
            }
            $hklm.Close()
        } catch { }

        if (-not $wsusRead) {
            try {
                $result.WSUSRegistry = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
                    $k = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup" -ErrorAction Stop
                    [ordered]@{
                        ContentDir     = $k.ContentDir
                        PortNumber     = $k.PortNumber
                        UsingSSL       = $k.UsingSSL
                        ProductVersion = $k.ProductVersion
                        SqlServerName  = $k.SqlServerName
                    }
                }
                $result.WSUSRegistrySource = "Invoke-Command (WinRM)"
            } catch {
                $result.WSUSRegistry       = [ordered]@{ _Note = "Remote Registry service and WinRM both unavailable: $($_.Exception.Message)" }
                $result.WSUSRegistrySource = "Unavailable"
            }
        }
    }

    $result
}

#endregion

#region ── Site Code Discovery ───────────────────────────────────────────────────

Write-Host ""
Write-Host "MECM Environment Configuration Snapshot" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Provider   : $SMSProvider"
Write-Host "Started    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

if (-not $SiteCode) {
    $provLoc = @(Get-WmiObject -Namespace "root\SMS" -Class "SMS_ProviderLocation" `
                               -ComputerName $SMSProvider -ErrorAction SilentlyContinue) | Select-Object -First 1
    if ($provLoc) { $SiteCode = $provLoc.SiteCode }
}

if (-not $SiteCode) {
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SMS\Identification" -ErrorAction SilentlyContinue
    if ($reg) { $SiteCode = $reg."Site Code" }
}

if (-not $SiteCode) {
    Write-Warning "Cannot auto-detect site code. Specify -SiteCode <code> and try again."
    exit 1
}

$script:WmiNS = "root\SMS\site_$SiteCode"
Write-Host "Site Code  : $SiteCode"
Write-Host "Namespace  : $($script:WmiNS)"
Write-Host ""

#endregion

$report = [ordered]@{
    Metadata           = [ordered]@{
        GeneratedAt   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        GeneratedBy   = "$env:USERDOMAIN\$env:USERNAME"
        GeneratedOn   = $env:COMPUTERNAME
        SMSProvider   = $SMSProvider
        SiteCode      = $SiteCode
        ScriptVersion = "2.0"
    }
    SiteInfo           = $null
    SiteSystemRoles    = $null
    Boundaries         = $null
    BoundaryGroups     = $null
    ClientSettings     = $null
    DiscoveryMethods   = $null
    SoftwareUpdates    = $null
    DistributionPoints = $null
    DPGroups           = $null
    Collections        = $null
    Applications       = $null
    Packages           = $null
    OSD                = $null
    EndpointProtection = $null
    MaintenanceWindows = $null
    SoftwareMetering   = $null
    CloudServices      = $null
    HierarchySettings  = $null
    ComponentStatus    = $null
    DatabaseInfo       = $null
    Logs                    = $null
    RBAC                    = $null
    AutoDeploymentRules     = $null
    Deployments             = $null
    ClientCommunication     = $null
    HardwareInventory       = $null
    ConfigurationBaselines  = $null
    Alerts                  = $null
    RunScripts              = $null
    WindowsServicingPlans   = $null
    ThirdPartyUpdateCatalogs= $null
    CoManagement            = $null
    ContentDistribution     = $null
    SiteMaintenanceTasks    = $null
    SoftwareUpdateGroups    = $null
    StatusFilterRules       = $null
    Certificates            = $null
    IISConfiguration        = $null
    WSUSConfiguration       = $null
    ContentStore            = $null
    GroupPolicySettings     = $null
    HealthChecks            = $null
    ServiceAccounts         = $null
    RoleServerProbes        = $null
    RegistrySettings        = $null
    OSEventLogs             = $null
    FirewallConfig          = $null
    ScriptErrors            = $null
}

# Shared variables initialised here so later sections degrade safely if
# an earlier section fails and never sets them.
$sysResources = @()
$siteDefProps = [ordered]@{}

#region ── 1. Site Information ───────────────────────────────────────────────────

Write-Section "Site Information"
$report.SiteInfo = Invoke-Section "SiteInfo" {
    $allSites    = Invoke-WMI "SMS_Site"
    $primarySite = $allSites | Where-Object { $_.SiteCode -eq $SiteCode } | Select-Object -First 1

    [ordered]@{
        SiteCode          = sprop $primarySite SiteCode
        SiteName          = sprop $primarySite SiteName
        SiteType          = Resolve-SiteType ([int](sprop $primarySite Type))
        Version           = sprop $primarySite Version
        BuildNumber       = sprop $primarySite BuildNumber
        ReportingSiteCode = sprop $primarySite ReportingSiteCode
        ServerName        = sprop $primarySite ServerName
        InstallDir        = sprop $primarySite InstallDir
        TimeZoneOffset    = sprop $primarySite TimeZoneOffset
        Status            = sprop $primarySite Status
        AllSitesInHierarchy = @($allSites | Sort-Object SiteCode | ForEach-Object {
            [ordered]@{
                SiteCode    = sprop $_ SiteCode
                SiteName    = sprop $_ SiteName
                SiteType    = Resolve-SiteType ([int](sprop $_ Type))
                Version     = sprop $_ Version
                BuildNumber = sprop $_ BuildNumber
                ServerName  = sprop $_ ServerName
            }
        })
    }
}

#endregion

#region ── 2. Site System Roles ──────────────────────────────────────────────────

Write-Section "Site System Roles"
$report.SiteSystemRoles = Invoke-Section "SiteSystemRoles" {
    $script:sysResources = Invoke-WMI "SMS_SystemResourceList"
    @($script:sysResources | Sort-Object ServerName, RoleName | ForEach-Object {
        [ordered]@{
            ServerName   = sprop $_ ServerName
            RoleName     = sprop $_ RoleName
            SiteCode     = sprop $_ SiteCode
            ResourceType = sprop $_ ResourceType
            NALPath      = sprop $_ NALPath
        }
    })
}

#endregion

#region ── 3. Boundaries ─────────────────────────────────────────────────────────

Write-Section "Boundaries"
$report.Boundaries = Invoke-Section "Boundaries" {
    $boundaries = Invoke-WMI "SMS_Boundary"
    @($boundaries | Sort-Object BoundaryType, Value | ForEach-Object {
        [ordered]@{
            BoundaryID   = sprop $_ BoundaryID
            DisplayName  = sprop $_ DisplayName
            BoundaryType = switch ([int](sprop $_ BoundaryType)) {
                0{"IP Subnet"}; 1{"AD Site"}; 2{"IPv6 Prefix"}; 3{"IP Range"}; default{"$($_.BoundaryType)"}
            }
            Value        = sprop $_ Value
            GroupCount   = sprop $_ GroupCount
            SiteSystems  = @(try { $_.SiteSystems } catch { @() })
        }
    })
}

#endregion

#region ── 4. Boundary Groups ────────────────────────────────────────────────────

Write-Section "Boundary Groups"
$report.BoundaryGroups = Invoke-Section "BoundaryGroups" {
    $bgItems   = Invoke-WMI "SMS_BoundaryGroup"
    $bgMembers = Invoke-WMI "SMS_BoundaryGroupMembers"
    $bgSysSys  = Invoke-WMI "SMS_BoundaryGroupSiteSystems"

    @($bgItems | Sort-Object Name | ForEach-Object {
        $gid = sprop $_ GroupID
        [ordered]@{
            GroupID         = $gid
            Name            = sprop $_ Name
            Description     = sprop $_ Description
            DefaultSiteCode = sprop $_ DefaultSiteCode
            MemberCount     = sprop $_ MemberCount
            BoundaryIDs     = @($bgMembers | Where-Object { $_.GroupID -eq $gid } | Select-Object -Expand BoundaryID)
            SiteSystems     = @($bgSysSys  | Where-Object { $_.GroupID -eq $gid } | Select-Object -Expand ServerNALPath)
        }
    })
}

#endregion

#region ── 5. Client Settings ────────────────────────────────────────────────────

Write-Section "Client Settings"
$report.ClientSettings = Invoke-Section "ClientSettings" {
    # Default settings live in a separate class; custom settings in SMS_ClientSettings.
    # AgentConfigurations is lazy-loaded — .Get() must be called before reading it.
    $allSettings = @(Invoke-WMI "SMS_ClientSettingsDefault") + @(Invoke-WMI "SMS_ClientSettings")

    @($allSettings | Sort-Object Priority | ForEach-Object {
        $cs = $_
        # Force lazy-load of embedded agent configurations
        try { $cs.Get() } catch {}

        $agents = @()
        try {
            $rawAcs = $cs.AgentConfigurations
            if ($rawAcs -ne $null) {
                $agents = @($rawAcs | ForEach-Object {
                    $ac = $_
                    if (-not $ac -or (-not $ac.__CLASS -and -not $ac.AgentName)) { return }
                    $displayName = if ($ac.AgentName) { $ac.AgentName } else { $ac.__CLASS }
                    $h = [ordered]@{ AgentName = $displayName }
                    try {
                        $ac | Get-Member -MemberType Property -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notin @('AgentName','__CLASS','__DERIVATION','__DYNASTY',
                                                         '__GENUS','__NAMESPACE','__PATH','__PROPERTY_COUNT',
                                                         '__RELPATH','__SERVER','__SUPERCLASS') } |
                        ForEach-Object { try { $h[$_.Name] = $ac.($_.Name) } catch {} }
                    } catch {}
                    $h
                } | Where-Object { $_ -ne $null })
            }
        } catch {}

        $assignments = @()
        try {
            $sid = [int]$cs.SettingsID
            if ($sid -gt 0) {
                $assignments = @(Invoke-WMI "SMS_ClientSettingsAssignment" -Filter "ClientSettingsID=$sid" |
                    ForEach-Object { "$($_.CollectionName) ($($_.CollectionID))" })
            }
        } catch {}

        [ordered]@{
            SettingsID            = sprop $cs SettingsID
            Name                  = sprop $cs Name
            Description           = sprop $cs Description
            Priority              = sprop $cs Priority
            Type                  = switch ([int](sprop $cs Type)) { 0{"Default (applies to all)"}; 1{"Custom"}; 2{"Custom (User)"}; default{"$($cs.Type)"} }
            AssignedToCollections = $assignments
            AgentConfigurations   = $agents
        }
    })
}

#endregion

#region ── 6. Discovery Methods ──────────────────────────────────────────────────

Write-Section "Discovery Methods"
$report.DiscoveryMethods = Invoke-Section "DiscoveryMethods" {
    $discMap = [ordered]@{
        ActiveDirectorySystemDiscovery    = "SMS_AD_SYSTEM_DISCOVERY_AGENT"
        ActiveDirectoryUserDiscovery      = "SMS_AD_USER_DISCOVERY_AGENT"
        ActiveDirectoryGroupDiscovery     = "SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT"
        ActiveDirectoryForestDiscovery    = "SMS_AD_FOREST_DISCOVERY_MANAGER"
        HeartbeatDiscovery                = "SMS_HEARTBEAT_DISCOVERY_AGENT"
        NetworkDiscovery                  = "SMS_NETWORK_DISCOVERY"
    }

    $discoveries = [ordered]@{}
    foreach ($disc in $discMap.GetEnumerator()) {
        try {
            $comp = Invoke-WMI "SMS_SCI_Component" -Filter "SiteCode='$SiteCode' AND ComponentName='$($disc.Value)'"
            if ($comp) {
                $discoveries[$disc.Key] = [ordered]@{
                    ComponentName = $disc.Value
                    Props         = Get-EmbeddedProps     ($comp | Select-Object -First 1)
                    PropLists     = Get-EmbeddedPropLists ($comp | Select-Object -First 1)
                }
            } else {
                $discoveries[$disc.Key] = [ordered]@{ ComponentName = $disc.Value; Props = [ordered]@{}; PropLists = [ordered]@{} }
            }
        } catch {
            $discoveries[$disc.Key] = [ordered]@{ _Error = "Unable to retrieve data: $($_.Exception.Message)" }
        }
    }
    $discoveries
}

#endregion

#region ── 7. Software Update Configuration ──────────────────────────────────────

Write-Section "Software Update Configuration"
$report.SoftwareUpdates = Invoke-Section "SoftwareUpdates" {
    $supComp    = Invoke-WMI "SMS_SCI_Component" -Filter "SiteCode='$SiteCode' AND ComponentName='SMS_WSUS_CONFIGURATION_MANAGER'"
    $supServers = @($sysResources | Where-Object { $_.RoleName -eq "SMS Software Update Point" } |
                    Select-Object -Expand ServerName | Sort-Object)

    $updateCats  = Invoke-WMI "SMS_UpdateCategoryInstance"
    $enabledCats = @($updateCats | Where-Object { $_.IsSubscribed -eq $true } |
        Sort-Object CategoryTypeName, LocalizedCategoryInstanceName | ForEach-Object {
            [ordered]@{
                CategoryType = sprop $_ CategoryTypeName
                Name         = sprop $_ LocalizedCategoryInstanceName
                ID           = sprop $_ CategoryInstanceID
            }
        })

    [ordered]@{
        SUPServers          = $supServers
        ComponentProperties = Get-EmbeddedProps     ($supComp | Select-Object -First 1)
        ComponentPropLists  = Get-EmbeddedPropLists ($supComp | Select-Object -First 1)
        EnabledCategories   = $enabledCats
        EnabledCatCount     = $enabledCats.Count
    }
}

#endregion

#region ── 8. Distribution Points ────────────────────────────────────────────────

Write-Section "Distribution Points"
$report.DistributionPoints = Invoke-Section "DistributionPoints" {
    $dps = Invoke-WMI "SMS_DistributionPointInfo"
    @($dps | Sort-Object ServerName | ForEach-Object {
        $dp = $_
        $diskSpaceGB = try {
            $raw = sprop $dp AvailableContentLibDiskSpace
            if ($null -ne $raw -and $raw -ne 0) { [math]::Round([double]$raw / 1GB, 2) } else { $null }
        } catch { $null }

        [ordered]@{
            ServerName             = sprop $dp ServerName
            SiteCode               = sprop $dp SiteCode
            IsPXE                  = sprop $dp IsPXE
            IsMulticast            = sprop $dp IsMulticast
            IsActive               = sprop $dp IsActive
            IsPullDP               = sprop $dp IsPullDP
            IsProtected            = sprop $dp IsProtected
            PreStagingAllowed      = sprop $dp PreStagingAllowed
            Priority               = sprop $dp Priority
            ContentLibPath         = sprop $dp ContentLibPath
            AvailContentLibDiskGB  = $diskSpaceGB
        }
    })
}

#endregion

#region ── 9. DP Groups ──────────────────────────────────────────────────────────

Write-Section "DP Groups"
$report.DPGroups = Invoke-Section "DPGroups" {
    $dpGroups = Invoke-WMI "SMS_DistributionPointGroup"
    @($dpGroups | Sort-Object Name | ForEach-Object {
        [ordered]@{
            GroupID         = sprop $_ GroupID
            Name            = sprop $_ Name
            Description     = sprop $_ Description
            MemberCount     = sprop $_ MemberCount
            CollectionCount = sprop $_ CollectionCount
        }
    })
}

#endregion

#region ── 10. Collections ───────────────────────────────────────────────────────

Write-Section "Collections"
$report.Collections = Invoke-Section "Collections" {
    $deviceColls = Invoke-WMI "SMS_Collection" -Filter "CollectionType=2"
    $userColls   = Invoke-WMI "SMS_Collection" -Filter "CollectionType=1"

    $toRow = {
        [ordered]@{
            CollectionID         = sprop $_ CollectionID
            Name                 = sprop $_ Name
            MemberCount          = sprop $_ MemberCount
            LimitingCollectionID = sprop $_ LimitingCollectionID
            RefreshType          = Resolve-CollRefresh ([int](sprop $_ RefreshType))
            IsBuiltIn            = sprop $_ IsBuiltIn
            Comment              = sprop $_ Comment
        }
    }

    [ordered]@{
        DeviceCollectionCount = $deviceColls.Count
        UserCollectionCount   = $userColls.Count
        DeviceCollections     = @($deviceColls | Sort-Object Name | ForEach-Object $toRow)
        UserCollections       = @($userColls   | Sort-Object Name | ForEach-Object $toRow)
    }
}

#endregion

#region ── 11. Applications ──────────────────────────────────────────────────────

Write-Section "Applications"
$report.Applications = Invoke-Section "Applications" {
    $apps = Invoke-WMI "SMS_Application" -Filter "IsLatest=1"
    [ordered]@{
        Count        = $apps.Count
        Applications = @($apps | Sort-Object LocalizedDisplayName | ForEach-Object {
            [ordered]@{
                ModelName               = sprop $_ ModelName
                Name                    = sprop $_ LocalizedDisplayName
                SoftwareVersion         = sprop $_ SoftwareVersion
                Publisher               = sprop $_ LocalizedPublisher
                IsDeployed              = sprop $_ IsDeployed
                NumberOfDeploymentTypes = sprop $_ NumberOfDTs
                CIVersion               = sprop $_ CIVersion
                DateCreated             = sprop $_ DateCreated
                LastModifiedBy          = sprop $_ LastModifiedBy
            }
        })
    }
}

#endregion

#region ── 12. Packages & Task Sequences ─────────────────────────────────────────

Write-Section "Packages & Task Sequences"
$report.Packages = Invoke-Section "Packages" {
    $packages   = Invoke-WMI "SMS_Package"
    $tsPackages = Invoke-WMI "SMS_TaskSequencePackage"
    $driverPkgs = Invoke-WMI "SMS_DriverPackage"

    [ordered]@{
        PackageCount      = $packages.Count
        TaskSequenceCount = $tsPackages.Count
        DriverPkgCount    = $driverPkgs.Count
        Packages          = @($packages | Sort-Object Name | ForEach-Object {
            [ordered]@{
                PackageID    = sprop $_ PackageID
                Name         = sprop $_ Name
                Version      = sprop $_ Version
                Manufacturer = sprop $_ Manufacturer
                PackageType  = sprop $_ PackageType
                SourcePath   = sprop $_ PkgSourcePath
            }
        })
        TaskSequences     = @($tsPackages | Sort-Object Name | ForEach-Object {
            [ordered]@{
                PackageID   = sprop $_ PackageID
                Name        = sprop $_ Name
                Version     = sprop $_ Version
                BootImageID = sprop $_ BootImageID
            }
        })
        DriverPackages    = @($driverPkgs | Sort-Object Name | ForEach-Object {
            [ordered]@{
                PackageID  = sprop $_ PackageID
                Name       = sprop $_ Name
                Version    = sprop $_ Version
                SourcePath = sprop $_ PkgSourcePath
            }
        })
    }
}

#endregion

#region ── 13. OSD ───────────────────────────────────────────────────────────────

Write-Section "OSD (Boot Images, OS Images, Upgrade Packages)"
$report.OSD = Invoke-Section "OSD" {
    $bootImages = Invoke-WMI "SMS_BootImagePackage"
    $osImages   = Invoke-WMI "SMS_OperatingSystemInstallPackage"
    $osUpgPkgs  = Invoke-WMI "SMS_OperatingSystemUpgradePackage"

    [ordered]@{
        BootImages = @($bootImages | Sort-Object Name | ForEach-Object {
            $arch = try {
                $a = sprop $_ Architecture
                if ($a -eq 9) { "x64" } elseif ($a -eq 0) { "x86" } else { "$a" }
            } catch { $null }
            [ordered]@{
                PackageID            = sprop $_ PackageID
                Name                 = sprop $_ Name
                Version              = sprop $_ Version
                Architecture         = $arch
                SourcePath           = sprop $_ PkgSourcePath
                OptionalComponents   = @(try { $_.OptionalComponents } catch { @() })
                BackgroundBitmapPath = sprop $_ BackgroundBitmapPath
            }
        })
        OSImages = @($osImages | Sort-Object Name | ForEach-Object {
            [ordered]@{
                PackageID  = sprop $_ PackageID
                Name       = sprop $_ Name
                Version    = sprop $_ Version
                SourcePath = sprop $_ PkgSourcePath
            }
        })
        OSUpgradePackages = @($osUpgPkgs | Sort-Object Name | ForEach-Object {
            [ordered]@{
                PackageID  = sprop $_ PackageID
                Name       = sprop $_ Name
                Version    = sprop $_ Version
                SourcePath = sprop $_ PkgSourcePath
            }
        })
    }
}

#endregion

#region ── 14. Endpoint Protection ───────────────────────────────────────────────

Write-Section "Endpoint Protection Policies"
$report.EndpointProtection = Invoke-Section "EndpointProtection" {
    $amPolicies = Invoke-WMI "SMS_AntiMalwareSettings"
    [ordered]@{
        PolicyCount = $amPolicies.Count
        Policies    = @($amPolicies | Sort-Object Name | ForEach-Object {
            [ordered]@{
                SettingsID                = sprop $_ SettingsID
                Name                      = sprop $_ Name
                SettingType               = sprop $_ SettingType
                RealTimeProtectionEnabled = sprop $_ RealTimeProtectionEnabled
                DefinitionUpdatesEnabled  = sprop $_ DefinitionUpdatesEnabled
                CloudProtectionLevel      = sprop $_ JoinSpyNet
                ScheduledScanEnabled      = sprop $_ EnableScheduledScan
                ScheduledScanTime         = sprop $_ ScheduledScanTime
                ScheduledScanType         = sprop $_ ScheduledScanType
            }
        })
    }
}

#endregion

#region ── 15. Maintenance Windows ───────────────────────────────────────────────

Write-Section "Maintenance Windows"
$report.MaintenanceWindows = Invoke-Section "MaintenanceWindows" {
    $mws = Invoke-WMI "SMS_ServiceWindow"
    @($mws | Sort-Object SmsCollectionID, Name | ForEach-Object {
        [ordered]@{
            ServiceWindowID   = sprop $_ ServiceWindowID
            Name              = sprop $_ Name
            CollectionID      = sprop $_ SmsCollectionID
            IsEnabled         = sprop $_ IsEnabled
            ServiceWindowType = switch ([int](sprop $_ ServiceWindowType)) {
                1{"General"}; 2{"OSD"}; 4{"Updates"}; 5{"Updates+Applications"}; default{"$($_.ServiceWindowType)"}
            }
            Duration          = sprop $_ Duration
            IsGMT             = sprop $_ IsGMT
            Schedules         = sprop $_ ServiceWindowSchedules
        }
    })
}

#endregion

#region ── 16. Software Metering ─────────────────────────────────────────────────

Write-Section "Software Metering Rules"
$report.SoftwareMetering = Invoke-Section "SoftwareMetering" {
    $meteringRules = Invoke-WMI "SMS_MeteredProductRule"
    [ordered]@{
        RuleCount = $meteringRules.Count
        Rules     = @($meteringRules | Sort-Object ProductName | ForEach-Object {
            [ordered]@{
                RuleID      = sprop $_ RuleID
                ProductName = sprop $_ ProductName
                FileName    = sprop $_ FileName
                FileVersion = sprop $_ FileVersion
                LanguageID  = sprop $_ LanguageID
                Enabled     = sprop $_ Enabled
            }
        })
    }
}

#endregion

#region ── 17. Cloud Services ────────────────────────────────────────────────────

Write-Section "Cloud Services (CMG / Azure)"
$report.CloudServices = Invoke-Section "CloudServices" {
    $cmgConns   = @($sysResources | Where-Object { $_.RoleName -eq "SMS Cloud Management Gateway Connection Point" } |
                    Select-Object -Expand ServerName | Sort-Object)
    $cloudDPs   = @($sysResources | Where-Object { $_.RoleName -eq "SMS Cloud-Based Distribution Point" } |
                    Select-Object -Expand ServerName | Sort-Object)
    $azServices = Invoke-WMI "SMS_AzureService"

    [ordered]@{
        CMGConnectionPoints = $cmgConns
        CloudDPs            = $cloudDPs
        AzureServices       = @($azServices | Sort-Object ServiceName | ForEach-Object {
            [ordered]@{
                ServiceType = sprop $_ ServiceType
                ServiceName = sprop $_ ServiceName
                TenantName  = sprop $_ TenantName
                TenantID    = sprop $_ AADTenantId
                Region      = sprop $_ Region
            }
        })
    }
}

#endregion

#region ── 18. Hierarchy Settings ────────────────────────────────────────────────

Write-Section "Hierarchy / Site Definition Settings"
$report.HierarchySettings = Invoke-Section "HierarchySettings" {
    $siteDef = Invoke-WMI "SMS_SCI_SiteDefinition" -Filter "SiteCode='$SiteCode'" | Select-Object -First 1
    $props   = Get-EmbeddedProps     $siteDef
    $lists   = Get-EmbeddedPropLists $siteDef

    # Expose for use by DatabaseInfo section below
    $script:siteDefProps = $props

    [ordered]@{
        Properties = $props
        PropLists  = $lists
    }
}

#endregion

#region ── 19. Component Status ──────────────────────────────────────────────────

Write-Section "Component Status (last interval)"
$report.ComponentStatus = Invoke-Section "ComponentStatus" {
    $compStatus = Invoke-WMI "SMS_ComponentSummarizer" `
        -Filter "SiteCode='$SiteCode' AND TallyInterval='0001128000100008'"
    @($compStatus | Sort-Object ComponentName | ForEach-Object {
        [ordered]@{
            ComponentName = sprop $_ ComponentName
            MachineName   = sprop $_ MachineName
            State         = switch ([int](sprop $_ Status)) { 0{"OK"}; 1{"Warning"}; 2{"Error"}; default{"$($_.Status)"} }
            ErrorCount    = sprop $_ ErrorCount
            WarningCount  = sprop $_ WarningCount
            InfoCount     = sprop $_ InfoCount
        }
    })
}

#endregion

#region ── 20. Database Info (optional SQL) ───────────────────────────────────────

Write-Section "Database Info (SQL)"
$report.DatabaseInfo = Invoke-Section "DatabaseInfo" {
    $dbServer = $script:siteDefProps["SQL Server Name"]
    $dbName   = $script:siteDefProps["Database Name"]

    $dbInfo = [ordered]@{
        SQLServerName = $dbServer
        DatabaseName  = $dbName
        SQLSSBPort    = $script:siteDefProps["SQL SSB Port"]
    }

    if (-not $dbServer -or -not $dbName) {
        $dbInfo.SQLConnectionStatus = "Skipped: SQL server/database name not found in site definition"
        return $dbInfo
    }

    try {
        $connStr = "Server=$dbServer;Database=$dbName;Integrated Security=True;Connect Timeout=15;Application Name=MECMConfigSnapshot"
        $conn    = New-Object System.Data.SqlClient.SqlConnection $connStr
        $conn.Open()
        $dbInfo.SQLConnectionStatus = "OK"

        $sqlQueries = [ordered]@{
            SQLServerVersion = "SELECT @@VERSION AS Version"
            SQLEditionInfo   = "SELECT CAST(SERVERPROPERTY('Edition')       AS NVARCHAR(256)) AS Edition,
                                       CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) AS ProductVersion,
                                       CAST(SERVERPROPERTY('Collation')      AS NVARCHAR(128)) AS Collation,
                                       CAST(SERVERPROPERTY('IsClustered')    AS INT)           AS IsClustered,
                                       CAST(SERVERPROPERTY('IsHadrEnabled')  AS INT)           AS IsAlwaysOnEnabled"
            SQLMaxMemoryMB   = "SELECT value_in_use AS MaxServerMemoryMB FROM sys.configurations WHERE name = 'max server memory (MB)'"
            DatabaseSize     = "SELECT DB_NAME() AS DatabaseName,
                                       CAST(SUM(CASE WHEN type_desc='ROWS' THEN size END) * 8.0 / 1024 AS DECIMAL(18,2)) AS DataFileSizeMB,
                                       CAST(SUM(CASE WHEN type_desc='LOG'  THEN size END) * 8.0 / 1024 AS DECIMAL(18,2)) AS LogFileSizeMB
                                FROM sys.database_files"
            MECMBuildHistory = "SELECT TOP 5 PackageGuid, BuildNumber, UpdateVersion, State, DateCreated
                                FROM dbo.CM_UpdatePackages ORDER BY BuildNumber DESC"
        }

        foreach ($qName in $sqlQueries.Keys) {
            try {
                $cmd                = $conn.CreateCommand()
                $cmd.CommandText    = $sqlQueries[$qName]
                $cmd.CommandTimeout = 30
                $reader             = $cmd.ExecuteReader()
                $rows               = @()
                while ($reader.Read()) {
                    $row = [ordered]@{}
                    for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                        $row[$reader.GetName($i)] = $reader.GetValue($i).ToString()
                    }
                    $rows += $row
                }
                $reader.Close()
                $dbInfo[$qName] = if ($rows.Count -eq 1) { $rows[0] } else { $rows }
            } catch {
                $dbInfo[$qName] = "Unable to retrieve data: $($_.Exception.Message)"
            }
        }
        $conn.Close()
    } catch {
        $dbInfo.SQLConnectionStatus = "Unable to connect: $($_.Exception.Message)"
    }

    $dbInfo
}

#endregion

#region ── 21. Logs ──────────────────────────────────────────────────────────────

Write-Section "Log File Analysis (last $LogHoursBack hrs)"
$report.Logs = Invoke-Section "Logs" {

    # ── Discover log directory ────────────────────────────────────────────────
    $logDir = $null
    $regLogging = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SMS\Logging" -ErrorAction SilentlyContinue
    if ($regLogging) { $logDir = $regLogging."Log Directory" }
    if (-not $logDir -or -not (Test-Path $logDir)) {
        $installDir = sprop $report.SiteInfo InstallDir
        if ($installDir) { $logDir = Join-Path $installDir "Logs" }
    }
    if (-not $logDir -or -not (Test-Path $logDir)) {
        $logDir = "C:\Program Files\Microsoft Configuration Manager\Logs"
    }

    # ── CMTrace log line regexes ─────────────────────────────────────────────
    # XML format:    <![LOG[msg]LOG]!><time="H:M:S.ns" date="M-D-YYYY" ... type="N" ... component="X" ...>
    # Simple format: msg  $$<Component><MM-DD-YYYY HH:MM:SS.ms-tz><thread=...>
    $cmtRxXml    = [regex]'<!\[LOG\[(?<msg>.+?)\]LOG\]!><time="(?<time>[0-9:]+)(?:\.[0-9]+)?(?:[+-][0-9]+)?" date="(?<date>[0-9]+-[0-9]+-[0-9]+)"[^>]*?type="(?<type>[0-9])"[^>]*?component="(?<comp>[^"]*)"'
    $cmtRxSimple = [regex]'^(?<msg>.+?)~?\s+\$\$<(?<comp>[^>]+)><(?<date>[0-9]{1,2}-[0-9]{1,2}-[0-9]{4})\s+(?<time>[0-9]{1,2}:[0-9]{2}:[0-9]{2})'

    # ── Keywords for non-error entries ────────────────────────────────────────
    # Warnings are only flagged when they also match one of these.
    # Info entries are only flagged when they match two indicators (keyword + failure word).
    $warnKW = @(
        'failed','failure','exception','access denied','access is denied',
        'unable to','cannot connect','could not connect','timeout','timed out',
        'certificate','ssl','tls','rejected','refused','unavailable','offline',
        'corrupt','account locked','password expired','trust relationship',
        '0x80','0x8007','not found','missing','no space','disk full'
    )

    # ── Log file definitions ──────────────────────────────────────────────────
    # File, friendly label, and optional extra keywords that are always critical
    # regardless of severity level for that specific log.
    $logDefs = @(
        # Site server operations
        [pscustomobject]@{ File="smsexec.log";      Label="SMS Executive"              ; ExtraKW=@('crashed','thread died') }
        [pscustomobject]@{ File="smsprov.log";       Label="SMS Provider"               ; ExtraKW=@('access denied','unauthorised','unauthorized') }
        [pscustomobject]@{ File="smsdbmon.log";      Label="Database Monitor"           ; ExtraKW=@('sql','database','transaction') }
        [pscustomobject]@{ File="hman.log";          Label="Hierarchy Manager"          ; ExtraKW=@() }
        [pscustomobject]@{ File="sitestat.log";      Label="Site Status Summarizer"     ; ExtraKW=@() }
        [pscustomobject]@{ File="compsumm.log";      Label="Component Summarizer"       ; ExtraKW=@() }
        # Replication & communication
        [pscustomobject]@{ File="replmgr.log";       Label="Replication Manager"        ; ExtraKW=@() }
        [pscustomobject]@{ File="objreplmgr.log";    Label="Object Replication Manager" ; ExtraKW=@() }
        [pscustomobject]@{ File="sender.log";        Label="Sender"                     ; ExtraKW=@() }
        # Certificates
        [pscustomobject]@{ File="certmgr.log";       Label="Certificate Manager"        ; ExtraKW=@('expired','invalid','revoked','chain') }
        # Distribution
        [pscustomobject]@{ File="distmgr.log";       Label="Distribution Manager"       ; ExtraKW=@('no space','failed to send') }
        [pscustomobject]@{ File="pkgxfermgr.log";    Label="Package Transfer Manager"   ; ExtraKW=@() }
        [pscustomobject]@{ File="smsdpprov.log";     Label="DP Provider"                ; ExtraKW=@() }
        # Software updates
        [pscustomobject]@{ File="wcm.log";           Label="WSUS Config Manager"        ; ExtraKW=@('sync','certificate','proxy') }
        [pscustomobject]@{ File="wsyncmgr.log";      Label="Update Sync Manager"        ; ExtraKW=@('sync failed','wsus') }
        # Management point
        [pscustomobject]@{ File="mpcontrol.log";     Label="Management Point Control"   ; ExtraKW=@('health','unavailable') }
        [pscustomobject]@{ File="mpfdm.log";         Label="MP Fallback Device Mgr"     ; ExtraKW=@() }
        # Collections & policy
        [pscustomobject]@{ File="colleval.log";      Label="Collection Evaluation"      ; ExtraKW=@('cycle','long','exceeded') }
        [pscustomobject]@{ File="policypv.log";      Label="Policy Provider"            ; ExtraKW=@() }
        [pscustomobject]@{ File="statesys.log";      Label="State System"               ; ExtraKW=@() }
        # Deployments & offers
        [pscustomobject]@{ File="offermgr.log";      Label="Deployment Offer Manager"   ; ExtraKW=@() }
        [pscustomobject]@{ File="schedulermgr.log";  Label="Scheduler Manager"          ; ExtraKW=@() }
    )

    $cutoff          = (Get-Date).AddHours(-$LogHoursBack)
    $logResults      = [ordered]@{}
    $totalErrors     = 0
    $totalWarnings   = 0
    $logsWithIssues  = [System.Collections.Generic.List[string]]::new()

    foreach ($def in $logDefs) {
        $logPath = Join-Path $logDir $def.File
        $key     = $def.File -replace '\.log$',''

        $meta = [ordered]@{
            Label        = $def.Label
            FilePath     = $logPath
            Exists       = (Test-Path $logPath)
            FileSizeKB   = $null
            LastModified = $null
            LinesScanned = 0
            ErrorCount   = 0
            WarningCount = 0
            Entries      = @()
        }

        if (-not $meta.Exists) {
            $logResults[$key] = $meta
            continue
        }

        try {
            $fi               = Get-Item $logPath -ErrorAction Stop
            $meta.FileSizeKB   = [math]::Round($fi.Length / 1KB, 1)
            $meta.LastModified = $fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

            $lines           = Get-Content $logPath -Tail $LogMaxLines -ErrorAction Stop
            $meta.LinesScanned = $lines.Count
            $flagged         = [System.Collections.Generic.List[object]]::new()
            $allParsed       = [System.Collections.Generic.List[object]]::new()
            $allExtraKW      = $def.ExtraKW + $warnKW

            foreach ($line in $lines) {
                $m = $cmtRxXml.Match($line)
                $isSimple = $false
                if (-not $m.Success) {
                    $m = $cmtRxSimple.Match($line)
                    if (-not $m.Success) { continue }
                    $isSimple = $true
                }

                $rawMsg  = $m.Groups['msg'].Value.Trim().TrimEnd('~').Trim()
                $timeStr = $m.Groups['time'].Value
                $dateStr = $m.Groups['date'].Value
                $comp    = $m.Groups['comp'].Value
                $msgL    = $rawMsg.ToLower()

                # Infer severity for simple-format entries (no type field)
                $sev = if ($isSimple) {
                    if ($msgL -match '\berror\b|\bfailed\b|\bfailure\b|\bexception\b') { 3 }
                    elseif ($msgL -match '\bwarning\b|\bwarn\b') { 2 }
                    else { 1 }
                } else { [int]$m.Groups['type'].Value }

                # Parse entry datetime and apply time-window filter
                $dt = $null
                $dtFormats = @("M-d-yyyy HH:mm:ss","MM-dd-yyyy HH:mm:ss","M-d-yyyy H:mm:ss","MM-dd-yyyy H:mm:ss")
                foreach ($fmt in $dtFormats) {
                    try { $dt = [datetime]::ParseExact("$dateStr $timeStr", $fmt, $null); break } catch {}
                }
                if ($dt -and $dt -lt $cutoff) { continue }
                $dtDisplay = if ($dt) { $dt.ToString("yyyy-MM-dd HH:mm:ss") } else { "$dateStr $timeStr" }

                # Decide whether this entry is flagged (error/warning worth highlighting)
                $flag   = $false
                $reason = ""

                if ($sev -eq 3) {
                    $flag   = $true
                    $reason = "Error"
                    $meta.ErrorCount++
                } elseif ($sev -eq 2) {
                    $meta.WarningCount++
                    foreach ($kw in $allExtraKW) {
                        if ($msgL.Contains($kw)) { $flag = $true; $reason = "Warning - $kw"; break }
                    }
                } else {
                    $hasExtra   = $false
                    $hasFailure = ($msgL.Contains("fail") -or $msgL.Contains(" error") -or
                                   $msgL.Contains("unable") -or $msgL.Contains("exception") -or
                                   $msgL.Contains("access denied") -or $msgL.Contains("0x8007"))
                    if ($hasFailure) {
                        foreach ($kw in $def.ExtraKW) {
                            if ($msgL.Contains($kw)) { $hasExtra = $true; break }
                        }
                        if ($hasExtra) { $flag = $true; $reason = "Info (notable)" }
                    }
                }

                $display  = if ($rawMsg.Length -gt 400) { $rawMsg.Substring(0,400) + " [...]" } else { $rawMsg }
                $sevStr   = switch ($sev) { 3{"Error"}; 2{"Warning"}; default{"Info"} }
                $entryObj = [ordered]@{
                    DateTime  = $dtDisplay
                    Severity  = $sevStr
                    Flagged   = $flag
                    Component = $comp
                    Message   = $display
                }
                if ($flag) { $flagged.Add($entryObj) }
                [void]$allParsed.Add($entryObj)
            }

            # Store all parsed entries for the log viewer (newest first, capped at 300 per log)
            $meta.Entries = @($allParsed | Sort-Object DateTime -Descending | Select-Object -First 300)

            if ($meta.ErrorCount -gt 0 -or $flagged.Count -gt 0) {
                [void]$logsWithIssues.Add($def.File)
            }

        } catch {
            $meta.ReadError = "Unable to read: $($_.Exception.Message)"
        }

        $totalErrors   += $meta.ErrorCount
        $totalWarnings += $meta.WarningCount
        $logResults[$key] = $meta
    }

    [ordered]@{
        LogDirectory    = $logDir
        TimeWindowHours = $LogHoursBack
        MaxLinesTailed  = $LogMaxLines
        Summary         = [ordered]@{
            LogsScanned      = ($logDefs | Where-Object { Test-Path (Join-Path $logDir $_.File) }).Count
            LogsNotFound     = ($logDefs | Where-Object { -not (Test-Path (Join-Path $logDir $_.File)) }).Count
            TotalErrors      = $totalErrors
            TotalWarnings    = $totalWarnings
            FlaggedEntries   = ($logResults.Values | ForEach-Object { $_.Entries.Count } | Measure-Object -Sum).Sum
            LogsWithIssues   = @($logsWithIssues)
        }
        LogFiles        = $logResults
    }
}

#endregion

#region ── 23. RBAC ─────────────────────────────────────────────────────────────

Write-Section "RBAC (Admin Users / Roles / Scopes)"
$report.RBAC = Invoke-Section "RBAC" {

    # Admin accounts — .Get() loads lazy string-array properties RoleNames / CategoryNames
    $adminObjs = Invoke-WMI "SMS_Admin"
    $adminList = @($adminObjs | ForEach-Object {
        try { $_.Get() } catch {}
        $roleNames  = @(try { $_.RoleNames      } catch { @() })
        $scopeNames = @(try { $_.CategoryNames  } catch { @() })
        $collNames  = @(try { $_.CollectionNames } catch { @() })
        [ordered]@{
            LogonName       = sprop $_ LogonName
            DisplayName     = sprop $_ DisplayName
            IsGroup         = sprop $_ IsGroup
            Roles           = $roleNames  -join "; "
            Scopes          = $scopeNames -join "; "
            Collections     = $collNames  -join "; "
            CreatedBy       = sprop $_ CreatedBy
            LastModifiedBy  = sprop $_ LastModifiedBy
        }
    })

    # Security roles (all — built-in flag distinguishes default vs custom)
    $roleList = @(Invoke-WMI "SMS_Role" | Sort-Object RoleName | ForEach-Object {
        [ordered]@{
            RoleName    = sprop $_ RoleName
            Description = sprop $_ RoleDescription
            IsBuiltIn   = sprop $_ IsBuiltIn
            CopiedFrom  = sprop $_ CopiedFromID
        }
    })

    # Security scopes
    $scopeList = @(Invoke-WMI "SMS_SecuredCategory" | Sort-Object CategoryName | ForEach-Object {
        [ordered]@{
            Name        = sprop $_ CategoryName
            Description = sprop $_ CategoryDescription
            IsBuiltIn   = sprop $_ IsBuiltIn
        }
    })

    [ordered]@{
        AdminCount     = @($adminList).Count
        AdminUsers     = $adminList
        RoleCount      = @($roleList).Count
        Roles          = $roleList
        ScopeCount     = @($scopeList).Count
        SecurityScopes = $scopeList
    }
}

#endregion

#region ── 24. Automatic Deployment Rules ────────────────────────────────────────

Write-Section "Automatic Deployment Rules"
$report.AutoDeploymentRules = Invoke-Section "AutoDeploymentRules" {

    $adrObjs = Invoke-WMI "SMS_AutoDeployment"
    @($adrObjs | Sort-Object Name | ForEach-Object {
        $lastRun = $null
        try { $lastRun = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.LastRunTime).ToString("yyyy-MM-dd HH:mm:ss") } catch {}
        $lastState = switch ([int](sprop $_ LastRunState)) {
            0{"Unknown"}; 1{"Succeeded"}; 2{"Failed"}; 3{"Running"}; default{"Unknown"}
        }
        [ordered]@{
            Name           = sprop $_ Name
            Description    = sprop $_ Description
            CollectionID   = sprop $_ CollectionID
            CollectionName = sprop $_ CollectionName
            Enabled        = sprop $_ Enabled
            LastRunTime    = $lastRun
            LastRunState   = $lastState
            LastErrorCode  = sprop $_ LastErrorCode
            Schedule       = sprop $_ Schedule
        }
    })
}

#endregion

#region ── 25. Deployments ───────────────────────────────────────────────────────

Write-Section "Deployments"
$report.Deployments = Invoke-Section "Deployments" {

    $depObjs = Invoke-WMI "SMS_DeploymentSummary"

    $typeNameMap = @{
        1="Application"; 2="Program"; 3="MobileProgram"; 4="Script";
        5="SoftwareUpdate"; 6="Baseline"; 8="TaskSequence"; 9="ContentDistribution"
    }
    $byCounts = [ordered]@{}
    foreach ($d in $depObjs) {
        $t = $typeNameMap[[int](sprop $d FeatureType)]
        if (-not $t) { $t = "Other" }
        if ($byCounts.Contains($t)) { $byCounts[$t]++ } else { $byCounts[$t] = 1 }
    }

    $depList = @($depObjs | ForEach-Object {
        $typeName = $typeNameMap[[int](sprop $_ FeatureType)]
        if (-not $typeName) { $typeName = "Other" }
        $intent = switch ([int](sprop $_ DeploymentIntent)) { 1{"Required"}; 2{"Available"}; default{"Unknown"} }
        $dName  = sprop $_ ApplicationName
        if (-not $dName) { $dName = sprop $_ SoftwareName }
        if (-not $dName) { $dName = sprop $_ PackageName  }
        [ordered]@{
            Name             = $dName
            Type             = $typeName
            CollectionName   = sprop $_ CollectionName
            Intent           = $intent
            NumberTargeted   = sprop $_ NumberTargeted
            NumberSuccess    = sprop $_ NumberSuccess
            NumberErrors     = sprop $_ NumberErrors
            NumberInProgress = sprop $_ NumberInProgress
        }
    })

    [ordered]@{
        TotalDeployments = @($depObjs).Count
        ByType           = $byCounts
        Deployments      = $depList
    }
}

#endregion

#region ── 26. Client Communication ─────────────────────────────────────────────

Write-Section "Client Communication"
$report.ClientCommunication = Invoke-Section "ClientCommunication" {

    # Site-level SSL state from SMS_SCI_SiteDefinition
    $siteDef = Invoke-WMI "SMS_SCI_SiteDefinition" -Filter "SiteCode='$SiteCode'" | Select-Object -First 1
    $props   = Get-EmbeddedProps $siteDef

    $sslRaw   = $props["SSLState"]
    $sslMode  = switch ([int]$sslRaw) {
        0{"HTTP (no PKI)"}; 1{"HTTPS (PKI required)"}; 2{"HTTPS or HTTP (Enhanced HTTP eligible)"}
        default { if ($sslRaw -ne $null) { "Unknown ($sslRaw)" } else { "Not configured" } }
    }

    # Enhanced HTTP — stored as UseNewHttp = 1 in site definition Props
    $eHttp = $false
    try {
        $siteDef2 = @(Get-WmiObject -Namespace $script:WmiNS -Class SMS_SCI_SiteDefinition `
                       -Filter "SiteCode='$SiteCode'" -ComputerName $SMSProvider -ErrorAction Stop)
        foreach ($sd in $siteDef2) {
            $sd.Get()
            foreach ($p in @($sd.Props)) {
                if ($p.PropertyName -eq "UseNewHttp" -and $p.Value -eq 1) { $eHttp = $true }
            }
        }
    } catch {}

    # Management Points — count and their roles from sysResources
    $mpList = @($script:sysResources | Where-Object { $_.RoleName -eq "SMS Management Point" } | ForEach-Object {
        [ordered]@{ ServerName = sprop $_ ServerName; SiteCode = sprop $_ SiteCode }
    })

    # Management point SSL details from SMS_SCI_SysResUse
    $mpDetails = @(Invoke-WMI "SMS_SCI_SysResUse" -Filter "RoleName='SMS Management Point' AND SiteCode='$SiteCode'" | ForEach-Object {
        $p = Get-EmbeddedProps $_
        [ordered]@{
            ServerName  = sprop $_ NetworkOSPath
            SSLState    = switch ([int]$p["SSLState"]) { 0{"HTTP"}; 1{"HTTPS"}; default{"Unknown"} }
            UseProxy    = $p["UseProxy"]
        }
    })

    # Distribution Point SSL details (sample — number using HTTPS vs HTTP)
    $dpSSL  = @(Invoke-WMI "SMS_SCI_SysResUse" -Filter "RoleName='SMS Distribution Point' AND SiteCode='$SiteCode'" | ForEach-Object {
        $p = Get-EmbeddedProps $_
        [ordered]@{
            ServerName = sprop $_ NetworkOSPath
            SSLState   = switch ([int]$p["SSLState"]) { 0{"HTTP"}; 1{"HTTPS"}; default{"Unknown"} }
        }
    })
    $dpHttpsCount = @($dpSSL | Where-Object { $_.SSLState -eq "HTTPS" }).Count
    $dpHttpCount  = @($dpSSL | Where-Object { $_.SSLState -eq "HTTP"  }).Count

    [ordered]@{
        SiteSSLMode          = $sslMode
        EnhancedHTTPEnabled  = $eHttp
        ManagementPoints     = $mpDetails
        DPsUsingHTTPS        = $dpHttpsCount
        DPsUsingHTTP         = $dpHttpCount
    }
}

#endregion

#region ── 27. Hardware Inventory Classes ────────────────────────────────────────

Write-Section "Hardware Inventory Classes"
$report.HardwareInventory = Invoke-Section "HardwareInventory" {

    # SMS_InventoryReport with ReportType=1 is the hardware inventory definition
    $hwReport = Invoke-WMI "SMS_InventoryReport" -Filter "ReportType=1" | Select-Object -First 1
    $classList = @()
    $fetchedViaReport = $false

    if ($hwReport) {
        try {
            $hwReport.Get()
            $classList = @($hwReport.SMSInventoryReportClass | ForEach-Object {
                [ordered]@{
                    ClassName      = sprop $_ ClassName
                    SMSClassID     = sprop $_ SMSClassID
                    ReportType     = 1
                }
            })
            $fetchedViaReport = $true
        } catch {}
    }

    # Fallback: directly query SMS_InventoryClass if available
    if (-not $fetchedViaReport -or $classList.Count -eq 0) {
        $classList = @(Invoke-WMI "SMS_InventoryClass" | Sort-Object ClassName | ForEach-Object {
            [ordered]@{
                ClassName  = sprop $_ ClassName
                SMSClassID = sprop $_ SMSClassID
                ReportType = sprop $_ ReportType
            }
        })
    }

    [ordered]@{
        ClassCount = @($classList).Count
        Classes    = $classList
    }
}

#endregion

#region ── 28. Configuration Baselines ──────────────────────────────────────────

Write-Section "Configuration Baselines"
$report.ConfigurationBaselines = Invoke-Section "ConfigurationBaselines" {

    $baselines = Invoke-WMI "SMS_ConfigurationBaselineInfo"
    @($baselines | Sort-Object LocalizedDisplayName | ForEach-Object {
        [ordered]@{
            Name                = sprop $_ LocalizedDisplayName
            Version             = sprop $_ SDMPackageVersion
            IsAssigned          = sprop $_ IsAssigned
            NumberOfDeployments = sprop $_ NumberOfDeployments
            NumberOfCIs         = sprop $_ NumberOfChildCIs
            IsEnabled           = sprop $_ IsEnabled
            DateLastModified    = sprop $_ DateLastModified
            CreatedBy           = sprop $_ CreatedBy
        }
    })
}

#endregion

#region ── 29. Alerts ────────────────────────────────────────────────────────────

Write-Section "Alerts"
$report.Alerts = Invoke-Section "Alerts" {

    $alertObjs = Invoke-WMI "SMS_Alert"
    $subObjs   = Invoke-WMI "SMS_Subscription"

    $alertList = @($alertObjs | Sort-Object Name | ForEach-Object {
        [ordered]@{
            Name          = sprop $_ Name
            TypeID        = sprop $_ TypeID
            Severity      = switch ([int](sprop $_ Severity)) {
                1{"Critical"}; 2{"Warning"}; 3{"Informational"}; default{"Unknown"}
            }
            IsEnabled      = sprop $_ IsEnabled
            IsClosed       = sprop $_ IsClosed
            OccurrenceType = sprop $_ OccurrenceType
        }
    })

    $subList = @($subObjs | Sort-Object Name | ForEach-Object {
        [ordered]@{
            Name      = sprop $_ Name
            TypeID    = sprop $_ TypeID
            EmailTo   = sprop $_ EmailTo
            Locale    = sprop $_ Locale
        }
    })

    [ordered]@{
        AlertCount        = @($alertList).Count
        SubscriptionCount = @($subList).Count
        Alerts            = $alertList
        Subscriptions     = $subList
    }
}

#endregion

#region ── 30. Run Scripts ───────────────────────────────────────────────────────

Write-Section "Run Scripts"
$report.RunScripts = Invoke-Section "RunScripts" {

    $scripts = Invoke-WMI "SMS_Scripts"
    @($scripts | Sort-Object ScriptName | ForEach-Object {
        [ordered]@{
            ScriptName     = sprop $_ ScriptName
            Author         = sprop $_ Author
            Approver       = sprop $_ Approver
            ApprovalState  = switch ([int](sprop $_ ApprovalState)) {
                0{"None"}; 1{"Waiting"}; 2{"Declined"}; 3{"Approved"}; default{"Unknown"}
            }
            ScriptType     = switch ([int](sprop $_ ScriptType)) { 0{"PowerShell"}; default{"Unknown"} }
            LastUpdateTime = sprop $_ LastUpdateTime
            ScriptHash     = sprop $_ ScriptHash
        }
    })
}

#endregion

#region ── 31. Windows Servicing Plans ──────────────────────────────────────────

Write-Section "Windows Servicing Plans"
$report.WindowsServicingPlans = Invoke-Section "WindowsServicingPlans" {

    # Try both class names used across MECM versions
    $plans = Invoke-WMI "SMS_WindowsServicingPlan"
    if ($plans.Count -eq 0) { $plans = Invoke-WMI "SMS_ServicingPlan" }

    @($plans | Sort-Object Name | ForEach-Object {
        $lastRun = $null
        try { $lastRun = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.LastRunTime).ToString("yyyy-MM-dd HH:mm:ss") } catch {}
        [ordered]@{
            Name           = sprop $_ Name
            Description    = sprop $_ Description
            CollectionID   = sprop $_ CollectionID
            CollectionName = sprop $_ CollectionName
            Enabled        = sprop $_ Enabled
            LastRunTime    = $lastRun
            LastRunState   = sprop $_ LastRunState
        }
    })
}

#endregion

#region ── 32. Third-Party Update Catalogs ───────────────────────────────────────

Write-Section "Third-Party Update Catalogs"
$report.ThirdPartyUpdateCatalogs = Invoke-Section "ThirdPartyUpdateCatalogs" {

    $catalogs = Invoke-WMI "SMS_ISVCatalogs"
    @($catalogs | Sort-Object CatalogName | ForEach-Object {
        [ordered]@{
            CatalogName      = sprop $_ CatalogName
            Publisher        = sprop $_ Publisher
            SupportURL       = sprop $_ SupportURL
            Version          = sprop $_ Version
            IsSubscribed     = sprop $_ IsSubscribed
            IsAutoSync       = sprop $_ IsAutoSync
            IsMSFTContent    = sprop $_ IsMSFTContent
        }
    })
}

#endregion

#region ── 33. Co-Management ─────────────────────────────────────────────────────

Write-Section "Co-management Settings"
$report.CoManagement = Invoke-Section "CoManagement" {

    $coMgmt = Invoke-WMI "SMS_CoManagementSettings" | Select-Object -First 1

    # Workload bit flags: 1=CompliancePolicies,2=ResourceAccessPolicies,4=DeviceConfiguration,
    # 8=WindowsUpdatePolicies,16=EndpointProtection,32=ClientApps,64=OfficeApps,128=DeviceEnrollment
    $workloadFlags = [int](sprop $coMgmt CoManagementWorkloads)
    $workloads = [ordered]@{
        CompliancePolicies     = [bool]($workloadFlags -band 1)
        ResourceAccessPolicies = [bool]($workloadFlags -band 2)
        DeviceConfiguration    = [bool]($workloadFlags -band 4)
        WindowsUpdatePolicies  = [bool]($workloadFlags -band 8)
        EndpointProtection     = [bool]($workloadFlags -band 16)
        ClientApps             = [bool]($workloadFlags -band 32)
        OfficeApps             = [bool]($workloadFlags -band 64)
        DeviceEnrollment       = [bool]($workloadFlags -band 128)
    }

    [ordered]@{
        Enabled               = ($null -ne $coMgmt)
        AutoEnroll            = sprop $coMgmt AutoEnroll
        MDMStatus             = sprop $coMgmt MDMStatus
        CoManagementWorkloads = $workloadFlags
        Workloads             = $workloads
    }
}

#endregion

#region ── 34. Content Distribution Status ───────────────────────────────────────

Write-Section "Content Distribution Status"
$report.ContentDistribution = Invoke-Section "ContentDistribution" {

    # Package-level status across all DPs — limit query to avoid huge result sets
    $allStatus = Invoke-WMI "SMS_PackageStatusDistPointsSummarizer"

    $stateMap = @{ 0="Success"; 1="InProgress"; 2="Failed"; 3="Unknown" }

    $summary = [ordered]@{ Success=0; InProgress=0; Failed=0; Unknown=0 }
    foreach ($s in $allStatus) {
        $stateKey = $stateMap[[int](sprop $s State)]
        if (-not $stateKey) { $stateKey = "Unknown" }
        $summary[$stateKey]++
    }

    $pkgTypeMap = @{
        0="Package"; 3="Driver"; 4="TaskSequence"; 8="SoftwareUpdatePackage";
        257="OSImage"; 258="OSInstallPackage"; 259="BootImage"; 512="Application"
    }

    # Failures only — most actionable
    $failures = @($allStatus | Where-Object { [int](sprop $_ State) -eq 2 } | Sort-Object PackageID | ForEach-Object {
        $typeName = $pkgTypeMap[[int](sprop $_ PackageType)]
        if (-not $typeName) { $typeName = "Type$([int](sprop $_ PackageType))" }
        [ordered]@{
            PackageID        = sprop $_ PackageID
            PackageName      = sprop $_ PackageName
            PackageType      = $typeName
            SourceVersion    = sprop $_ SourceVersion
            ServerNALPath    = sprop $_ ServerNALPath
            LastUpdateTime   = sprop $_ LastUpdateTime
        }
    })

    [ordered]@{
        TotalEntries      = @($allStatus).Count
        Summary           = $summary
        FailureCount      = @($failures).Count
        Failures          = $failures
    }
}

#endregion

#region ── 22. Host System ───────────────────────────────────────────────────────

Write-Section "Host System"
$report.HostSystem = Invoke-Section "HostSystem" {

    # Helper: open a registry key, local or remote
    function Open-RegKey ([string]$Hive, [string]$SubKey) {
        try {
            if ($SMSProvider -eq $env:COMPUTERNAME -or $SMSProvider -eq "localhost" -or $SMSProvider -eq ".") {
                $base = if ($Hive -eq "HKLM") { "HKLM:\$SubKey" } else { "HKCU:\$SubKey" }
                Get-ItemProperty $base -ErrorAction Stop
            } else {
                $hiveEnum = if ($Hive -eq "HKLM") { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
                $remReg   = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveEnum, $SMSProvider)
                $key      = $remReg.OpenSubKey($SubKey)
                if ($null -eq $key) { return $null }
                $h = @{}
                foreach ($v in $key.GetValueNames()) { $h[$v] = $key.GetValue($v) }
                [pscustomobject]$h
            }
        } catch { $null }
    }

    function Get-RegValue ([string]$Hive, [string]$SubKey, [string]$Name) {
        try {
            $p = Open-RegKey $Hive $SubKey
            if ($p) { return $p.$Name } else { return $null }
        } catch { $null }
    }

    # ── Win32 WMI shortcuts ───────────────────────────────────────────────────
    function wq ([string]$Class, [string]$Filter="") {
        try {
            $q = if ($Filter) { "SELECT * FROM $Class WHERE $Filter" } else { "SELECT * FROM $Class" }
            @(Get-WmiObject -Namespace "root\CIMV2" -Query $q -ComputerName $SMSProvider -ErrorAction Stop)
        } catch { @() }
    }

    # ── 1. System ─────────────────────────────────────────────────────────────
    $cs  = wq "Win32_ComputerSystem" | Select-Object -First 1
    $bio = wq "Win32_BIOS"           | Select-Object -First 1

    $manufacturer = sprop $cs Manufacturer
    $model        = sprop $cs Model
    $isVirtual    = $false
    $vmPlatform   = "Physical"
    if ($manufacturer -match "VMware")                              { $isVirtual = $true; $vmPlatform = "VMware" }
    elseif ($manufacturer -match "Microsoft" -and $model -match "Virtual") { $isVirtual = $true; $vmPlatform = "Hyper-V" }
    elseif ($manufacturer -match "innotek|VirtualBox")             { $isVirtual = $true; $vmPlatform = "VirtualBox" }
    elseif ($manufacturer -match "QEMU|KVM")                       { $isVirtual = $true; $vmPlatform = "QEMU/KVM" }
    elseif ($model -match "Virtual")                               { $isVirtual = $true; $vmPlatform = "Virtual (unknown)" }

    $sysInfo = [ordered]@{
        ComputerName     = sprop $cs Name
        Domain           = sprop $cs Domain
        Manufacturer     = $manufacturer
        Model            = $model
        IsVirtual        = $isVirtual
        VirtualPlatform  = $vmPlatform
        TotalSockets     = sprop $cs NumberOfProcessors
        LogicalProcessors = sprop $cs NumberOfLogicalProcessors
        BIOSManufacturer = sprop $bio Manufacturer
        BIOSVersion      = sprop $bio SMBIOSBIOSVersion
        BIOSReleaseDate  = sprop $bio ReleaseDate
    }

    # ── 2. Operating System ───────────────────────────────────────────────────
    $os = wq "Win32_OperatingSystem" | Select-Object -First 1

    $lastBoot    = $null
    $uptimeDays  = $null
    try {
        $lastBoot   = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        $uptimeDays = [math]::Round(((Get-Date) - $lastBoot).TotalDays, 1)
        $lastBoot   = $lastBoot.ToString("yyyy-MM-dd HH:mm:ss")
    } catch {}

    $installDate = $null
    try { $installDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate).ToString("yyyy-MM-dd") } catch {}

    $osTotalMemGB = $null
    $osFreeMemGB  = $null
    $osTZ         = $null
    try { $osTotalMemGB = [math]::Round([long](sprop $os TotalVisibleMemorySize) / 1MB, 2) } catch {}
    try { $osFreeMemGB  = [math]::Round([long](sprop $os FreePhysicalMemory)      / 1MB, 2) } catch {}
    try { $osTZ         = (wq "Win32_TimeZone" | Select-Object -First 1).Caption } catch {}

    $osInfo = [ordered]@{
        Caption          = sprop $os Caption
        Version          = sprop $os Version
        BuildNumber      = sprop $os BuildNumber
        ServicePackMajor = sprop $os ServicePackMajorVersion
        Architecture     = sprop $os OSArchitecture
        InstallDate      = $installDate
        LastBootTime     = $lastBoot
        UptimeDays       = $uptimeDays
        TotalVisibleMemGB = $osTotalMemGB
        FreePhysMemGB    = $osFreeMemGB
        SystemDrive      = sprop $os SystemDrive
        WindowsDirectory = sprop $os WindowsDirectory
        TimeZone         = $osTZ
    }

    # ── 3. CPU ────────────────────────────────────────────────────────────────
    $procs = wq "Win32_Processor"

    $cpuName   = $null; try { $cpuName   = ($procs | Select-Object -First 1).Name.Trim() } catch {}
    $cpuPCores = $null; try { $cpuPCores = ($procs | Measure-Object -Property NumberOfCores -Sum).Sum } catch {}
    $cpuLProcs = $null; try { $cpuLProcs = ($procs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum } catch {}
    $cpuMHz    = $null; try { $cpuMHz    = ($procs | Select-Object -First 1).MaxClockSpeed } catch {}
    $cpuLoad   = $null; try { $cpuLoad   = ($procs | Measure-Object -Property LoadPercentage -Average).Average } catch {}
    $cpuL2     = $null; try { $cpuL2     = ($procs | Select-Object -First 1).L2CacheSize } catch {}
    $cpuL3     = $null; try { $cpuL3     = ($procs | Select-Object -First 1).L3CacheSize } catch {}

    $cpuInfo = [ordered]@{
        ProcessorCount    = @($procs).Count
        Name              = $cpuName
        PhysicalCores     = $cpuPCores
        LogicalProcessors = $cpuLProcs
        MaxClockSpeedMHz  = $cpuMHz
        CurrentLoadPct    = $cpuLoad
        L2CacheSizeKB     = $cpuL2
        L3CacheSizeKB     = $cpuL3
    }

    # ── 4. Memory modules ─────────────────────────────────────────────────────
    $dimms = wq "Win32_PhysicalMemory"

    $memTotalGB = $null
    try { $memTotalGB = [math]::Round(($dimms | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2) } catch {}

    $memModules = @($dimms | ForEach-Object {
        $speedMHz  = $null
        try { $speedMHz = $_.ConfiguredClockSpeed } catch {}
        if (-not $speedMHz) { try { $speedMHz = $_.Speed } catch {} }
        $modCapGB  = $null; try { $modCapGB  = [math]::Round([long](sprop $_ Capacity) / 1GB, 2) } catch {}
        $modPartNo = $null; try { $modPartNo = (sprop $_ PartNumber).Trim() } catch {}
        $modType   = switch ([int](sprop $_ SMBIOSMemoryType)) {
            20 { "DDR" }; 21 { "DDR2" }; 24 { "DDR3" }; 26 { "DDR4" }; 34 { "DDR5" }
            default { sprop $_ MemoryType }
        }
        [ordered]@{
            BankLabel     = sprop $_ BankLabel
            DeviceLocator = sprop $_ DeviceLocator
            CapacityGB    = $modCapGB
            SpeedMHz      = $speedMHz
            MemoryType    = $modType
            Manufacturer  = sprop $_ Manufacturer
            PartNumber    = $modPartNo
        }
    })

    $memoryInfo = [ordered]@{
        TotalInstalledGB = $memTotalGB
        ModuleCount      = @($dimms).Count
        Modules          = $memModules
    }

    # ── 5. Logical disks ─────────────────────────────────────────────────────
    $logDisks = wq "Win32_LogicalDisk" -Filter "DriveType=3"
    $diskInfo = @($logDisks | Sort-Object DeviceID | ForEach-Object {
        $sizeGB  = try { [math]::Round([long](sprop $_ Size)      / 1GB, 2) } catch { $null }
        $freeGB  = try { [math]::Round([long](sprop $_ FreeSpace) / 1GB, 2) } catch { $null }
        $freePct = try { [math]::Round($freeGB / $sizeGB * 100, 1) } catch { $null }
        [ordered]@{
            Drive       = sprop $_ DeviceID
            Label       = sprop $_ VolumeName
            FileSystem  = sprop $_ FileSystem
            SizeGB      = $sizeGB
            FreeGB      = $freeGB
            FreePercent = $freePct
        }
    })

    # ── 6. Physical disks ────────────────────────────────────────────────────
    $physDisks = wq "Win32_DiskDrive"
    $physDiskInfo = @($physDisks | Sort-Object Index | ForEach-Object {
        $sizeGB   = try { [math]::Round([long](sprop $_ Size) / 1GB, 2) } catch { $null }
        $mediaStr = sprop $_ MediaType
        [ordered]@{
            Index      = sprop $_ Index
            Model      = sprop $_ Model
            SizeGB     = $sizeGB
            MediaType  = $mediaStr
            Partitions = sprop $_ Partitions
            Interface  = sprop $_ InterfaceType
        }
    })

    # ── 7. Network adapters ──────────────────────────────────────────────────
    $nics = wq "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled=True"
    $netInfo = @($nics | ForEach-Object {
        $nic_ips = @(try { $_.IPAddress             } catch { @() })
        $nic_sub = @(try { $_.IPSubnet              } catch { @() })
        $nic_gws = @(try { $_.DefaultIPGateway      } catch { @() })
        $nic_dns = @(try { $_.DNSServerSearchOrder  } catch { @() })
        [ordered]@{
            Description  = sprop $_ Description
            MACAddress   = sprop $_ MACAddress
            IPAddresses  = $nic_ips
            SubnetMasks  = $nic_sub
            Gateways     = $nic_gws
            DNSServers   = $nic_dns
            DHCPEnabled  = sprop $_ DHCPEnabled
            DHCPServer   = sprop $_ DHCPServer
        }
    })

    # ── 8. .NET Framework ────────────────────────────────────────────────────
    $netRelease = Get-RegValue "HKLM" "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release"
    $netVersion = switch ([int]$netRelease) {
        {$_ -ge 533320} { "4.8.1"; break }
        {$_ -ge 528040} { "4.8";   break }
        {$_ -ge 461808} { "4.7.2"; break }
        {$_ -ge 461308} { "4.7.1"; break }
        {$_ -ge 460798} { "4.7";   break }
        {$_ -ge 394802} { "4.6.2"; break }
        {$_ -ge 394254} { "4.6.1"; break }
        {$_ -ge 393295} { "4.6";   break }
        {$_ -ge 379893} { "4.5.2"; break }
        {$_ -ge 378675} { "4.5.1"; break }
        {$_ -ge 378389} { "4.5";   break }
        default         { if ($netRelease) { "Unknown (release=$netRelease)" } else { "Not detected" } }
    }
    $dotNetInfo = [ordered]@{
        HighestVersion = $netVersion
        ReleaseKey     = $netRelease
    }

    # ── 9. IIS ───────────────────────────────────────────────────────────────
    $iisMajor = Get-RegValue "HKLM" "SOFTWARE\Microsoft\InetStp" "MajorVersion"
    $iisMinor = Get-RegValue "HKLM" "SOFTWARE\Microsoft\InetStp" "MinorVersion"
    $iisInfo  = [ordered]@{
        Installed = ($null -ne $iisMajor)
        Version   = if ($iisMajor) { "$iisMajor.$iisMinor" } else { "Not installed" }
    }

    # ── 10. SQL Server instances ─────────────────────────────────────────────
    $sqlInstances = @()
    try {
        $sqlRegBase  = "SOFTWARE\Microsoft\Microsoft SQL Server"
        $sqlInstProp = Open-RegKey "HKLM" "$sqlRegBase\Instance Names\SQL"
        if ($sqlInstProp) {
            $instNames = $sqlInstProp | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue |
                         Select-Object -Expand Name |
                         Where-Object { $_ -notmatch '^PS' }
            foreach ($inst in $instNames) {
                $instKey   = $sqlInstProp.$inst          # e.g. MSSQL16.MSSQLSERVER
                $verProp   = Open-RegKey "HKLM" "$sqlRegBase\$instKey\MSSQLServer\CurrentVersion"
                $ver       = if ($verProp) { $verProp.CurrentVersion } else { $null }
                $svcName   = if ($inst -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$inst" }
                $svc       = wq "Win32_Service" -Filter "Name='$svcName'" | Select-Object -First 1
                $sqlInstances += [ordered]@{
                    InstanceName = $inst
                    RegistryKey  = $instKey
                    Version      = $ver
                    ServiceName  = $svcName
                    State        = sprop $svc State
                    StartMode    = sprop $svc StartMode
                    StartName    = sprop $svc StartName
                }
            }
        }
    } catch {}

    # SQL Agent services
    $sqlAgents = @(wq "Win32_Service" -Filter "Name LIKE 'SQLAgent%'" | ForEach-Object {
        [ordered]@{
            ServiceName = sprop $_ Name
            State       = sprop $_ State
            StartMode   = sprop $_ StartMode
            StartName   = sprop $_ StartName
        }
    })

    # ── 11. Windows Features (MECM-relevant) ─────────────────────────────────
    $mecmFeatures = @(
        'NET-Framework-Core','NET-Framework-45-Core','NET-Framework-45-ASPNET',
        'NET-WCF-HTTP-Activation45','NET-WCF-Pipe-Activation45','NET-WCF-TCP-Activation45',
        'Web-Server','Web-Metabase','Web-WMI','Web-Windows-Auth',
        'Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Net-Ext45','Web-Asp-Net45',
        'Web-Http-Redirect','Web-DAV-Publishing',
        'BITS','BITS-IIS-Ext','BITS-Compact-Server',
        'RDC','Remote-Desktop-Services',
        'WDS','WDS-Deployment','WDS-Transport',
        'WSUS-Services'
    )
    $featureResults = [ordered]@{}
    try {
        Import-Module ServerManager -ErrorAction Stop
        foreach ($feat in $mecmFeatures) {
            $r = Get-WindowsFeature -Name $feat -ComputerName $SMSProvider -ErrorAction SilentlyContinue
            if ($r) { $featureResults[$feat] = $r.InstallState.ToString() }
        }
    } catch {
        $featureResults["_Error"] = "ServerManager module unavailable: $($_.Exception.Message)"
    }

    # ── 12. Time sync / NTP ───────────────────────────────────────────────────
    $ntpServer = Get-RegValue "HKLM" "SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "NtpServer"
    $ntpType   = Get-RegValue "HKLM" "SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "Type"
    $tzInfo     = wq "Win32_TimeZone" | Select-Object -First 1
    $tsOffset   = $null
    try { $tsOffset = [math]::Round((sprop $tzInfo Bias) / -60, 1) } catch {}
    $timeSyncInfo = [ordered]@{
        NTPServer = $ntpServer
        NTPType   = $ntpType
        TimeZone  = sprop $tzInfo Caption
        UTCOffset = $tsOffset
    }

    # ── 13. Pending reboot check ──────────────────────────────────────────────
    $pendingReboot = $false
    $pendingReasons = @()
    $cbsKey  = Open-RegKey "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $wuKey   = Open-RegKey "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $pfroKey = Open-RegKey "HKLM" "SYSTEM\CurrentControlSet\Control\Session Manager"
    if ($cbsKey)  { $pendingReboot = $true; $pendingReasons += "CBS (Component Based Servicing)" }
    if ($wuKey)   { $pendingReboot = $true; $pendingReasons += "Windows Update" }
    if ($pfroKey -and $pfroKey.PendingFileRenameOperations) { $pendingReboot = $true; $pendingReasons += "Pending File Rename Operations" }

    # ── Assemble result ───────────────────────────────────────────────────────
    [ordered]@{
        System          = $sysInfo
        OperatingSystem = $osInfo
        CPU             = $cpuInfo
        Memory          = $memoryInfo
        LogicalDisks    = $diskInfo
        PhysicalDisks   = $physDiskInfo
        Network         = $netInfo
        DotNetFramework = $dotNetInfo
        IIS             = $iisInfo
        SQLInstances    = $sqlInstances
        SQLAgents       = $sqlAgents
        WindowsFeatures = $featureResults
        TimeSync        = $timeSyncInfo
        PendingReboot   = $pendingReboot
        PendingRebootReasons = $pendingReasons
    }
}

#endregion

#region ── 35. Site Maintenance Tasks ────────────────────────────────────────────

Write-Section "Site Maintenance Tasks"
$report.SiteMaintenanceTasks = Invoke-Section "SiteMaintenanceTasks" {
    $tasks = Invoke-WMI "SMS_SCI_SQLTask" -Filter "SiteCode='$SiteCode'"
    $dowLabels = @('Sun','Mon','Tue','Wed','Thu','Fri','Sat')
    @($tasks | Sort-Object TaskName | ForEach-Object {
        $dow = try { [int](sprop $_ DaysOfWeek) } catch { 0 }
        $dowStr = @(0..6 | Where-Object { $dow -band [math]::Pow(2, $_) } | ForEach-Object { $dowLabels[$_] }) -join ', '
        [ordered]@{
            TaskName        = sprop $_ TaskName
            IsEnabled       = sprop $_ IsEnabled
            DaysOfWeek      = $dow
            DaysOfWeekText  = $dowStr
            BeginTime       = sprop $_ BeginTime
            LatestBeginTime = sprop $_ LatestBeginTime
            NumRefreshDays  = sprop $_ NumRefreshDays
        }
    })
}

#endregion

#region ── 36. Software Update Groups ────────────────────────────────────────────

Write-Section "Software Update Groups"
$report.SoftwareUpdateGroups = Invoke-Section "SoftwareUpdateGroups" {
    $sugs = Invoke-WMI "SMS_AuthorizationList"
    [ordered]@{
        Count  = $sugs.Count
        Groups = @($sugs | Sort-Object LocalizedDisplayName | ForEach-Object {
            [ordered]@{
                Name             = sprop $_ LocalizedDisplayName
                Description      = sprop $_ LocalizedDescription
                NumberOfUpdates  = sprop $_ NumberOfUpdates
                IsDeployed       = sprop $_ IsDeployed
                IsExpired        = sprop $_ IsExpired
                DateCreated      = sprop $_ DateCreated
                DateLastModified = sprop $_ DateLastModified
                CreatedBy        = sprop $_ CreatedBy
                LastModifiedBy   = sprop $_ LastModifiedBy
            }
        })
    }
}

#endregion

#region ── 37. Status Message Filter Rules ───────────────────────────────────────

Write-Section "Status Message Filter Rules"
$report.StatusFilterRules = Invoke-Section "StatusFilterRules" {
    $statusMgr = Invoke-WMI "SMS_SCI_Component" -Filter "SiteCode='$SiteCode' AND ComponentName='SMS_STATUS_MANAGER'" |
                 Select-Object -First 1

    $managerProps     = [ordered]@{}
    $managerPropLists = [ordered]@{}

    if ($statusMgr) {
        try { $statusMgr.Get() } catch {}
        $managerProps     = Get-EmbeddedProps     $statusMgr
        $managerPropLists = Get-EmbeddedPropLists $statusMgr
    }

    [ordered]@{
        ComponentProps     = $managerProps
        ComponentPropLists = $managerPropLists
    }
}

#endregion

#region ── 38. Certificates ──────────────────────────────────────────────────────

Write-Section "Site Certificates"
$report.Certificates = Invoke-Section "Certificates" {
    $certs = Invoke-WMI "SMS_CertificateData"
    @($certs | Sort-Object FQDN, CertificateType | ForEach-Object {
        $validFrom  = $null
        $validUntil = $null
        try { $validFrom  = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.ValidFromDate).ToString("yyyy-MM-dd") } catch {}
        try { $validUntil = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.ValidUntilDate).ToString("yyyy-MM-dd") } catch {}
        [ordered]@{
            FQDN            = sprop $_ FQDN
            CertificateType = sprop $_ CertificateType
            Thumbprint      = sprop $_ Thumbprint
            IssuedTo        = sprop $_ IssuedTo
            IssuedBy        = sprop $_ IssuedBy
            ValidFrom       = $validFrom
            ValidUntil      = $validUntil
            IsBlocked       = sprop $_ IsBlocked
        }
    })
}

#endregion

#region ── 39. IIS Configuration ─────────────────────────────────────────────────

Write-Section "IIS Configuration"
$report.IISConfiguration = Invoke-Section "IISConfiguration" {
    $iisData = [ordered]@{}

    $regIIS = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue
    $iisData.Version    = if ($regIIS) { "$($regIIS.MajorVersion).$($regIIS.MinorVersion)" } else { "Not detected" }
    $iisData.InstallPath = if ($regIIS) { $regIIS.InstallPath } else { $null }
    $iisData.W3SVCState = try { (Get-Service W3SVC -ErrorAction Stop).Status.ToString() } catch { "Unknown" }
    $iisData.WASState   = try { (Get-Service WAS   -ErrorAction Stop).Status.ToString() } catch { "Unknown" }

    $modAvail = $false
    try { Import-Module WebAdministration -ErrorAction Stop; $modAvail = $true } catch {}
    $iisData.WebAdminModuleAvailable = $modAvail

    if ($modAvail) {
        $iisData.Websites = @(Get-Website -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
            [ordered]@{
                Name         = $_.Name
                ID           = $_.ID
                State        = $_.State
                PhysicalPath = $_.PhysicalPath
                Bindings     = ($_.Bindings.Collection | ForEach-Object { "$($_.Protocol)/$($_.BindingInformation)" }) -join "; "
            }
        })

        $iisData.ApplicationPools = @(Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
            [ordered]@{
                Name           = $_.Name
                State          = $_.State
                ManagedRuntime = $_.ManagedRuntimeVersion
                PipelineMode   = $_.ManagedPipelineMode
                IdentityType   = $_.ProcessModel.IdentityType
                IdentityUser   = $(try { $_.ProcessModel.UserName } catch { $null })
                StartMode      = $_.StartMode
                Enable32Bit    = $_.Enable32BitAppOnWin64
            }
        })

        $iisData.MECMApplications = @(try {
            Get-WebApplication -ErrorAction SilentlyContinue | Where-Object {
                $_.Path -match 'SMS|CCM|WSUS|ConfigMgr|Incoming|Outgoing|SMS_MP|SMS_DP' -or
                $_.PhysicalPath -match 'SMS|ConfigMgr'
            } | Sort-Object { "$($_.GetParentElement().Attributes['name'].Value)$($_.Path)" } | ForEach-Object {
                [ordered]@{
                    Site         = $(try { $_.GetParentElement().Attributes['name'].Value } catch { '?' })
                    AppPath      = $_.Path
                    PhysicalPath = $_.PhysicalPath
                    AppPool      = $_.ApplicationPool
                }
            }
        } catch { @() })

        $iisData.SSLBindings = @(Get-ChildItem IIS:\SslBindings -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{
                IPPort     = "$($_.IPAddress):$($_.Port)"
                Thumbprint = $_.Thumbprint
                Host       = $_.Host
            }
        })
    }

    $iisData
}

#endregion

#region ── 40. WSUS Configuration ────────────────────────────────────────────────

Write-Section "WSUS Configuration"
$report.WSUSConfiguration = Invoke-Section "WSUSConfiguration" {
    $wsusData = [ordered]@{}

    $wsusSetup = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup" -ErrorAction SilentlyContinue
    if ($wsusSetup) {
        $wsusData.ContentDir      = $wsusSetup.ContentDir
        $wsusData.TargetDir       = $wsusSetup.TargetDir
        $wsusData.SqlServerName   = $wsusSetup.SqlServerName
        $wsusData.SqlInstanceName = $wsusSetup.SqlInstanceName
        $wsusData.UsingSSL        = $wsusSetup.UsingSSL
        $wsusData.PortNumber      = $wsusSetup.PortNumber
        $wsusData.ProductVersion  = $wsusSetup.ProductVersion
    } else {
        $wsusData._Note = "WSUS setup registry key not found — WSUS may not be installed on this server"
    }

    foreach ($svcName in @("WsusService","W3SVC","wuauserv","BITS")) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        $wsusData["Service_$svcName"] = if ($svc) { $svc.Status.ToString() } else { "Not installed" }
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop
        $wsusPool = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'WSUS' } | Select-Object -First 1
        if ($wsusPool) {
            $wsusData.WSUSAppPoolState          = $wsusPool.State
            $wsusData.WSUSAppPoolManagedRuntime = $wsusPool.ManagedRuntimeVersion
        }
        $wsusSite = Get-Website -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'WSUS' -or
                        ($_.Bindings.Collection | Where-Object { $_.BindingInformation -match ':853[01]:' }) }
        if ($wsusSite) {
            $ws = $wsusSite | Select-Object -First 1
            $wsusData.WSUSWebsite      = $ws.Name
            $wsusData.WSUSWebsiteState = $ws.State
            $wsusData.WSUSBindings     = ($ws.Bindings.Collection | ForEach-Object { "$($_.Protocol)/$($_.BindingInformation)" }) -join "; "
        }
    } catch {}

    $wuPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    if ($wuPolicy) {
        $wsusData.GPO_WUServer        = $wuPolicy.WUServer
        $wsusData.GPO_WUStatusServer  = $wuPolicy.WUStatusServer
        $wsusData.GPO_DisableWUAccess = $wuPolicy.DisableWindowsUpdateAccess
        $wsusData.GPO_ElevateNonAdmins = $wuPolicy.ElevateNonAdmins
    }
    $wuAU = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    if ($wuAU) {
        $wsusData.GPO_NoAutoUpdate         = $wuAU.NoAutoUpdate
        $wsusData.GPO_AUOptions            = $wuAU.AUOptions
        $wsusData.GPO_UseWUServer          = $wuAU.UseWUServer
        $wsusData.GPO_ScheduledInstallDay  = $wuAU.ScheduledInstallDay
        $wsusData.GPO_ScheduledInstallTime = $wuAU.ScheduledInstallTime
    }

    $contentDir = if ($wsusSetup) { $wsusSetup.ContentDir } else { $null }
    if ($contentDir) {
        $drive = [System.IO.Path]::GetPathRoot($contentDir)
        $disk  = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($drive.TrimEnd('\'))'" -ErrorAction SilentlyContinue
        if ($disk) {
            $wsusData.ContentDirDrive        = $drive
            $wsusData.ContentDirDriveSizeGB  = [math]::Round([long]$disk.Size      / 1GB, 2)
            $wsusData.ContentDirDriveFreeGB  = [math]::Round([long]$disk.FreeSpace / 1GB, 2)
            $wsusData.ContentDirDriveFreePct = [math]::Round([long]$disk.FreeSpace / [long]$disk.Size * 100, 1)
        }
    }

    $wsusData
}

#endregion

#region ── 41. Content Store ─────────────────────────────────────────────────────

Write-Section "Content Store (DP Content Libraries)"
$report.ContentStore = Invoke-Section "ContentStore" {
    $csData = [ordered]@{}

    $dpInfos = Invoke-WMI "SMS_DistributionPointInfo"
    $csData.DistributionPoints = @($dpInfos | Sort-Object ServerName | ForEach-Object {
        [ordered]@{
            ServerName            = sprop $_ ServerName
            ContentLibPath        = sprop $_ ContentLibPath
            AvailContentLibDiskGB = sprop $_ AvailContentLibDiskGB
            IsPXE                 = sprop $_ IsPXE
            IsMulticast           = sprop $_ IsMulticast
            IsPullDP              = sprop $_ IsPullDP
            IsActive              = sprop $_ IsActive
        }
    })

    # Package distribution status summary
    $distStatus = Invoke-WMI "SMS_PackageStatusDistPointsSummarizer"
    $summary    = [ordered]@{ Success=0; InProgress=0; Failed=0; Unknown=0; Total=0 }
    foreach ($s in $distStatus) {
        switch ([int](sprop $s State)) {
            0 { $summary.Success++ }
            1 { $summary.InProgress++ }
            2 { $summary.Failed++ }
            default { $summary.Unknown++ }
        }
        $summary.Total++
    }
    $csData.PackageStatusSummary = $summary

    # Package source path accessibility (capped at 200 to keep runtime reasonable)
    $pkgs     = Invoke-WMI "SMS_Package"
    $srcCheck = @($pkgs | Where-Object { $_.PkgSourcePath } | Select-Object -First 200 |
        Sort-Object Name | ForEach-Object {
            $path = sprop $_ PkgSourcePath
            $ok   = try { Test-Path $path } catch { $false }
            [ordered]@{
                PackageName = sprop $_ Name
                PackageID   = sprop $_ PackageID
                SourcePath  = $path
                Accessible  = $ok
            }
        })
    $csData.PackageSourceSample      = $srcCheck
    $csData.InaccessibleSourceCount  = @($srcCheck | Where-Object { -not $_.Accessible }).Count
    $csData.PackageSourceSampleLimit = 200

    $csData
}

#endregion

#region ── 42. Group Policy Settings ─────────────────────────────────────────────

Write-Section "Group Policy Settings (MECM-relevant)"
$report.GroupPolicySettings = Invoke-Section "GroupPolicySettings" {
    $gpData = [ordered]@{}

    $regPaths = [ordered]@{
        WindowsUpdate   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        WUAutoUpdate    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        BITS            = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\BITS"
        WindowsFirewall = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        RemoteDesktop   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        WinDefender     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        SCEPAntimalware = "HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware"
        SMBClient       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
        MECM_Client     = "HKLM:\SOFTWARE\Policies\Microsoft\CCMSetup"
    }

    foreach ($rp in $regPaths.GetEnumerator()) {
        $props = Get-ItemProperty $rp.Value -ErrorAction SilentlyContinue
        if ($props) {
            $h = [ordered]@{}
            try {
                $props | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        try { $h[$_.Name] = "$($props.($_.Name))" } catch {}
                    }
            } catch {}
            $gpData[$rp.Key] = if ($h.Count -gt 0) { $h } else { [ordered]@{ _Status = "Key present but no values" } }
        } else {
            $gpData[$rp.Key] = [ordered]@{ _Status = "Not configured (key absent)" }
        }
    }

    # Computer-scope RSoP via gpresult — first 60 lines
    $gpData.RSoPComputerSummary = try {
        ($( & gpresult /r /scope computer ) | Select-Object -First 60) -join "`n"
    } catch {
        "gpresult unavailable: $($_.Exception.Message)"
    }

    $gpData
}

#endregion

#region ── 43. Health Checks (CI Baseline) ────────────────────────────────────────

Write-Section "Health Checks (CI Baseline)"
$report.HealthChecks = Invoke-Section "HealthChecks" {

    # Resolve site prefix from parameter or auto-detect from computer name
    $effectivePrefix = if ($SitePrefix) { $SitePrefix } else {
        if ($env:COMPUTERNAME -match '^([A-Za-z]{3,4})') { $Matches[1] } else { "" }
    }

    # Load IIS modules best-effort
    $null = try { Import-Module WebAdministration -ErrorAction Stop } catch {}
    $null = try { Import-Module IISAdministration  -ErrorAction Stop } catch {}

    # Extract certificate template name from a cert object
    function Get-CertTemplateName ([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
        $ext = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -match "Certificate Template" }
        if (-not $ext) { return "" }
        $raw = try { $ext.Format(0) } catch { return "" }
        if ($raw -match '=\s*([^(]+)') { return $Matches[1].Trim() }
        return ""
    }

    $checks = [System.Collections.Generic.List[hashtable]]::new()

    function Add-Check ([string]$Name, [string]$Category, [string]$Status, [string]$Detail = "") {
        $checks.Add(@{ Name = $Name; Category = $Category; Status = $Status; Detail = $Detail })
    }

    # ── Services ──────────────────────────────────────────────────────────────────
    foreach ($svcDef in @(
        @{ Name = "IISADMIN"; Label = "Service: IIS Admin (IISADMIN)" },
        @{ Name = "WDSServer"; Label = "Service: Windows Deployment Services (WDSServer)" },
        @{ Name = "CcmExec";  Label = "Service: SMS Agent Host (CcmExec)" }
    )) {
        try {
            $svc = Get-Service -Name $svcDef.Name -ErrorAction SilentlyContinue
            if (-not $svc) {
                Add-Check $svcDef.Label "Services" "NotInstalled" "Service not found on this system"
            } elseif ($svc.Status -eq 'Running') {
                Add-Check $svcDef.Label "Services" "Pass" "Running"
            } else {
                Add-Check $svcDef.Label "Services" "Fail" "Status: $($svc.Status)"
            }
        } catch {
            Add-Check $svcDef.Label "Services" "Error" $_.Exception.Message
        }
    }

    # ── IIS Application Pools ─────────────────────────────────────────────────────
    foreach ($poolDef in @(
        @{ Name = "DefaultAppPool";               Label = "App Pool: DefaultAppPool" },
        @{ Name = "SMS Distribution Points Pool"; Label = "App Pool: SMS Distribution Points Pool" }
    )) {
        try {
            $poolState = $null
            # IISAdministration first, WebAdministration fallback
            try {
                $pool = Get-IISAppPool $poolDef.Name -ErrorAction Stop
                $poolState = $pool.State.ToString()
            } catch {
                try {
                    $poolState = (Get-WebAppPoolState $poolDef.Name -ErrorAction Stop).Value
                } catch { $poolState = $null }
            }

            if ($null -eq $poolState) {
                Add-Check $poolDef.Label "AppPools" "NotInstalled" "App pool not found"
            } elseif ($poolState -eq 'Started') {
                Add-Check $poolDef.Label "AppPools" "Pass" "Started"
            } else {
                Add-Check $poolDef.Label "AppPools" "Fail" "State: $poolState"
            }
        } catch {
            Add-Check $poolDef.Label "AppPools" "Error" $_.Exception.Message
        }
    }

    # ── Windows Features ──────────────────────────────────────────────────────────
    foreach ($featDef in @(
        @{ Name = "Web-Server"; Label = "Feature: Web Server (IIS)" },
        @{ Name = "WDS";        Label = "Feature: Windows Deployment Services" }
    )) {
        try {
            $feat = Get-WindowsFeature -Name $featDef.Name -ErrorAction SilentlyContinue
            if (-not $feat) {
                Add-Check $featDef.Label "Features" "NotInstalled" "Feature not found"
            } elseif ($feat.Installed -eq $true) {
                Add-Check $featDef.Label "Features" "Pass" "Installed"
            } else {
                Add-Check $featDef.Label "Features" "Fail" "Not installed (InstallState: $($feat.InstallState))"
            }
        } catch {
            Add-Check $featDef.Label "Features" "Error" $_.Exception.Message
        }
    }

    # ── Disk Space ────────────────────────────────────────────────────────────────
    foreach ($diskDef in @(
        @{ Drive = "C"; MinGB = 10; Label = "Disk: C:\ >= 10 GB free" },
        @{ Drive = "U"; MinGB = 50; Label = "Disk: U:\ >= 50 GB free" }
    )) {
        try {
            $psDrive = Get-PSDrive -Name $diskDef.Drive -ErrorAction SilentlyContinue
            if (-not $psDrive) {
                Add-Check $diskDef.Label "Disk" "NotInstalled" "Drive $($diskDef.Drive): not present on this system"
            } else {
                $freeGB = [math]::Round($psDrive.Free / 1GB, 2)
                if ($freeGB -ge $diskDef.MinGB) {
                    Add-Check $diskDef.Label "Disk" "Pass" "$freeGB GB free"
                } else {
                    Add-Check $diskDef.Label "Disk" "Fail" "$freeGB GB free (minimum: $($diskDef.MinGB) GB)"
                }
            }
        } catch {
            Add-Check $diskDef.Label "Disk" "Error" $_.Exception.Message
        }
    }

    # ── IIS Authentication (Default Web Site) ─────────────────────────────────────
    try {
        $webauth = Get-WebConfigurationProperty `
            -Filter "/system.webServer/security/authentication/*" `
            -Name enabled `
            -PSPath 'IIS:\Sites\Default Web Site' -ErrorAction Stop |
            Where-Object { $_.Value -eq $true }

        $anonEntry = $webauth | Where-Object { $_.ItemXPath -match 'anonymousAuthentication' }
        if ($anonEntry) {
            Add-Check "IIS Auth: Anonymous Authentication (Default Web Site)" "IISAuth" "Pass" "Enabled"
        } else {
            Add-Check "IIS Auth: Anonymous Authentication (Default Web Site)" "IISAuth" "Fail" "Not enabled"
        }

        $winEntry = $webauth | Where-Object { $_.ItemXPath -match 'windowsAuthentication' }
        if ($winEntry) {
            Add-Check "IIS Auth: Windows Authentication (Default Web Site)" "IISAuth" "Pass" "Enabled"
        } else {
            Add-Check "IIS Auth: Windows Authentication (Default Web Site)" "IISAuth" "Fail" "Not enabled"
        }
    } catch {
        Add-Check "IIS Auth: Anonymous Authentication (Default Web Site)" "IISAuth" "Error" $_.Exception.Message
        Add-Check "IIS Auth: Windows Authentication (Default Web Site)"   "IISAuth" "Error" $_.Exception.Message
    }

    # ── Certificates ──────────────────────────────────────────────────────────────
    $today    = Get-Date
    $warnDays = 30
    $allCerts = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue

    foreach ($certDef in @(
        @{ Pattern = "*ConfigMgr*Distribution Point*"; Label = "Cert: ConfigMgr Client Distribution Point Certificate" },
        @{ Pattern = "*ConfigMgr*Web Server*";         Label = "Cert: ConfigMgr Web Server Certificate" }
    )) {
        try {
            # Primary: match by template name (prefix-agnostic wildcard)
            $matched = $allCerts | Where-Object { (Get-CertTemplateName $_) -like $certDef.Pattern }
            if (-not $matched) {
                Add-Check $certDef.Label "Certificates" "Fail" "No certificate found matching template pattern: $($certDef.Pattern)"
                continue
            }
            # Use the non-expired cert with the latest expiry
            $cert     = $matched | Sort-Object NotAfter -Descending | Select-Object -First 1
            $daysLeft = ($cert.NotAfter - $today).Days
            $tplName  = Get-CertTemplateName $cert

            if ($cert.NotAfter -le $today) {
                Add-Check $certDef.Label "Certificates" "Fail" "EXPIRED on $($cert.NotAfter.ToString('yyyy-MM-dd')) [template: $tplName]"
            } elseif ($daysLeft -le $warnDays) {
                Add-Check $certDef.Label "Certificates" "Warning" "Expires in $daysLeft days ($($cert.NotAfter.ToString('yyyy-MM-dd'))) [template: $tplName]"
            } else {
                Add-Check $certDef.Label "Certificates" "Pass" "Valid — expires $($cert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days) [template: $tplName]"
            }
        } catch {
            Add-Check $certDef.Label "Certificates" "Error" $_.Exception.Message
        }
    }

    # ── IIS SSL Binding vs Certificate Thumbprint ─────────────────────────────────
    try {
        $webServerCert = $allCerts | Where-Object {
            (Get-CertTemplateName $_) -like "*ConfigMgr*Web Server*"
        } | Sort-Object NotAfter -Descending | Select-Object -First 1

        # Retrieve thumbprint bound to port 443
        $binding443 = $null
        try {
            $b = Get-IISSiteBinding -Name "Default Web Site" -ErrorAction Stop |
                 Where-Object { $_.Protocol -eq 'https' -and $_.BindingInformation -match ':443:' }
            if ($b) { $binding443 = [System.BitConverter]::ToString($b.CertificateHash) -replace '-','' }
        } catch {
            try {
                $null = New-PSDrive -Name IIS -PSProvider WebAdministration -Root "\\$env:COMPUTERNAME" -ErrorAction SilentlyContinue
                $binding443 = (Get-Item 'IIS:\SslBindings\0.0.0.0!443' -ErrorAction Stop).Thumbprint
            } catch { $binding443 = $null }
        }

        if (-not $webServerCert) {
            Add-Check "IIS SSL Binding: Port 443 cert matches Web Server cert" "IISBinding" "Fail" "Web Server certificate not found in certificate store"
        } elseif (-not $binding443) {
            Add-Check "IIS SSL Binding: Port 443 cert matches Web Server cert" "IISBinding" "Fail" "No SSL certificate bound to port 443 on Default Web Site"
        } elseif ($webServerCert.Thumbprint -ieq $binding443) {
            Add-Check "IIS SSL Binding: Port 443 cert matches Web Server cert" "IISBinding" "Pass" "Thumbprints match ($($webServerCert.Thumbprint.Substring(0,8))...)"
        } else {
            Add-Check "IIS SSL Binding: Port 443 cert matches Web Server cert" "IISBinding" "Fail" "Thumbprint mismatch — Store: $($webServerCert.Thumbprint.Substring(0,8))... / Binding: $($binding443.Substring(0,8))..."
        }
    } catch {
        Add-Check "IIS SSL Binding: Port 443 cert matches Web Server cert" "IISBinding" "Error" $_.Exception.Message
    }

    # ── IIS DP Content Library Health ────────────────────────────────────────────
    # SMS_DP_SMSPKG$ is a web application (not a VD). DataLib/FileLib/PkgLib are
    # physical subdirectories of its root — not separate IIS virtual directories.
    # All three are lost or lose IIS permissions when IIS is reinstalled.
    try {
        $dpApp  = Get-WebApplication -Site "Default Web Site" -Name "SMS_DP_SMSPKG$" -ErrorAction SilentlyContinue
        $dpRoot = if ($dpApp) { $dpApp.PhysicalPath } else { $null }

        if (-not $dpApp -or -not $dpRoot) {
            Add-Check 'IIS DP: SMS_DP_SMSPKG$ web application' 'IISVirtualDirs' 'Fail' 'SMS_DP_SMSPKG$ web application not found under Default Web Site — DP content delivery broken'
            foreach ($dir in @('DataLib','FileLib','PkgLib')) {
                Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Fail' 'Parent SMS_DP_SMSPKG$ application is missing in IIS'
            }
        } else {
            Add-Check 'IIS DP: SMS_DP_SMSPKG$ web application' 'IISVirtualDirs' 'Pass' "Web application found — content library root: $dpRoot"
            foreach ($dir in @('DataLib','FileLib','PkgLib')) {
                try {
                    $phys = Join-Path $dpRoot $dir
                    if (-not (Test-Path $phys -PathType Container)) {
                        Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Fail' "Directory not found on disk: $phys"
                        continue
                    }
                    $acl = try { Get-Acl $phys -ErrorAction Stop } catch { $null }
                    if (-not $acl) {
                        Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Warning' "Directory exists but ACL could not be read: $phys"
                        continue
                    }
                    # Check for Deny ACEs on IIS accounts — these actively break content delivery
                    $denyIIS = @($acl.Access | Where-Object {
                        $_.AccessControlType -eq 'Deny' -and
                        $_.IdentityReference.Value -match 'IIS_IUSRS|IIS APPPOOL|IUSR|BUILTIN\\Users$|Everyone'
                    })
                    if ($denyIIS.Count -gt 0) {
                        $deniedAccts = ($denyIIS | ForEach-Object { $_.IdentityReference.Value }) -join ', '
                        Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Fail' "Deny ACE for IIS account(s) on $phys — $deniedAccts. Content delivery will fail."
                        continue
                    }
                    # At least one IIS-accessible identity must have Read
                    # (IIS_IUSRS, IUSR via Users membership, or Everyone)
                    $hasRead = [bool]@($acl.Access | Where-Object {
                        $_.AccessControlType -eq 'Allow' -and
                        $_.IdentityReference.Value -match 'IIS_IUSRS|Everyone|BUILTIN\\Users$|\\IUSR$|Authenticated Users' -and
                        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read)
                    })
                    if ($hasRead) {
                        Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Pass' "Exists and IIS read access confirmed: $phys"
                    } else {
                        Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Warning' "Exists but no IIS-accessible identity (IIS_IUSRS/Users/IUSR) has Read — verify NTFS permissions: $phys"
                    }
                } catch {
                    Add-Check "IIS DP: $dir content library directory" 'IISVirtualDirs' 'Error' $_.Exception.Message
                }
            }
        }
    } catch {
        Add-Check 'IIS DP: SMS_DP_SMSPKG$ web application' 'IISVirtualDirs' 'Error' $_.Exception.Message
    }

    # ── Pre-compute conditional flags used by multiple categories below ───────────
    # SQL instance name from registry (falls back to site def props)
    $sqlSrvReg = try { (Get-Item 'HKLM:\SOFTWARE\Microsoft\SMS\SQL Server' -ErrorAction Stop).GetValue('SQL Server Name') } catch { $null }
    if (-not $sqlSrvReg) { $sqlSrvReg = $script:siteDefProps["SQL Server Name"] }
    $sqlInstance     = if ($sqlSrvReg -match '\\(.+)') { $Matches[1] } else { '' }
    $sqlSvcName      = if ($sqlInstance) { "MSSQL`$$sqlInstance" }      else { 'MSSQLSERVER'    }
    $sqlAgentSvcName = if ($sqlInstance) { "SQLAgent`$$sqlInstance" }   else { 'SQLSERVERAGENT' }

    $wsusFeat      = Get-WindowsFeature -Name 'UpdateServices-Services' -ErrorAction SilentlyContinue
    $wsusInstalled = $wsusFeat -and $wsusFeat.Installed -eq $true
    $srsInstalled  = $null -ne (Get-Service -Name 'ReportServer*' -ErrorAction SilentlyContinue | Select-Object -First 1)

    $smsInstallDir = try { (Get-Item 'HKLM:\SOFTWARE\Microsoft\SMS\Setup' -ErrorAction Stop).GetValue('Installation Directory') } catch { '' }
    if (-not $smsInstallDir) { $smsInstallDir = 'C:\Program Files\Microsoft Configuration Manager' }

    # ── Additional Services ───────────────────────────────────────────────────────
    $stdSvcs = [System.Collections.Generic.List[hashtable]]::new()
    [void]$stdSvcs.Add(@{ Name = 'SMS_EXECUTIVE';  Label = 'Service: SMS Executive (smsexec)'             })
    [void]$stdSvcs.Add(@{ Name = 'W3SVC';          Label = 'Service: World Wide Web Publishing (W3SVC)'   })
    [void]$stdSvcs.Add(@{ Name = 'WAS';            Label = 'Service: Windows Process Activation (WAS)'    })
    [void]$stdSvcs.Add(@{ Name = $sqlSvcName;      Label = "Service: SQL Server ($sqlSvcName)"             })
    [void]$stdSvcs.Add(@{ Name = $sqlAgentSvcName; Label = "Service: SQL Server Agent ($sqlAgentSvcName)" })
    if ($wsusInstalled) { [void]$stdSvcs.Add(@{ Name = 'WsusService'; Label = 'Service: WSUS Service' }) }

    foreach ($svcDef in $stdSvcs) {
        try {
            $svc = Get-Service -Name $svcDef.Name -ErrorAction SilentlyContinue
            if (-not $svc)                       { Add-Check $svcDef.Label 'Services' 'Fail'  "Service '$($svcDef.Name)' not found" }
            elseif ($svc.Status -eq 'Running')   { Add-Check $svcDef.Label 'Services' 'Pass'  'Running' }
            else                                  { Add-Check $svcDef.Label 'Services' 'Fail'  "Status: $($svc.Status)" }
        } catch { Add-Check $svcDef.Label 'Services' 'Error' $_.Exception.Message }
    }

    # SMS_SITE_BACKUP: check StartMode — being stopped is normal between runs
    try {
        $bkSvc = Get-Service -Name 'SMS_SITE_BACKUP' -ErrorAction SilentlyContinue
        if (-not $bkSvc) {
            Add-Check 'Service: SMS Site Backup (SMS_SITE_BACKUP)' 'Services' 'NotInstalled' 'Service not found'
        } else {
            $bkWmi = Get-WmiObject Win32_Service -Filter "Name='SMS_SITE_BACKUP'" -ErrorAction SilentlyContinue
            $mode  = if ($bkWmi) { $bkWmi.StartMode } else { 'Unknown' }
            if ($mode -eq 'Disabled') {
                Add-Check 'Service: SMS Site Backup (SMS_SITE_BACKUP)' 'Services' 'Warning' 'StartMode is Disabled — site backup is not configured'
            } else {
                Add-Check 'Service: SMS Site Backup (SMS_SITE_BACKUP)' 'Services' 'Pass' "Configured (StartMode: $mode)"
            }
        }
    } catch { Add-Check 'Service: SMS Site Backup (SMS_SITE_BACKUP)' 'Services' 'Error' $_.Exception.Message }

    # ── Additional IIS App Pools ──────────────────────────────────────────────────
    # Management Point pool — try several name variants
    $mpPoolNames = @('SMS Management Point Pool','SMS Windows Auth Management Point Pool','SMS_MP_WebServiceAppPool','SMS MP Pool')
    $mpFound = $false
    foreach ($pn in $mpPoolNames) {
        try {
            $pState = $null
            try { $pState = (Get-IISAppPool $pn -ErrorAction Stop).State.ToString() } catch {}
            if (-not $pState) { try { $pState = (Get-WebAppPoolState $pn -ErrorAction Stop).Value } catch {} }
            if ($pState) {
                $mpFound = $true
                if ($pState -eq 'Started') { Add-Check "App Pool: $pn (MP)" 'AppPools' 'Pass' 'Started' }
                else                        { Add-Check "App Pool: $pn (MP)" 'AppPools' 'Fail' "State: $pState" }
                break
            }
        } catch {}
    }
    if (-not $mpFound) { Add-Check 'App Pool: SMS_MP_WebServiceAppPool' 'AppPools' 'NotInstalled' 'Management Point app pool not found' }

    # WsusPool (only if WSUS installed)
    if ($wsusInstalled) {
        try {
            $pState = $null
            try { $pState = (Get-IISAppPool 'WsusPool' -ErrorAction Stop).State.ToString() } catch {}
            if (-not $pState) { try { $pState = (Get-WebAppPoolState 'WsusPool' -ErrorAction Stop).Value } catch {} }
            if ($pState) {
                if ($pState -eq 'Started') { Add-Check 'App Pool: WsusPool' 'AppPools' 'Pass' 'Started' }
                else                        { Add-Check 'App Pool: WsusPool' 'AppPools' 'Fail' "State: $pState" }
            } else { Add-Check 'App Pool: WsusPool' 'AppPools' 'NotInstalled' 'WsusPool not found despite WSUS feature being installed' }
        } catch { Add-Check 'App Pool: WsusPool' 'AppPools' 'Error' $_.Exception.Message }
    }

    # ReportServer pool (only if SSRS service present)
    if ($srsInstalled) {
        $rsPoolNames = @('ReportServer','ReportServerWebApp','SSRS')
        $rsFound = $false
        foreach ($pn in $rsPoolNames) {
            try {
                $pState = $null
                try { $pState = (Get-IISAppPool $pn -ErrorAction Stop).State.ToString() } catch {}
                if (-not $pState) { try { $pState = (Get-WebAppPoolState $pn -ErrorAction Stop).Value } catch {} }
                if ($pState) {
                    $rsFound = $true
                    if ($pState -eq 'Started') { Add-Check "App Pool: $pn (SSRS)" 'AppPools' 'Pass' 'Started' }
                    else                        { Add-Check "App Pool: $pn (SSRS)" 'AppPools' 'Fail' "State: $pState" }
                    break
                }
            } catch {}
        }
        if (-not $rsFound) { Add-Check 'App Pool: ReportServer (SSRS)' 'AppPools' 'NotInstalled' 'SSRS app pool not found' }
    }

    # ── MECM Site Health ──────────────────────────────────────────────────────────
    # Site active status
    try {
        $siteObj = @(Invoke-WMI 'SMS_Site') | Where-Object { $_.SiteCode -eq $SiteCode } | Select-Object -First 1
        if ($siteObj) {
            $siteStatusStr = switch ($siteObj.Status) {
                1 { 'Active' }  2 { 'Pending' }  3 { 'Failed' }  4 { 'Unknown' }  default { "$($siteObj.Status)" }
            }
            if ($siteObj.Status -eq 1) { Add-Check 'MECM Site Status' 'SiteHealth' 'Pass' "Status: $siteStatusStr" }
            else                        { Add-Check 'MECM Site Status' 'SiteHealth' 'Fail' "Status: $siteStatusStr (expected: Active)" }
        } else { Add-Check 'MECM Site Status' 'SiteHealth' 'Warning' 'Could not retrieve site status from WMI' }
    } catch { Add-Check 'MECM Site Status' 'SiteHealth' 'Error' $_.Exception.Message }

    # Backup task: enabled + last run within 48 hours
    try {
        $bkTask = @(Invoke-WMI 'SMS_SCI_SQLTask' "TaskName='Backup SMS Site Server'") | Select-Object -First 1
        if (-not $bkTask) {
            Add-Check 'MECM Backup: Task Enabled' 'SiteHealth' 'Warning' 'Backup task not found in WMI'
        } elseif (-not ($bkTask.Enabled -eq $true -or $bkTask.Enabled -eq 1)) {
            Add-Check 'MECM Backup: Task Enabled' 'SiteHealth' 'Warning' 'Backup SMS Site Server task is disabled — backups not running'
        } else {
            $lastRunRaw = $bkTask.LastRunTime
            if ($lastRunRaw) {
                $lastRun  = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastRunRaw)
                $hoursAgo = [math]::Round(((Get-Date) - $lastRun).TotalHours, 1)
                if ($hoursAgo -le 48) { Add-Check 'MECM Backup: Task Enabled' 'SiteHealth' 'Pass'    "Enabled — last run $($lastRun.ToString('yyyy-MM-dd HH:mm')) ($hoursAgo hrs ago)" }
                else                  { Add-Check 'MECM Backup: Task Enabled' 'SiteHealth' 'Warning' "Enabled but last run was $hoursAgo hrs ago ($($lastRun.ToString('yyyy-MM-dd HH:mm')))" }
            } else {
                Add-Check 'MECM Backup: Task Enabled' 'SiteHealth' 'Pass' 'Enabled (no last-run timestamp — may not have run yet)'
            }
        }
    } catch { Add-Check 'MECM Backup: Task Enabled' 'SiteHealth' 'Error' $_.Exception.Message }

    # Component errors
    try {
        $compErrs = @(Invoke-WMI 'SMS_ComponentSummarizer' 'Status=2')
        if ($compErrs.Count -eq 0) {
            Add-Check 'MECM Component Status: Error count' 'SiteHealth' 'Pass' 'No components in error state'
        } else {
            $names = ($compErrs | Select-Object -First 5 -ExpandProperty ComponentName) -join ', '
            Add-Check 'MECM Component Status: Error count' 'SiteHealth' 'Fail' "$($compErrs.Count) component(s) in error: $names"
        }
    } catch { Add-Check 'MECM Component Status: Error count' 'SiteHealth' 'Error' $_.Exception.Message }

    # ── SMS Signing Certificate ───────────────────────────────────────────────────
    try {
        $signingCerts = @(Get-ChildItem Cert:\LocalMachine\SMS -ErrorAction SilentlyContinue)
        if ($signingCerts.Count -eq 0) {
            Add-Check 'Cert: SMS Signing Certificate' 'Certificates' 'Warning' 'No certificates in Cert:\LocalMachine\SMS (HTTP-only site or not yet created)'
        } else {
            $validSigning = $signingCerts | Where-Object { $_.NotAfter -gt $today } | Sort-Object NotAfter -Descending | Select-Object -First 1
            if (-not $validSigning) {
                Add-Check 'Cert: SMS Signing Certificate' 'Certificates' 'Fail' 'All SMS signing certificates are expired'
            } else {
                $daysLeft = ($validSigning.NotAfter - $today).Days
                if ($daysLeft -le $warnDays) { Add-Check 'Cert: SMS Signing Certificate' 'Certificates' 'Warning' "Expires in $daysLeft days ($($validSigning.NotAfter.ToString('yyyy-MM-dd')))" }
                else                          { Add-Check 'Cert: SMS Signing Certificate' 'Certificates' 'Pass'    "Valid — expires $($validSigning.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days)" }
            }
        }
    } catch { Add-Check 'Cert: SMS Signing Certificate' 'Certificates' 'Error' $_.Exception.Message }

    # Broad MECM cert expiry scan — flag anything expiring within 60 days
    try {
        $warn60   = 60
        $mecmPats = @('*ConfigMgr*','*MECM*','*SCCM*','*SMS*')
        $expiring = @($allCerts | Where-Object {
            $tpl = Get-CertTemplateName $_
            $days = ($_.NotAfter - $today).Days
            ($mecmPats | Where-Object { $tpl -like $_ }) -and $days -le $warn60 -and $days -ge 0
        })
        if ($expiring.Count -eq 0) {
            Add-Check 'Cert: MECM expiry scan (60-day window)' 'Certificates' 'Pass' "No MECM-related certificates expiring within $warn60 days"
        } else {
            $det = ($expiring | ForEach-Object { "$($_.Subject -replace 'CN=','') — $(($_.NotAfter-$today).Days)d" }) -join '; '
            Add-Check 'Cert: MECM expiry scan (60-day window)' 'Certificates' 'Warning' "$($expiring.Count) cert(s) expiring within $warn60 days: $det"
        }
    } catch { Add-Check 'Cert: MECM expiry scan (60-day window)' 'Certificates' 'Error' $_.Exception.Message }

    # ── Additional Windows Features ───────────────────────────────────────────────
    foreach ($featDef in @(
        @{ Name = 'NET-Framework-45-Core'; Label = 'Feature: .NET Framework 4.5'                          },
        @{ Name = 'RDC';                   Label = 'Feature: Remote Differential Compression (RDC)'        },
        @{ Name = 'BITS';                  Label = 'Feature: Background Intelligent Transfer Service (BITS)'}
    )) {
        try {
            $feat = Get-WindowsFeature -Name $featDef.Name -ErrorAction SilentlyContinue
            if (-not $feat)          { Add-Check $featDef.Label 'Features' 'Warning' "Feature '$($featDef.Name)' not found via ServerManager" }
            elseif ($feat.Installed) { Add-Check $featDef.Label 'Features' 'Pass'    'Installed' }
            else                     { Add-Check $featDef.Label 'Features' 'Fail'    "Not installed (InstallState: $($feat.InstallState))" }
        } catch { Add-Check $featDef.Label 'Features' 'Error' $_.Exception.Message }
    }

    # ── Inbox Health ──────────────────────────────────────────────────────────────
    foreach ($inboxDef in @(
        @{ Rel = 'inboxes\auth\ddm.box';  Label = 'Inbox: Discovery Data Manager (ddm.box)';       Warn = 1000 },
        @{ Rel = 'inboxes\policypv.box';  Label = 'Inbox: Policy Provider (policypv.box)';         Warn = 1000 },
        @{ Rel = 'inboxes\repl.stg';      Label = 'Inbox: Replication Staging (repl.stg)';         Warn = 500  }
    )) {
        try {
            $inboxPath = Join-Path $smsInstallDir $inboxDef.Rel
            if (-not (Test-Path $inboxPath)) {
                Add-Check $inboxDef.Label 'InboxHealth' 'NotInstalled' "Path not found: $inboxPath"
                continue
            }
            $fc = (Get-ChildItem $inboxPath -File -ErrorAction SilentlyContinue).Count
            if ($fc -ge $inboxDef.Warn) { Add-Check $inboxDef.Label 'InboxHealth' 'Warning' "$fc files (threshold: $($inboxDef.Warn)) — possible processing backlog" }
            else                         { Add-Check $inboxDef.Label 'InboxHealth' 'Pass'    "$fc files" }
        } catch { Add-Check $inboxDef.Label 'InboxHealth' 'Error' $_.Exception.Message }
    }

    # ── OS / Host Health ──────────────────────────────────────────────────────────
    # Pending reboot
    try {
        $rebootReasons = @()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootReasons += 'Windows Update' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')  { $rebootReasons += 'Component Based Servicing' }
        $pfro = try { (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop).PendingFileRenameOperations } catch { $null }
        if ($pfro) { $rebootReasons += 'Pending File Rename Operations' }
        if ($rebootReasons.Count -gt 0) { Add-Check 'OS: Pending Reboot' 'OSHealth' 'Warning' "Reboot pending: $($rebootReasons -join ', ')" }
        else                             { Add-Check 'OS: Pending Reboot' 'OSHealth' 'Pass'    'No reboot pending' }
    } catch { Add-Check 'OS: Pending Reboot' 'OSHealth' 'Error' $_.Exception.Message }

    # System uptime
    try {
        $osCI   = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $osCI.LastBootUpTime
        $uptimeStr = '{0}d {1}h {2}m' -f [int]$uptime.TotalDays, $uptime.Hours, $uptime.Minutes
        $bootStr   = $osCI.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
        if ($uptime.TotalHours -lt 24) { Add-Check 'OS: System Uptime' 'OSHealth' 'Warning' "Uptime $uptimeStr — recent reboot (last boot: $bootStr)" }
        else                            { Add-Check 'OS: System Uptime' 'OSHealth' 'Pass'    "Uptime: $uptimeStr (last boot: $bootStr)" }
    } catch { Add-Check 'OS: System Uptime' 'OSHealth' 'Error' $_.Exception.Message }

    # Time synchronisation
    try {
        $w32Out   = & w32tm /query /status 2>&1
        $src      = [string]($w32Out | Where-Object { $_ -match '^Source\s*:' }           | Select-Object -First 1) -replace '^Source\s*:\s*',''
        $offset   = [string]($w32Out | Where-Object { $_ -match '^Phase Offset\s*:' }     | Select-Object -First 1) -replace '^Phase Offset\s*:\s*',''
        $lastSync = [string]($w32Out | Where-Object { $_ -match '^Last Successful Sync' } | Select-Object -First 1) -replace '^Last Successful Sync Time:\s*',''
        $detail   = "Source: $src | Offset: $offset | Last sync: $lastSync"
        if ($src -match 'Local CMOS|Free-running') { Add-Check 'OS: Time Synchronisation' 'OSHealth' 'Warning' "Not syncing to external NTP — $detail" }
        else                                        { Add-Check 'OS: Time Synchronisation' 'OSHealth' 'Pass'    $detail }
    } catch { Add-Check 'OS: Time Synchronisation' 'OSHealth' 'Error' $_.Exception.Message }

    # Available memory
    try {
        $osCI   = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $freeGB = [math]::Round($osCI.FreePhysicalMemory / 1MB, 2)
        $totGB  = [math]::Round($osCI.TotalVisibleMemorySize / 1MB, 2)
        $pct    = [math]::Round($freeGB / $totGB * 100, 1)
        $detail = "$freeGB GB free of $totGB GB ($pct%)"
        if ($freeGB -lt 1)    { Add-Check 'OS: Available Memory' 'OSHealth' 'Fail'    "$detail — critically low" }
        elseif ($freeGB -lt 2){ Add-Check 'OS: Available Memory' 'OSHealth' 'Warning' "$detail — low" }
        else                   { Add-Check 'OS: Available Memory' 'OSHealth' 'Pass'    $detail }
    } catch { Add-Check 'OS: Available Memory' 'OSHealth' 'Error' $_.Exception.Message }

    # Physical disk health
    try {
        $physDisks = @(Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue)
        if ($physDisks.Count -eq 0) {
            Add-Check 'OS: Physical Disk Health' 'OSHealth' 'Warning' 'No physical disks found via WMI'
        } else {
            $badDisks = @($physDisks | Where-Object { $_.Status -ne 'OK' })
            if ($badDisks.Count -eq 0) {
                $dets = ($physDisks | ForEach-Object { "$($_.Caption) [$($_.Status)]" }) -join '; '
                Add-Check 'OS: Physical Disk Health' 'OSHealth' 'Pass' $dets
            } else {
                $dets = ($badDisks | ForEach-Object { "$($_.Caption) — Status: $($_.Status)" }) -join '; '
                Add-Check 'OS: Physical Disk Health' 'OSHealth' 'Fail' $dets
            }
        }
    } catch { Add-Check 'OS: Physical Disk Health' 'OSHealth' 'Error' $_.Exception.Message }

    # Windows Firewall profiles
    try {
        $fwProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $fwDisabled = @($fwProfiles | Where-Object { -not $_.Enabled })
        if ($fwDisabled.Count -eq 0) { Add-Check 'OS: Windows Firewall' 'OSHealth' 'Pass'    "All profiles enabled: $(($fwProfiles.Name) -join ', ')" }
        else                          { Add-Check 'OS: Windows Firewall' 'OSHealth' 'Warning' "Disabled profiles: $(($fwDisabled.Name) -join ', ')" }
    } catch { Add-Check 'OS: Windows Firewall' 'OSHealth' 'Error' $_.Exception.Message }

    # Critical events in Windows System log (storage, time, SCM sources)
    try {
        $hcEvtCutoff = (Get-Date).AddHours(-48)
        $critSources = @('Disk','volsnap','NTFS','Storport','storahci','nvme','iaStor','iaStorV','srv','W32Time','Service Control Manager','Microsoft-Windows-Kernel-Power','Microsoft-Windows-WER-SystemErrorReporting')
        $sysEvts = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Level=1,2; StartTime=$hcEvtCutoff } -ErrorAction SilentlyContinue |
                     Where-Object { $critSources -contains $_.ProviderName })
        if ($sysEvts.Count -eq 0) {
            Add-Check 'OS: Critical System Events (48hr)' 'OSHealth' 'Pass' 'No critical/error events from key sources in System log'
        } else {
            $top = ($sysEvts | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '
            Add-Check 'OS: Critical System Events (48hr)' 'OSHealth' 'Warning' "$($sysEvts.Count) error event(s) from key sources — $top"
        }
    } catch { Add-Check 'OS: Critical System Events (48hr)' 'OSHealth' 'Error' $_.Exception.Message }

    # ── Firewall: MECM / WSUS port accessibility ──────────────────────────────────
    # Batch-collects all enabled inbound rules via Get-NetFirewallPortFilter in one
    # pass rather than calling Get-NetFirewallPortFilter per-rule (which is very slow).
    try {
        $hcFwRuleHt = @{}
        foreach ($r in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) { $hcFwRuleHt[$r.Name] = $r }

        $hcPortMap = @{}   # port string -> @{ Allow = List[string]; Block = List[string] }
        foreach ($pf in @(Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
            $r = $hcFwRuleHt[$pf.InstanceID]
            if (-not $r -or $r.Enabled -ne 'True' -or $r.Direction -ne 'Inbound') { continue }
            $portStr = $pf.LocalPort
            if (-not $portStr -or $portStr -eq 'Any') { continue }
            foreach ($p in ($portStr -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) {
                if (-not $hcPortMap.ContainsKey($p)) {
                    $hcPortMap[$p] = @{
                        Allow = [System.Collections.Generic.List[string]]::new()
                        Block = [System.Collections.Generic.List[string]]::new()
                    }
                }
                if ($r.Action -eq 'Allow') { $hcPortMap[$p].Allow.Add($r.DisplayName) }
                else                        { $hcPortMap[$p].Block.Add($r.DisplayName) }
            }
        }

        $hcDomProf = try { (Get-NetFirewallProfile -Name Domain -ErrorAction Stop).DefaultInboundAction.ToString() } catch { 'Block' }

        $hcMecmPorts = [System.Collections.Generic.List[hashtable]]::new()
        [void]$hcMecmPorts.Add(@{ Port='80';    Label='HTTP — DP / MP / client policy' })
        [void]$hcMecmPorts.Add(@{ Port='443';   Label='HTTPS — DP / MP / CMG' })
        [void]$hcMecmPorts.Add(@{ Port='10123'; Label='Client Notification (MP)' })
        [void]$hcMecmPorts.Add(@{ Port='135';   Label='DCOM / RPC Endpoint Mapper' })
        [void]$hcMecmPorts.Add(@{ Port='1433';  Label='SQL Server' })
        if ($wsusInstalled) {
            [void]$hcMecmPorts.Add(@{ Port='8530'; Label='WSUS HTTP (SUP)' })
            [void]$hcMecmPorts.Add(@{ Port='8531'; Label='WSUS HTTPS (SUP)' })
        }

        foreach ($pd in $hcMecmPorts) {
            $chkName  = "Firewall: Port $($pd.Port) inbound ($($pd.Label))"
            $entry    = $hcPortMap[$pd.Port]
            $hasAllow = $entry -and $entry.Allow.Count -gt 0
            $hasBlock = $entry -and $entry.Block.Count -gt 0

            if ($hasBlock) {
                $bn = ($entry.Block | Select-Object -First 2) -join '; '
                Add-Check $chkName 'FirewallPorts' 'Fail' "Explicitly blocked by enabled inbound rule(s): $bn"
            } elseif ($hasAllow) {
                Add-Check $chkName 'FirewallPorts' 'Pass' "Allowed — rule: $($entry.Allow | Select-Object -First 1)"
            } elseif ($hcDomProf -eq 'Block') {
                Add-Check $chkName 'FirewallPorts' 'Warning' "No explicit Allow rule — Domain profile default inbound is Block (port may be unreachable from remote clients)"
            } else {
                Add-Check $chkName 'FirewallPorts' 'Pass' "No explicit rule — Domain profile default inbound is $hcDomProf"
            }
        }
    } catch { Add-Check 'Firewall: MECM port checks' 'FirewallPorts' 'Error' $_.Exception.Message }

    # ── Summary ───────────────────────────────────────────────────────────────────
    $hcSummary = @{
        Total           = $checks.Count
        Pass            = ($checks | Where-Object { $_.Status -eq 'Pass'         }).Count
        Warning         = ($checks | Where-Object { $_.Status -eq 'Warning'      }).Count
        Fail            = ($checks | Where-Object { $_.Status -eq 'Fail'         }).Count
        Error           = ($checks | Where-Object { $_.Status -eq 'Error'        }).Count
        NotInstalled    = ($checks | Where-Object { $_.Status -eq 'NotInstalled' }).Count
        EffectivePrefix = $effectivePrefix
    }

    @{
        Summary = $hcSummary
        Checks  = @($checks)
    }
}
#endregion

#region ── 44. Service Accounts ──────────────────────────────────────────────────

Write-Section "Service Accounts"
$report.ServiceAccounts = Invoke-Section "ServiceAccounts" {

    # ── 1. Windows Services — MECM-related or running under named accounts ────────
    $builtinPatterns = @(
        'LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService',
        'NT AUTHORITY\SYSTEM', 'Local System'
    )
    function Is-BuiltinAccount ([string]$acct) {
        if (-not $acct) { return $true }
        foreach ($p in $builtinPatterns) { if ($acct -ieq $p) { return $true } }
        if ($acct -match '^NT (AUTHORITY|SERVICE)\\') { return $true }
        return $false
    }

    $mecmSvcPatterns = @('SMS_','CCMEXEC','CcmExec','MSSQL','SQLAgent','SQLBrowser',
                          'ReportServer','WsusService','W3SVC','WAS','IISADMIN','WDSServer')

    $allSvcs = @(Get-WmiObject Win32_Service -ComputerName $SMSProvider -ErrorAction SilentlyContinue)

    $windowsServices = @($allSvcs | Where-Object {
        $name = $_.Name
        $isMecm = $mecmSvcPatterns | Where-Object { $name -like "*$_*" }
        $isNamed = -not (Is-BuiltinAccount $_.StartName)
        $isMecm -or $isNamed
    } | Sort-Object Name | ForEach-Object {
        [ordered]@{
            ServiceName  = $_.Name
            DisplayName  = $_.DisplayName
            StartName    = if ($_.StartName) { $_.StartName } else { "(none)" }
            State        = $_.State
            StartMode    = $_.StartMode
            IsNamedAcct  = -not (Is-BuiltinAccount $_.StartName)
            IsgMSA       = ($_.StartName -match '\$$')
        }
    })

    # ── 2. MECM Component Account Settings (WMI PropLists + Props) ───────────────
    # Reads account names from site control components — passwords are never stored
    # in plain text; only the account name fields (Value2 / Values) are captured.
    $componentAccounts = @()
    try {
        $components = @(Get-WmiObject -Namespace $script:WmiNS -Class SMS_SCI_Component `
                        -ComputerName $SMSProvider -ErrorAction Stop)
        # Looks like a domain account: DOMAIN\user, user@domain, or .\user
        function Looks-LikeAccount ([string]$v) {
            if (-not $v) { return $false }
            if ($v -match '^[A-Za-z0-9\-_\.]+\\[A-Za-z0-9\-_\. ]+$') { return $true }  # DOMAIN\user
            if ($v -match '^[A-Za-z0-9\-_\.]+@[A-Za-z0-9\-_\.]+$')    { return $true }  # UPN
            if ($v -match '^\.[\\\/][A-Za-z0-9\-_\. ]+$')              { return $true }  # .\user
            return $false
        }

        foreach ($comp in $components) {
            if ($comp.PropLists) {
                foreach ($pl in $comp.PropLists) {
                    if ($pl.PropertyListName -match 'Account|User|Credential|Login') {
                        $vals = @($pl.Values) | Where-Object { Looks-LikeAccount $_ }
                        if ($vals) {
                            $componentAccounts += [ordered]@{
                                Component    = $comp.ComponentName
                                PropertyType = "PropList"
                                PropertyName = $pl.PropertyListName
                                Value        = $vals -join '; '
                            }
                        }
                    }
                }
            }
            if ($comp.Props) {
                foreach ($p in $comp.Props) {
                    if ($p.PropertyName -match 'Account|User Name|Username|Credential|Login' -and
                        (Looks-LikeAccount $p.Value2)) {
                        $componentAccounts += [ordered]@{
                            Component    = $comp.ComponentName
                            PropertyType = "Prop"
                            PropertyName = $p.PropertyName
                            Value        = $p.Value2
                        }
                    }
                }
            }
        }
    } catch {
        $componentAccounts += @([ordered]@{ _Error = $_.Exception.Message })
    }

    # ── 3. IIS App Pool Identities running as named accounts ─────────────────────
    $appPoolAccounts = @()
    try {
        $null = Import-Module WebAdministration -ErrorAction Stop
        $appPoolAccounts = @(Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue |
            ForEach-Object {
                $idType = $_.ProcessModel.IdentityType.ToString()
                $user   = $_.ProcessModel.UserName
                [ordered]@{
                    AppPool      = $_.Name
                    IdentityType = $idType
                    UserName     = if ($idType -eq 'SpecificUser') { $user } else { "(built-in: $idType)" }
                    IsNamedAcct  = ($idType -eq 'SpecificUser' -and $user)
                    State        = $_.State.ToString()
                }
            })
    } catch {
        $appPoolAccounts = @([ordered]@{ _Note = "WebAdministration module unavailable or IIS not installed" })
    }

    # ── 4. Local Group Membership (SMS and related groups) ───────────────────────
    $localGroups = @()
    $groupsToQuery = @(
        'SMS Admins',
        'ConfigMgr Remote Control Users',
        'Administrators',
        'Distributed COM Users',
        'Performance Monitor Users',
        'Performance Log Users'
    )
    foreach ($grpName in $groupsToQuery) {
        try {
            $grp     = [ADSI]"WinNT://$env:COMPUTERNAME/$grpName,group"
            $members = @($grp.psbase.Invoke("Members") | ForEach-Object {
                try {
                    $m = [ADSI]$_
                    $domain = try { ($m.psbase.Parent.Name) } catch { $env:COMPUTERNAME }
                    "$domain\$($m.Name[0])"
                } catch { "?" }
            })
            $localGroups += [ordered]@{
                GroupName   = $grpName
                MemberCount = $members.Count
                Members     = if ($members) { $members -join '; ' } else { "(empty)" }
            }
        } catch {
            $localGroups += [ordered]@{
                GroupName   = $grpName
                MemberCount = 0
                Members     = "Group not found or access denied"
            }
        }
    }

    # ── 5. SQL Server Logins with access to the ConfigMgr database ───────────────
    $sqlAccounts = @()
    $dbSection = $report.DatabaseInfo
    $dbServer  = if ($dbSection -and $dbSection.SQLServerName) { $dbSection.SQLServerName } else { $null }
    $dbName    = if ($dbSection -and $dbSection.DatabaseName)  { $dbSection.DatabaseName  } else { $null }

    if ($dbServer -and $dbName) {
        try {
            $connStr = "Server=$dbServer;Database=$dbName;Integrated Security=True;Connect Timeout=10;Application Name=MECMConfigSnapshot"
            $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandTimeout = 30
            $cmd.CommandText = @"
SELECT
    ISNULL(sp.name,'(no server login)')  AS LoginName,
    ISNULL(sp.type_desc,'')              AS LoginType,
    dp.name                              AS DatabaseUser,
    dp.type_desc                         AS UserType,
    ISNULL(
        STUFF((SELECT ', ' + r.name
               FROM sys.database_role_members rm
               JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
               WHERE rm.member_principal_id = dp.principal_id
               FOR XML PATH(''), TYPE).value('.','NVARCHAR(MAX)'),1,2,''),
        '') AS DatabaseRoles
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.type NOT IN ('R','A')
  AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys','public')
ORDER BY LoginName
"@
            $rdr = $cmd.ExecuteReader()
            while ($rdr.Read()) {
                $sqlAccounts += [ordered]@{
                    LoginName     = $rdr.GetValue(0).ToString()
                    LoginType     = $rdr.GetValue(1).ToString()
                    DatabaseUser  = $rdr.GetValue(2).ToString()
                    UserType      = $rdr.GetValue(3).ToString()
                    DatabaseRoles = $rdr.GetValue(4).ToString()
                }
            }
            $rdr.Close()
            $conn.Close()
        } catch {
            $sqlAccounts = @([ordered]@{ _Note = "SQL query failed: $($_.Exception.Message)" })
        }
    } else {
        $sqlAccounts = @([ordered]@{ _Note = "SQL connection details not available (DatabaseInfo section may have failed)" })
    }

    # ── 6. Managed / Group Managed Service Accounts in use ───────────────────────
    $msaInUse = @($windowsServices | Where-Object { $_.IsgMSA } | ForEach-Object {
        [ordered]@{
            ServiceName = $_.ServiceName
            DisplayName = $_.DisplayName
            Account     = $_.StartName
            State       = $_.State
        }
    })

    # ── 7. Named accounts summary (unique list across all sources) ────────────────
    $namedAccounts = [System.Collections.Generic.List[string]]::new()
    $windowsServices | Where-Object { $_.IsNamedAcct } | ForEach-Object { [void]$namedAccounts.Add($_.StartName) }
    $appPoolAccounts | Where-Object { $_.IsNamedAcct } | ForEach-Object { [void]$namedAccounts.Add($_.UserName) }
    $componentAccounts | Where-Object { $_.Value -and $_.Value -notmatch '_Error' } | ForEach-Object { [void]$namedAccounts.Add($_.Value) }
    # Case-insensitive dedup — DOMAIN\User and DOMAIN\USER are the same account
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $uniqueAccounts = @($namedAccounts | Where-Object { $seen.Add($_) } | Sort-Object)

    @{
        Summary = [ordered]@{
            NamedServiceAccountCount   = $uniqueAccounts.Count
            UniqueNamedAccounts        = $uniqueAccounts
            NamedWindowsServiceCount   = ($windowsServices | Where-Object { $_.IsNamedAcct }).Count
            gMSACount                  = $msaInUse.Count
            ComponentAccountEntryCount = $componentAccounts.Count
            SQLAccountCount            = $sqlAccounts.Count
        }
        WindowsServices    = $windowsServices
        ComponentAccounts  = $componentAccounts
        AppPoolAccounts    = $appPoolAccounts
        LocalGroups        = $localGroups
        SQLAccounts        = $sqlAccounts
        ManagedServiceAccts = $msaInUse
    }
}
#endregion

#region ── 45. Role Server Probes ────────────────────────────────────────────────

Write-Section "Role Server Probes"
$report.RoleServerProbes = Invoke-Section "RoleServerProbes" {

    if ($SkipRemoteProbes) {
        return [ordered]@{ _Note = "Skipped — use -SkipRemoteProbes:\$false to enable" }
    }

    # Build server → [roles] map from section 2 data
    $serverRoleMap = [ordered]@{}
    if ($report.SiteSystemRoles) {
        foreach ($role in @($report.SiteSystemRoles)) {
            $srv = $role.ServerName
            if (-not $srv) { continue }
            if (-not $serverRoleMap.Contains($srv)) {
                $serverRoleMap[$srv] = [System.Collections.Generic.List[string]]::new()
            }
            if (-not $serverRoleMap[$srv].Contains($role.RoleName)) {
                [void]$serverRoleMap[$srv].Add($role.RoleName)
            }
        }
    }

    # Ensure the SQL server host is included even if not in SiteSystemRoles
    $sqlSrvFull = $script:siteDefProps["SQL Server Name"]   # may include \INSTANCE
    if ($sqlSrvFull) {
        $sqlHost = ($sqlSrvFull -split '\\')[0].Trim()
        if ($sqlHost -and -not $serverRoleMap.Contains($sqlHost)) {
            $serverRoleMap[$sqlHost] = [System.Collections.Generic.List[string]]::new()
        }
        if ($sqlHost -and -not $serverRoleMap[$sqlHost].Contains("SQL Server")) {
            [void]$serverRoleMap[$sqlHost].Add("SQL Server")
        }
    }

    $probes     = [ordered]@{}
    $total      = $serverRoleMap.Count
    $idx        = 0

    foreach ($server in $serverRoleMap.Keys) {
        $idx++
        $roles = @($serverRoleMap[$server])
        Write-Host ("    [{0}/{1}] {2}  ({3})" -f $idx, $total, $server, ($roles -join ', ')) -ForegroundColor DarkCyan
        $probes[$server] = Probe-RoleServer -Server $server -Roles $roles -TimeoutSec $RemoteTimeoutSec
    }

    # Convert GenericList to plain arrays for JSON
    $roleMapJson = [ordered]@{}
    foreach ($k in $serverRoleMap.Keys) { $roleMapJson[$k] = @($serverRoleMap[$k]) }

    [ordered]@{
        ServersProbed = $probes.Count
        RoleMap       = $roleMapJson
        Probes        = $probes
    }
}
#endregion

#region ── 46. Registry Settings ────────────────────────────────────────────────
Write-Host "46. Collecting registry settings..." -ForegroundColor Cyan
try {
    # Helper: read all values under a registry key, skipping/truncating large binaries
    function Read-RegValues {
        param([string]$Path, [int]$MaxStringLen = 500)
        $result = [ordered]@{}
        if (-not (Test-Path $Path)) { return $result }
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            foreach ($vname in $item.GetValueNames()) {
                if ([string]::IsNullOrEmpty($vname)) { continue }  # skip (Default) value — empty key breaks ConvertFrom-Json
                $kind = $item.GetValueKind($vname)
                $val  = $item.GetValue($vname)
                # Skip large binary blobs
                if ($kind -eq 'Binary') {
                    if ($val -and $val.Length -gt 64) {
                        $result[$vname] = "<Binary $($val.Length) bytes — skipped>"
                        continue
                    }
                    $result[$vname] = ($val | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
                    continue
                }
                $str = "$val"
                if ($str.Length -gt $MaxStringLen) { $str = $str.Substring(0, $MaxStringLen) + '…' }
                $result[$vname] = $str
            }
        } catch { }
        return $result
    }

    # Helper: read per-component Tracing subkeys (SMS\Tracing\<Component>)
    function Read-TracingComponents {
        param([string]$TracingPath)
        $components = [ordered]@{}
        if (-not (Test-Path $TracingPath)) { return $components }
        $fields = @('MaxFileSize','Enabled','DebugLogging','LoggingLevel','LogMaxHistory')
        Get-ChildItem -LiteralPath $TracingPath -ErrorAction SilentlyContinue | ForEach-Object {
            $comp = $_.PSChildName
            $entry = [ordered]@{}
            foreach ($f in $fields) {
                try { $entry[$f] = "$($_.GetValue($f))" } catch { $entry[$f] = $null }
            }
            $components[$comp] = $entry
        }
        return $components
    }

    # ── SMS (server-side) ──────────────────────────────────────────────────────
    $smsRoot     = 'HKLM:\SOFTWARE\Microsoft\SMS'
    $smsIdent    = Read-RegValues "$smsRoot\Identification"
    $smsSql      = Read-RegValues "$smsRoot\SQL Server"
    $smsSec      = Read-RegValues "$smsRoot\Security"
    # Strip known large / sensitive blobs
    foreach ($bk in @('SerializedKey','CryptInfo','CcmRootCertList')) {
        if ($smsSec.Contains($bk))  { $smsSec.Remove($bk) }
        if ($smsIdent.Contains($bk)){ $smsIdent.Remove($bk) }
    }
    $smsIIS      = Read-RegValues "$smsRoot\IIS"
    $smsMP       = Read-RegValues "$smsRoot\MP"
    $smsDP       = Read-RegValues "$smsRoot\DP"
    $smsWSUS     = Read-RegValues "$smsRoot\WSUS"
    $smsSetup    = Read-RegValues "$smsRoot\Setup"

    # Tracing — global settings + per-component table
    $smsTracingGlobal = Read-RegValues "$smsRoot\Tracing"
    $smsTracingComps  = Read-TracingComponents "$smsRoot\Tracing"

    # ── CCM (client-side) ─────────────────────────────────────────────────────
    $ccmRoot = 'HKLM:\SOFTWARE\Microsoft\CCM'
    $ccmBase = Read-RegValues $ccmRoot
    # Drop large binary cert list if present
    if ($ccmBase.Contains('CcmRootCertList')) { $ccmBase.Remove('CcmRootCertList') }

    $ccmEval    = Read-RegValues "$ccmRoot\CcmEval"
    $ccmExec    = Read-RegValues "$ccmRoot\CcmExec"
    $ccmLog     = Read-RegValues "$ccmRoot\Logging"
    $ccmSec     = Read-RegValues "$ccmRoot\Security"
    foreach ($bk in @('SerializedKey','CryptInfo','CcmRootCertList')) {
        if ($ccmSec.Contains($bk)) { $ccmSec.Remove($bk) }
    }
    $ccmLocSvc  = Read-RegValues "$ccmRoot\LocationServices"
    $ccmSU      = Read-RegValues "$ccmRoot\SoftwareUpdates"
    $ccmInv     = Read-RegValues "$ccmRoot\Inventory"

    # ── CCMSetup ──────────────────────────────────────────────────────────────
    $ccmSetup = Read-RegValues 'HKLM:\SOFTWARE\Microsoft\CCMSetup'

    # ── Windows Update policy ─────────────────────────────────────────────────
    $wuPolicy = Read-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $wuAU     = Read-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

    $report.RegistrySettings = [ordered]@{
        SMS = [ordered]@{
            Identification = $smsIdent
            SqlServer      = $smsSql
            Security       = $smsSec
            IIS            = $smsIIS
            MP             = $smsMP
            DP             = $smsDP
            WSUS           = $smsWSUS
            Setup          = $smsSetup
            Tracing        = [ordered]@{
                Global     = $smsTracingGlobal
                Components = $smsTracingComps
            }
        }
        CCM = [ordered]@{
            Base             = $ccmBase
            CcmEval          = $ccmEval
            CcmExec          = $ccmExec
            Logging          = $ccmLog
            Security         = $ccmSec
            LocationServices = $ccmLocSvc
            SoftwareUpdates  = $ccmSU
            Inventory        = $ccmInv
        }
        CCMSetup = $ccmSetup
        WindowsUpdate = [ordered]@{
            Policy = $wuPolicy
            AU     = $wuAU
        }
    }
    Write-Host "    Registry settings collected." -ForegroundColor Green
} catch {
    $err = Handle-SectionError "RegistrySettings" $_
    $report.RegistrySettings = $err
}
#endregion

#region ── 47. OS Event Log Analysis ────────────────────────────────────────────
Write-Host "47. Collecting OS event log analysis..." -ForegroundColor Cyan
try {
    $osLogCutoff  = (Get-Date).AddHours(-$LogHoursBack)
    $osMaxEntries = 300

    # Build a normalised entry array from Get-WinEvent results
    # Uses same field names as the MECM log viewer (DateTime/Severity/Component/Message/Flagged)
    function Read-OSEventLog {
        param(
            [string]  $LogName,
            [int[]]   $Levels    = @(1,2),
            [int[]]   $EventIds  = @(),
            [string[]]$Sources   = @()
        )
        $filter = @{ LogName = $LogName; StartTime = $osLogCutoff }
        if ($Levels)   { $filter['Level'] = $Levels }
        if ($EventIds) { $filter['Id']    = $EventIds }

        try {
            $raw = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
        } catch { $raw = @() }

        if ($Sources) { $raw = @($raw | Where-Object { $Sources -contains $_.ProviderName }) }

        return @($raw | Select-Object -First $osMaxEntries | ForEach-Object {
            $sevLabel = switch ($_.Level) { 1{'Critical'} 2{'Error'} 3{'Warning'} default{'Information'} }
            $msg      = ($_.Message -replace '\r?\n',' ').Trim()
            if ($msg.Length -gt 500) { $msg = $msg.Substring(0,500) + '…' }
            [ordered]@{
                DateTime  = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Severity  = $sevLabel
                Component = "$($_.ProviderName) (ID:$($_.Id))"
                Message   = $msg
                Flagged   = ($_.Level -le 2)
            }
        })
    }

    $storageSources = @('Disk','volsnap','NTFS','Storport','storahci','nvme','iaStor','iaStorV',
                        'srv','W32Time','Service Control Manager','Microsoft-Windows-Kernel-Power',
                        'Microsoft-Windows-WER-SystemErrorReporting','EventLog')
    $sysEntries = Read-OSEventLog -LogName 'System'      -Levels @(1,2,3) -Sources $storageSources
    $appEntries = Read-OSEventLog -LogName 'Application' -Levels @(1,2)
    $secEntries = @()
    try {
        $secRaw  = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$osLogCutoff } -ErrorAction SilentlyContinue |
                     Select-Object -First $osMaxEntries)
        $secEntries = $secRaw | ForEach-Object {
            $msg = ($_.Message -replace '\r?\n',' ').Trim()
            if ($msg.Length -gt 500) { $msg = $msg.Substring(0,500) + '…' }
            [ordered]@{
                DateTime  = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Severity  = 'AuditFailure'
                Component = "$($_.ProviderName) (ID:$($_.Id))"
                Message   = $msg
                Flagged   = $true
            }
        }
    } catch {}

    $report.OSEventLogs = [ordered]@{
        Summary = [ordered]@{
            HoursBack            = $LogHoursBack
            CutoffTime           = $osLogCutoff.ToString('yyyy-MM-dd HH:mm:ss')
            SystemErrorCount     = ($sysEntries  | Where-Object { $_.Flagged }).Count
            ApplicationErrorCount= ($appEntries  | Where-Object { $_.Flagged }).Count
            FailedLogonCount     = $secEntries.Count
        }
        SystemLog = [ordered]@{
            Label      = 'Windows System Log'
            EntryCount = $sysEntries.Count
            Entries    = $sysEntries
        }
        ApplicationLog = [ordered]@{
            Label      = 'Windows Application Log'
            EntryCount = $appEntries.Count
            Entries    = $appEntries
        }
        SecurityLog = [ordered]@{
            Label      = 'Windows Security Log (Failed Logons 4625)'
            EntryCount = $secEntries.Count
            Entries    = $secEntries
        }
    }
    Write-Host ("    System: {0} entries ({1} errors) | Application: {2} entries ({3} errors) | Security 4625: {4}" -f `
        $sysEntries.Count, $report.OSEventLogs.Summary.SystemErrorCount,
        $appEntries.Count, $report.OSEventLogs.Summary.ApplicationErrorCount,
        $secEntries.Count) -ForegroundColor Green
} catch {
    $err = Handle-SectionError "OSEventLogs" $_
    $report.OSEventLogs = $err
}
#endregion

#region ── 48. Firewall Configuration ────────────────────────────────────────────
Write-Host "48. Collecting firewall configuration..." -ForegroundColor Cyan
try {
    # ── Profiles ─────────────────────────────────────────────────────────────────
    $fwProfileData = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            Name                  = $_.Name
            Enabled               = $_.Enabled
            DefaultInboundAction  = $_.DefaultInboundAction.ToString()
            DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
            LogAllowed            = [bool]$_.LogAllowed
            LogBlocked            = [bool]$_.LogBlocked
            LogMaxSizeKilobytes   = $_.LogMaxSizeKilobytes
            LogFileName           = $_.LogFileName
        }
    })

    # ── Key MECM / WSUS port definitions ─────────────────────────────────────────
    $keyPortDefs = @(
        [ordered]@{ Port='80';    Protocol='TCP'; Role='HTTP — DP, MP, client policy download'      },
        [ordered]@{ Port='443';   Protocol='TCP'; Role='HTTPS — DP, MP, CMG, WSUS HTTPS'            },
        [ordered]@{ Port='8530';  Protocol='TCP'; Role='WSUS HTTP (SUP)'                            },
        [ordered]@{ Port='8531';  Protocol='TCP'; Role='WSUS HTTPS (SUP)'                           },
        [ordered]@{ Port='10123'; Protocol='TCP'; Role='Client Notification (MP → client)'          },
        [ordered]@{ Port='2701';  Protocol='TCP'; Role='Remote Control'                             },
        [ordered]@{ Port='135';   Protocol='TCP'; Role='DCOM / RPC Endpoint Mapper (WMI)'           },
        [ordered]@{ Port='445';   Protocol='TCP'; Role='SMB (PXE, state migration, file copy)'      },
        [ordered]@{ Port='1433';  Protocol='TCP'; Role='SQL Server'                                 },
        [ordered]@{ Port='4022';  Protocol='TCP'; Role='SQL Server Service Broker'                  },
        [ordered]@{ Port='1434';  Protocol='UDP'; Role='SQL Browser (named instances)'              },
        [ordered]@{ Port='9';     Protocol='UDP'; Role='Wake on LAN'                               }
    )
    $keyPortNums = @($keyPortDefs | ForEach-Object { $_.Port })

    # ── Batch-collect all rules + port filters in two passes ──────────────────────
    # Building a name→rule hashtable avoids the very slow per-rule Get-NetFirewallPortFilter call.
    $mecmNamePat = 'MECM|ConfigMgr|SCCM|SMS|WSUS|Windows Update Services|Management Point|Distribution Point|Software Update|WMI|SQL Server'

    $fwAllRulesHt = @{}
    foreach ($r in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) { $fwAllRulesHt[$r.Name] = $r }

    $fwPortMap    = @{}   # port -> @{ Allow = List[string]; Block = List[string] }
    $fwRuleList   = [System.Collections.Generic.List[object]]::new()

    foreach ($pf in @(Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        $rule = $fwAllRulesHt[$pf.InstanceID]
        if (-not $rule) { continue }

        $isEnabled   = $rule.Enabled -eq 'True'
        $portStr     = $pf.LocalPort
        $isKeyPort   = $portStr -and ($keyPortNums | Where-Object { $portStr -match "^$_$" })
        $isNameMatch = $rule.DisplayName -match $mecmNamePat

        if ($isKeyPort -or $isNameMatch) {
            $fwRuleList.Add([ordered]@{
                Name      = $rule.DisplayName
                Direction = $rule.Direction.ToString()
                Action    = $rule.Action.ToString()
                Enabled   = $isEnabled
                Profile   = $rule.Profile.ToString()
                Protocol  = $pf.Protocol
                LocalPort = $portStr
                MECMNamed = [bool]$isNameMatch
            })
        }

        # Build the port map for enabled inbound rules with discrete port numbers
        if ($isEnabled -and $rule.Direction -eq 'Inbound' -and $portStr -and $portStr -ne 'Any') {
            foreach ($p in ($portStr -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) {
                if ($keyPortNums -notcontains $p) { continue }
                if (-not $fwPortMap.ContainsKey($p)) {
                    $fwPortMap[$p] = @{
                        Allow = [System.Collections.Generic.List[string]]::new()
                        Block = [System.Collections.Generic.List[string]]::new()
                    }
                }
                if ($rule.Action -eq 'Allow') { $fwPortMap[$p].Allow.Add($rule.DisplayName) }
                else                           { $fwPortMap[$p].Block.Add($rule.DisplayName) }
            }
        }
    }

    # ── Per-port effective status ─────────────────────────────────────────────────
    $domProfObj    = $fwProfileData | Where-Object { $_.Name -eq 'Domain' } | Select-Object -First 1
    $domProfAction = if ($domProfObj) { $domProfObj.DefaultInboundAction } else { 'Block' }

    $fwPortStatus = @(foreach ($pd in $keyPortDefs) {
        $entry    = $fwPortMap[$pd.Port]
        $hasAllow = $entry -and $entry.Allow.Count -gt 0
        $hasBlock = $entry -and $entry.Block.Count -gt 0
        $status   = if     ($hasBlock)  { 'Blocked'                       }
                    elseif ($hasAllow)  { 'Allowed'                       }
                    elseif ($domProfAction -eq 'Block') { 'No-Rule (default: Block)'  }
                    else                                { 'No-Rule (default: Allow)'  }
        [ordered]@{
            Port       = $pd.Port
            Protocol   = $pd.Protocol
            Role       = $pd.Role
            Status     = $status
            AllowRules = if ($entry -and $entry.Allow.Count -gt 0) { $entry.Allow -join '; ' } else { '' }
            BlockRules = if ($entry -and $entry.Block.Count -gt 0) { $entry.Block -join '; ' } else { '' }
        }
    })

    # ── Identify issues ───────────────────────────────────────────────────────────
    # Ports that are critical for MECM / WSUS operation
    $mecmCritPorts = @('80','443','8530','8531','10123','135','1433','445','4022')
    $fwIssues = [System.Collections.Generic.List[object]]::new()

    foreach ($prof in $fwProfileData) {
        if (-not $prof.Enabled) {
            $fwIssues.Add([ordered]@{
                Severity    = 'Warning'
                Area        = 'Profile'
                Description = "Firewall profile '$($prof.Name)' is DISABLED — all inbound traffic unrestricted on this network type"
            })
        }
    }

    foreach ($ps in $fwPortStatus) {
        if ($ps.Status -eq 'Blocked') {
            $sev = if ($mecmCritPorts -contains $ps.Port) { 'Critical' } else { 'Warning' }
            $fwIssues.Add([ordered]@{
                Severity    = $sev
                Area        = 'Port'
                Description = "Port $($ps.Port)/$($ps.Protocol) ($($ps.Role)) is BLOCKED by an enabled inbound rule — $($ps.BlockRules)"
            })
        } elseif ($ps.Status -eq 'No-Rule (default: Block)' -and $mecmCritPorts -contains $ps.Port) {
            $fwIssues.Add([ordered]@{
                Severity    = 'Warning'
                Area        = 'Port'
                Description = "Port $($ps.Port)/$($ps.Protocol) ($($ps.Role)) has no explicit Allow rule and Domain profile blocks inbound by default — remote clients may be unable to connect"
            })
        }
    }

    $report.FirewallConfig = [ordered]@{
        Summary = [ordered]@{
            ProfilesEnabled      = ($fwProfileData | Where-Object { $_.Enabled  }).Count
            ProfilesDisabled     = ($fwProfileData | Where-Object { -not $_.Enabled }).Count
            ProfilesTotal        = $fwProfileData.Count
            MECMRelatedRuleCount = ($fwRuleList | Where-Object { $_.MECMNamed }).Count
            AllRelatedRuleCount  = $fwRuleList.Count
            KeyPortBlockedCount  = ($fwPortStatus | Where-Object { $_.Status -eq 'Blocked' }).Count
            KeyPortNoRuleCount   = ($fwPortStatus | Where-Object { $_.Status -like 'No-Rule*' }).Count
            IssueCount           = $fwIssues.Count
        }
        Profiles   = $fwProfileData
        PortStatus = @($fwPortStatus)
        Rules      = @($fwRuleList)
        Issues     = @($fwIssues)
    }

    Write-Host ("    Profiles: {0}/{1} enabled | Related rules: {2} | Port blocked: {3} | Issues: {4}" -f
        $report.FirewallConfig.Summary.ProfilesEnabled,
        $report.FirewallConfig.Summary.ProfilesTotal,
        $report.FirewallConfig.Summary.AllRelatedRuleCount,
        $report.FirewallConfig.Summary.KeyPortBlockedCount,
        $report.FirewallConfig.Summary.IssueCount) -ForegroundColor Green
} catch {
    $err = Handle-SectionError "FirewallConfig" $_
    $report.FirewallConfig = $err
}
#endregion

#region ── Output ─────────────────────────────────────────────────────────────────

$report.ScriptErrors = $script:SectionErrors

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile   = Join-Path $OutputPath "MECM_Config_${SiteCode}_${timestamp}.json"

$report | ConvertTo-Json -Depth 20 | Out-File -FilePath $outFile -Encoding utf8

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Report written to:" -ForegroundColor Green
Write-Host "  $outFile" -ForegroundColor White
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow

$si = $report.SiteInfo

# cntArr handles the PS5.1 pipeline quirks:
#   - empty array  returned from a function → arrives as $null  → treat as count 0
#   - 1-item array returned from a function → unwrapped to item → check if it's an error dict
#   - multi-item array                      → arrives intact    → use .Count
function cntArr ($v) {
    if ($null -eq $v)                                                        { return "0" }
    if ($v -is [System.Collections.IDictionary] -and $v.Contains("_Error")) { return "N/A" }
    if ($v -is [System.Collections.IDictionary])                             { return "1" }   # 1-item array unwrapped
    return "$(@($v).Count)"
}
# cntVal: safe display for scalar values (e.g. counts stored as named keys in a section hashtable).
function cntVal ($v) {
    if ($null -eq $v)                                                        { return "N/A" }
    if ($v -is [System.Collections.IDictionary] -and $v.Contains("_Error")) { return "N/A" }
    if ($v -is [System.Collections.IDictionary])                             { return "N/A" }
    return "$v"
}

Write-Host ("  Site           : {0} - {1}" -f (sprop $si SiteCode), (sprop $si SiteName))
Write-Host ("  Version        : {0} (build {1})" -f (sprop $si Version), (sprop $si BuildNumber))
Write-Host ("  {0,-18}: {1}" -f "Sites in hier.",  (cntArr (sprop $si AllSitesInHierarchy)))
Write-Host ("  {0,-18}: {1}" -f "Site roles",      (cntArr $report.SiteSystemRoles))
Write-Host ("  {0,-18}: {1}" -f "Boundaries",      (cntArr $report.Boundaries))
Write-Host ("  {0,-18}: {1}" -f "Boundary groups", (cntArr $report.BoundaryGroups))
Write-Host ("  {0,-18}: {1}" -f "DPs",             (cntArr $report.DistributionPoints))
Write-Host ("  {0,-18}: {1}" -f "DP groups",       (cntArr $report.DPGroups))
Write-Host ("  {0,-18}: {1}" -f "Device colls",    (cntVal $report.Collections.DeviceCollectionCount))
Write-Host ("  {0,-18}: {1}" -f "User colls",      (cntVal $report.Collections.UserCollectionCount))
Write-Host ("  {0,-18}: {1}" -f "Applications",    (cntVal $report.Applications.Count))
Write-Host ("  {0,-18}: {1}" -f "Packages",        (cntVal $report.Packages.PackageCount))
Write-Host ("  {0,-18}: {1}" -f "Task Sequences",  (cntVal $report.Packages.TaskSequenceCount))
Write-Host ("  {0,-18}: {1}" -f "Boot Images",     (cntArr $report.OSD.BootImages))
Write-Host ("  {0,-18}: {1}" -f "EP Policies",     (cntVal $report.EndpointProtection.PolicyCount))
Write-Host ("  {0,-18}: {1}" -f "Maint. Windows",  (cntArr $report.MaintenanceWindows))
Write-Host ("  {0,-18}: {1}" -f "Components",      (cntArr $report.ComponentStatus))
Write-Host ("  {0,-18}: {1}" -f "Maint. Tasks",    (cntArr $report.SiteMaintenanceTasks))
Write-Host ("  {0,-18}: {1}" -f "SU Groups",        (cntVal $report.SoftwareUpdateGroups.Count))
Write-Host ("  {0,-18}: {1}" -f "Certificates",     (cntArr $report.Certificates))
Write-Host ("  {0,-18}: {1}" -f "IIS App Pools",    (cntArr $report.IISConfiguration.ApplicationPools))
Write-Host ("  {0,-18}: {1}" -f "WSUS Port",        (cntVal $report.WSUSConfiguration.PortNumber))
Write-Host ("  {0,-18}: {1}" -f "Content Store DPs",(cntArr $report.ContentStore.DistributionPoints))
Write-Host ("  {0,-18}: {1}" -f "Inacc. Src Paths", (cntVal $report.ContentStore.InaccessibleSourceCount))
$hcSum = $report.HealthChecks
if ($hcSum -is [System.Collections.IDictionary] -and $hcSum.Contains("Summary")) {
    $s = $hcSum.Summary
    Write-Host ("  {0,-18}: {1}" -f "HC Total",  (cntVal $s.Total))
} else {
    Write-Host ("  {0,-18}: {1}" -f "HC Total",  "N/A")
}
$saSum = $report.ServiceAccounts
if ($saSum -is [System.Collections.IDictionary] -and $saSum.Contains("Summary")) {
    Write-Host ("  {0,-18}: {1}" -f "Named Svc Accts", (cntVal $saSum.Summary.NamedServiceAccountCount))
    Write-Host ("  {0,-18}: {1}" -f "gMSA in use",     (cntVal $saSum.Summary.gMSACount))
} else {
    Write-Host ("  {0,-18}: {1}" -f "Named Svc Accts", "N/A")
}
$rspSum = $report.RoleServerProbes
if ($rspSum -is [System.Collections.IDictionary] -and $rspSum.Contains("ServersProbed")) {
    Write-Host ("  {0,-18}: {1}" -f "Servers probed", (cntVal $rspSum.ServersProbed))
} elseif ($rspSum -is [System.Collections.IDictionary] -and $rspSum.Contains("_Note")) {
    Write-Host ("  {0,-18}: {1}" -f "Servers probed", "Skipped")
} else {
    Write-Host ("  {0,-18}: {1}" -f "Servers probed", "N/A")
}

# Log analysis summary
$logSum = $report.Logs
if ($logSum -is [System.Collections.IDictionary] -and -not $logSum.Contains("_Error")) {
    $ls = $logSum.Summary
    Write-Host ""
    Write-Host "  Log Analysis ($LogHoursBack hr window):" -ForegroundColor Yellow
    Write-Host ("  {0,-18}: {1}" -f "Logs scanned",  (cntVal $ls.LogsScanned))
    Write-Host ("  {0,-18}: {1}" -f "Logs not found", (cntVal $ls.LogsNotFound))
    $errCol = if ($ls.TotalErrors -gt 0) { "Red" } else { "Green" }
    $wrnCol = if ($ls.TotalWarnings -gt 0) { "Yellow" } else { "Green" }
    Write-Host ("  {0,-18}: {1}" -f "Error entries",  (cntVal $ls.TotalErrors))  -ForegroundColor $errCol
    Write-Host ("  {0,-18}: {1}" -f "Warning entries",(cntVal $ls.TotalWarnings)) -ForegroundColor $wrnCol
    Write-Host ("  {0,-18}: {1}" -f "Flagged total",  (cntVal $ls.FlaggedEntries))
    if ($ls.LogsWithIssues -and $ls.LogsWithIssues.Count -gt 0) {
        Write-Host "  Logs with issues  :" -ForegroundColor Yellow
        foreach ($lf in $ls.LogsWithIssues) { Write-Host "    - $lf" -ForegroundColor Red }
    }
}

# Health Checks summary
$hcData = $report.HealthChecks
if ($hcData -is [System.Collections.IDictionary] -and $hcData.Contains("Summary")) {
    $hs = $hcData.Summary
    Write-Host ""
    Write-Host "  Health Checks (prefix: $($hs.EffectivePrefix)):" -ForegroundColor Yellow
    $passCol = if ($hs.Pass   -gt 0) { "Green"  } else { "White" }
    $warnCol = if ($hs.Warning -gt 0) { "Yellow" } else { "White" }
    $failCol = if ($hs.Fail   -gt 0) { "Red"    } else { "White" }
    $errCol  = if ($hs.Error  -gt 0) { "Red"    } else { "White" }
    Write-Host ("  {0,-18}: {1}" -f "Pass",         $hs.Pass)         -ForegroundColor $passCol
    Write-Host ("  {0,-18}: {1}" -f "Warning",       $hs.Warning)      -ForegroundColor $warnCol
    Write-Host ("  {0,-18}: {1}" -f "Fail",          $hs.Fail)         -ForegroundColor $failCol
    Write-Host ("  {0,-18}: {1}" -f "Error",         $hs.Error)        -ForegroundColor $errCol
    Write-Host ("  {0,-18}: {1}" -f "Not Installed", $hs.NotInstalled) -ForegroundColor White
    # List non-passing checks
    $nonPass = @($hcData.Checks) | Where-Object { $_.Status -notin @('Pass') }
    if ($nonPass) {
        Write-Host "  Checks needing attention:" -ForegroundColor Yellow
        foreach ($chk in $nonPass) {
            $col = switch ($chk.Status) {
                'Warning'      { 'Yellow' }
                'Fail'         { 'Red' }
                'Error'        { 'Red' }
                'NotInstalled' { 'Gray' }
                default        { 'White' }
            }
            Write-Host ("    [{0,-12}] {1}" -f $chk.Status, $chk.Name) -ForegroundColor $col
            if ($chk.Detail) { Write-Host "               $($chk.Detail)" -ForegroundColor DarkGray }
        }
    }
}

# Role Server Probes summary
$rspData = $report.RoleServerProbes
if ($rspData -is [System.Collections.IDictionary] -and $rspData.Contains("Probes")) {
    Write-Host ""
    Write-Host "  Role Server Probes:" -ForegroundColor Yellow
    foreach ($srv in $rspData.Probes.Keys) {
        $probe = $rspData.Probes[$srv]
        $roles = if ($rspData.RoleMap -and $rspData.RoleMap[$srv]) { $rspData.RoleMap[$srv] -join ', ' } else { "?" }
        $osStr = if ($probe.OS -and $probe.OS.Caption) { "OS: $($probe.OS.Caption.Replace('Windows Server ','WS '))" } else { "OS: N/A" }
        $svcOk  = if ($probe.Services) { ($probe.Services | Where-Object { $_.State -eq 'Running' }).Count } else { 0 }
        $svcAll = if ($probe.Services) { $probe.Services.Count } else { 0 }
        Write-Host ("  {0,-20}: {1}" -f $srv, $roles) -ForegroundColor Cyan
        Write-Host ("    {0}  |  Services running: {1}/{2}" -f $osStr, $svcOk, $svcAll) -ForegroundColor White
        if ($probe.Disks) {
            foreach ($d in @($probe.Disks)) {
                if ($d.Drive) {
                    $col = if ($d.FreeGB -lt 10) { "Red" } elseif ($d.FreeGB -lt 30) { "Yellow" } else { "Green" }
                    Write-Host ("    Drive {0}: {1} GB free of {2} GB ({3}%)" -f $d.Drive,$d.FreeGB,$d.SizeGB,$d.FreePct) -ForegroundColor $col
                }
            }
        }
    }
}

# Service Accounts summary
$saData = $report.ServiceAccounts
if ($saData -is [System.Collections.IDictionary] -and $saData.Contains("Summary")) {
    $ss = $saData.Summary
    Write-Host ""
    Write-Host "  Service Accounts:" -ForegroundColor Yellow
    Write-Host ("  {0,-25}: {1}" -f "Unique named accounts", $ss.NamedServiceAccountCount)
    Write-Host ("  {0,-25}: {1}" -f "gMSA/sMSA in use",     $ss.gMSACount)
    Write-Host ("  {0,-25}: {1}" -f "Component account entries", $ss.ComponentAccountEntryCount)
    Write-Host ("  {0,-25}: {1}" -f "SQL account entries",   $ss.SQLAccountCount)
    if ($ss.UniqueNamedAccounts -and $ss.UniqueNamedAccounts.Count -gt 0) {
        Write-Host "  Named accounts found:" -ForegroundColor Cyan
        foreach ($a in $ss.UniqueNamedAccounts) { Write-Host "    $a" -ForegroundColor White }
    }
}

if ($script:SectionErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "  Sections with errors ($($script:SectionErrors.Count)):" -ForegroundColor Yellow
    foreach ($e in $script:SectionErrors.GetEnumerator()) {
        Write-Host ("    [!] {0}: {1}" -f $e.Key, $e.Value) -ForegroundColor Red
    }
} else {
    Write-Host ""
    Write-Host "  All sections collected successfully." -ForegroundColor Green
}
Write-Host ""

#endregion
