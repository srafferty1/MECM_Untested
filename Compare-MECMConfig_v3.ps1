#Requires -Version 5.1
<#
.SYNOPSIS
    Compare two MECM configuration JSON snapshots and produce an HTML diff report.
    When only -LeftFile is supplied the report shows a single-site configuration view.

.DESCRIPTION
    Reads one or two JSON files produced by Get-MECMConfig.ps1 and generates a
    self-contained HTML report with side-by-side comparison of all 49 sections.

    ── MODES ────────────────────────────────────────────────────────────────────
    Compare   Supply both -LeftFile and -RightFile. Differences are highlighted
              and counted in each section. The anchor bar shows diff badges.
    Viewer    Supply only -LeftFile (or press Enter when prompted for the right
              file). All data is shown; no diff columns are rendered.

    ── NAVIGATION ───────────────────────────────────────────────────────────────
    A sticky anchor bar sits below the top header and lists all 49 sections.
    Sections with differences show a red badge with the count.
    Clicking an anchor item expands that section (all sections start collapsed)
    and scrolls it into view below the sticky bars.

    ── PROGRESS ─────────────────────────────────────────────────────────────────
    Each section prints a timestamped line to the console as it is processed:
      [HH:mm:ss] Comparing: <section name>

    ── SECTIONS ─────────────────────────────────────────────────────────────────
     1  Summary                   26  Client Communications
     2  Insights                  27  Hardware Inventory
     3  Site Information          28  Configuration Baselines
     4  Site System Roles         29  Alerts
     5  Boundaries                30  Run Scripts
     6  Boundary Groups           31  Software Servicing Plans
     7  Client Settings           32  3rd Party Update Catalogs
     8  Discovery Methods         33  Co-Management
     9  Software Updates          34  Content Distribution
    10  Distribution Points       35  Host System
    11  DP Groups                 36  Maintenance Tasks
    12  Collections               37  SW Update Groups
    13  Applications              38  Status Filter Rules
    14  Packages / Task Sequences  39  Certificates
    15  OSD                       40  IIS Configuration
    16  Endpoint Protection        41  WSUS Configuration
    17  Maintenance Windows        42  Content Store
    18  Software Metering          43  Group Policy Settings
    19  Cloud Services             44  Health Checks
    20  Hierarchy Settings         45  Service Accounts
    21  Component Status           46  Role Server Probes
    22  Database                   47  Registry Settings
    23  Log Analysis               48  OS Event Logs
    24  RBAC                       49  Firewall Configuration
    25  Auto Deployment Rules      50  Script Execution Log

.PARAMETER LeftFile
    Path to the reference/baseline JSON snapshot (produced by Get-MECMConfig.ps1).

.PARAMETER RightFile
    Path to the comparison JSON snapshot. If omitted, the report shows the single
    site in LeftFile with all configuration data visible and no diff columns.

.PARAMETER OutputPath
    Folder for the HTML output. Default: same folder as LeftFile.

.EXAMPLE
    .\Compare-MECMConfig.ps1 -LeftFile .\MECM_Config_RAF_20260428.json -RightFile .\MECM_Config_P02_20260428.json

.EXAMPLE
    .\Compare-MECMConfig.ps1 -LeftFile .\MECM_Config_RAF_20260428.json
#>
[CmdletBinding()]
param(
    [string]$LeftFile    = "",
    [string]$RightFile   = "",
    [string]$OutputPath  = ""
)

$ErrorActionPreference = "Continue"

# ── Banner ────────────────────────────────────────────────────────────────────
$bannerWidth = 62
$border      = '+' + ('-' * ($bannerWidth - 2)) + '+'
function _BannerLine([string]$text, [string]$fg = 'Cyan') {
    $pad  = $bannerWidth - 4 - $text.Length
    $lpad = [int][Math]::Floor($pad / 2)
    $rpad = $pad - $lpad
    Write-Host ('| ' + (' ' * $lpad) + $text + (' ' * $rpad) + ' |') -ForegroundColor $fg
}
Write-Host ''
Write-Host $border                                        -ForegroundColor DarkCyan
_BannerLine 'MECM Configuration Compare'                  'White'
_BannerLine 'Compare-MECMConfig.ps1'                      'DarkGray'
Write-Host $border                                        -ForegroundColor DarkCyan
Write-Host ''
Write-Host '  Modes'                                      -ForegroundColor Yellow
Write-Host '    Compare   Provide both a left and right JSON file'
Write-Host '    Viewer    Provide only a left JSON file (Enter to skip right)'
Write-Host ''
Write-Host '  Parameters (optional - you will be prompted if omitted)'         -ForegroundColor Yellow
Write-Host '    -LeftFile    Path to the reference/baseline JSON snapshot'
Write-Host '    -RightFile   Path to the comparison JSON snapshot'
Write-Host '    -OutputPath  Folder for the HTML output (default: left file folder)'
Write-Host ''
Write-Host '  Example'                                    -ForegroundColor Yellow
Write-Host '    .\Compare-MECMConfig.ps1 -LeftFile .\SITE_A.json -RightFile .\SITE_B.json'
Write-Host ''
Write-Host $border                                        -ForegroundColor DarkCyan
Write-Host ''

# ── Interactive file prompts ───────────────────────────────────────────────────
while (-not $LeftFile -or -not (Test-Path $LeftFile -PathType Leaf)) {
    if ($LeftFile) { Write-Warning "File not found: $LeftFile" }
    $LeftFile = (Read-Host "Left file path").Trim()
    if (-not $LeftFile) { Write-Error "Left file is required."; exit 1 }
}
if (-not $RightFile) {
    $r = (Read-Host "Right file path (Enter to skip)").Trim()
    if ($r) { $RightFile = $r }
}
while ($RightFile -and -not (Test-Path $RightFile -PathType Leaf)) {
    Write-Warning "File not found: $RightFile"
    $r = (Read-Host "Right file path (Enter to skip)").Trim()
    $RightFile = $r
}

# ── Single-file mode ──────────────────────────────────────────────────────────
$singleMode        = (-not $RightFile)
$script:SingleMode = $singleMode

# ── Load JSON ─────────────────────────────────────────────────────────────────

function Write-Step ([string]$Name) {
    Write-Host ("  [{0:HH:mm:ss}] Comparing: {1}" -f (Get-Date), $Name) -ForegroundColor Cyan
}

Write-Step "Loading report files"
$L = Get-Content $LeftFile -Raw -Encoding UTF8 | ConvertFrom-Json
$R = if ($singleMode) { $null } else { Get-Content $RightFile -Raw -Encoding UTF8 | ConvertFrom-Json }
Write-Step "Parsing data"
# Snapshot error count after load — anything added beyond this is a report-generation error
$script:CmpErrStart = $global:Error.Count

$leftCode  = if ($L.Metadata.SiteCode) { $L.Metadata.SiteCode } else { "LEFT" }
$rightCode = if ($singleMode) { "" } elseif ($R.Metadata.SiteCode) { $R.Metadata.SiteCode } else { "RIGHT" }

$leftLabel  = "$leftCode  ($($L.Metadata.GeneratedAt) on $($L.Metadata.GeneratedOn))"
$rightLabel = if ($singleMode) { "" } else { "$rightCode ($($R.Metadata.GeneratedAt) on $($R.Metadata.GeneratedOn))" }

if (-not $OutputPath) { $OutputPath = Split-Path (Resolve-Path $LeftFile) -Parent }

# ── Helpers ───────────────────────────────────────────────────────────────────

function Get-Props ($obj) {
    if ($null -eq $obj) { return @() }
    @($obj | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -Expand Name)
}

function Val-Str ($val) {
    if ($null -eq $val)   { return '' }
    if ($val -is [string]) { return $val }
    if ($val -is [bool])   { return $val.ToString().ToLower() }
    if ($val -is [array])  {
        if ($val.Count -eq 0) { return '[]' }
        return ($val | ConvertTo-Json -Compress -Depth 6 -ErrorAction SilentlyContinue)
    }
    $p = Get-Props $val
    if ($p.Count -gt 0) { return ($val | ConvertTo-Json -Compress -Depth 6 -ErrorAction SilentlyContinue) }
    return "$val"
}

function He ([string]$s) {
    $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

function Is-Diff ($a, $b) { (Val-Str $a) -ne (Val-Str $b) }

$script:TotalDiffs   = 0
$script:SectionDiffs = [ordered]@{}

function Record-Diff ([string]$sec, [int]$n) {
    if ($script:SingleMode) { $n = 0 }
    if ($script:SectionDiffs.Contains($sec)) { $script:SectionDiffs[$sec] += $n }
    else { $script:SectionDiffs[$sec] = $n }
    $script:TotalDiffs += $n
}

function Diff-Badge ([int]$n, [string]$sec) {
    if ($n -gt 0)               { "<span class='badge bdiff' id='badge_$sec'>$n diff$(if($n-ne 1){'s'})</span>" }
    elseif ($script:SingleMode) { "" }
    else                        { "<span class='badge bok'   id='badge_$sec'>Match</span>" }
}

function Single-Badge ([int]$crit=0, [int]$warn=0, [int]$info=0, [int]$pass=0) {
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($crit -gt 0) { [void]$parts.Add("<span class='badge bdiff'>$crit critical</span>") }
    if ($warn -gt 0) { [void]$parts.Add("<span class='badge bwarn'>$warn warning$(if($warn -ne 1){'s'})</span>") }
    if ($info -gt 0) { [void]$parts.Add("<span class='badge binfo'>$info info</span>") }
    if ($parts.Count -eq 0 -and $pass -gt 0) { [void]$parts.Add("<span class='badge bok'>All pass</span>") }
    return $parts -join " "
}

# ── KV Table (flat object comparison) ────────────────────────────────────────

function Build-KVTable {
    param([string]$SecId, $LObj, $RObj, [string[]]$Skip = @())

    $keys  = @((Get-Props $LObj) + (Get-Props $RObj)) | Sort-Object -Unique | Where-Object { $_ -notin $Skip }
    $diffs = 0
    $sb    = [System.Text.StringBuilder]::new()

    if ($script:SingleMode) {
        [void]$sb.Append("<thead><tr><th class='col-prop'>Property</th><th class='col-val'>$leftCode</th></tr></thead><tbody>")
        foreach ($k in $keys) {
            $lv = if ($LObj) { try { $LObj.$k } catch { $null } } else { $null }
            [void]$sb.Append("<tr><td class='prop'>$(He $k)</td><td class='val'>$(He (Val-Str $lv))</td></tr>")
        }
    } else {
        [void]$sb.Append("<thead><tr><th class='col-prop'>Property</th><th class='col-val'>$leftCode</th><th class='col-val'>$rightCode</th></tr></thead><tbody>")
        foreach ($k in $keys) {
            $lv  = if ($LObj) { try { $LObj.$k } catch { $null } } else { $null }
            $rv  = if ($RObj) { try { $RObj.$k } catch { $null } } else { $null }
            $ls  = Val-Str $lv
            $rs  = Val-Str $rv
            $d   = $ls -ne $rs
            if ($d) { $diffs++ }
            $cls = if ($d) { 'diff' } else { 'match' }
            $lc  = if ($d) { 'ldiff' } else { 'val' }
            $rc  = if ($d) { 'rdiff' } else { 'val' }
            [void]$sb.Append("<tr class='$cls'><td class='prop'>$(He $k)</td><td class='$lc'>$(He $ls)</td><td class='$rc'>$(He $rs)</td></tr>")
        }
    }

    [void]$sb.Append("</tbody>")
    Record-Diff $SecId $diffs
    return $sb.ToString(), $diffs
}

# ── Array Table (list comparison keyed on a field) ────────────────────────────

function Build-ArrayTable {
    param(
        [string]$SecId,
        [array] $LArr,
        [array] $RArr,
        [string]$KeyField,
        [string[]]$Fields = @()
    )

    if (-not $LArr)  { $LArr  = @() }
    if (-not $RArr)  { $RArr  = @() }

    # Build maps
    $lMap = @{}; $rMap = @{}
    $keys = [System.Collections.Generic.List[string]]::new()

    foreach ($item in $LArr) {
        $k = try { "$($item.$KeyField)" } catch { "?" }
        $lMap[$k] = $item
        if (-not $keys.Contains($k)) { [void]$keys.Add($k) }
    }
    foreach ($item in $RArr) {
        $k = try { "$($item.$KeyField)" } catch { "?" }
        $rMap[$k] = $item
        if (-not $keys.Contains($k)) { [void]$keys.Add($k) }
    }

    # Determine display fields
    if ($Fields.Count -eq 0) {
        $sample = if ($LArr.Count -gt 0) { $LArr[0] } elseif ($RArr.Count -gt 0) { $RArr[0] } else { $null }
        $Fields = @($KeyField) + @(Get-Props $sample | Where-Object { $_ -ne $KeyField })
    }
    $dataFields = $Fields | Where-Object { $_ -ne $KeyField }

    $diffs = 0
    $sb    = [System.Text.StringBuilder]::new()

    if ($script:SingleMode) {
        # Single-column view — key + one value column per field, left data only
        [void]$sb.Append("<thead><tr>")
        [void]$sb.Append("<th class='col-key'>$(He $KeyField)</th>")
        foreach ($f in $dataFields) { [void]$sb.Append("<th class='col-l'>$(He $f)</th>") }
        [void]$sb.Append("</tr></thead><tbody>")
        foreach ($k in ($lMap.Keys | Sort-Object)) {
            $li = $lMap[$k]
            [void]$sb.Append("<tr><td class='key-cell'>$(He $k)</td>")
            foreach ($f in $dataFields) {
                $lv = try { $li.$f } catch { $null }
                [void]$sb.Append("<td class='val'>$(He (Val-Str $lv))</td>")
            }
            [void]$sb.Append("</tr>")
        }
    } else {
        # Side-by-side comparison — key + paired columns per field
        [void]$sb.Append("<thead><tr>")
        [void]$sb.Append("<th class='col-key'>$(He $KeyField)</th>")
        foreach ($f in $dataFields) {
            [void]$sb.Append("<th class='col-l'>$(He $f) ($leftCode)</th><th class='col-r'>$(He $f) ($rightCode)</th>")
        }
        [void]$sb.Append("</tr></thead><tbody>")
        foreach ($k in ($keys | Sort-Object)) {
            $li = $lMap[$k]; $ri = $rMap[$k]
            if ($li -and (-not $ri)) {
                $diffs++
                [void]$sb.Append("<tr class='diff only-left'><td class='key-cell'>$(He $k)</td>")
                foreach ($f in $dataFields) {
                    $lv = try { $li.$f } catch { $null }
                    [void]$sb.Append("<td class='ldiff'>$(He (Val-Str $lv))</td><td class='missing'><em>not present</em></td>")
                }
                [void]$sb.Append("</tr>")
            } elseif ((-not $li) -and $ri) {
                $diffs++
                [void]$sb.Append("<tr class='diff only-right'><td class='key-cell'>$(He $k)</td>")
                foreach ($f in $dataFields) {
                    $rv = try { $ri.$f } catch { $null }
                    [void]$sb.Append("<td class='missing'><em>not present</em></td><td class='rdiff'>$(He (Val-Str $rv))</td>")
                }
                [void]$sb.Append("</tr>")
            } else {
                $rowDiff = $false
                $cells   = [System.Text.StringBuilder]::new()
                foreach ($f in $dataFields) {
                    $lv = try { $li.$f } catch { $null }
                    $rv = try { $ri.$f } catch { $null }
                    $fd = Is-Diff $lv $rv
                    if ($fd) { $rowDiff = $true; $diffs++ }
                    $lc = if ($fd) { 'ldiff' } else { 'val' }
                    $rc = if ($fd) { 'rdiff' } else { 'val' }
                    [void]$cells.Append("<td class='$lc'>$(He (Val-Str $lv))</td><td class='$rc'>$(He (Val-Str $rv))</td>")
                }
                $cls = if ($rowDiff) { 'diff' } else { 'match' }
                [void]$sb.Append("<tr class='$cls'><td class='key-cell'>$(He $k)</td>$($cells.ToString())</tr>")
            }
        }
    }

    [void]$sb.Append("</tbody>")
    Record-Diff $SecId $diffs
    return $sb.ToString(), $diffs
}

# ── Section wrapper ───────────────────────────────────────────────────────────

function Wrap-Section {
    param([string]$Id, [string]$Title, [string]$Inner, [int]$Diffs, [string]$SingleBadge = "")
    if ($script:SingleMode) { $badge = $SingleBadge; $Diffs = 0 }
    else                    { $badge = Diff-Badge $Diffs $Id }
    $ctrl = if (-not $script:SingleMode) {
        "<div class='tbl-ctrl'><button class='btn-diffs' onclick=""toggleDiff(this,'$Id')"" data-state='all'>Show differences only</button><span class='row-counts' id='rc_$Id'></span></div>"
    } else { "" }
    @"
<section id="sec_$Id">
  <h2 class="sec-hdr $(if($Diffs -gt 0){'has-diffs'})" onclick="toggleSec('$Id')">
    <span class="tog" id="tog_$Id">&#9660;</span> $Title $badge
  </h2>
  <div class="sec-body" id="body_$Id">
    $ctrl
    <div class="tbl-wrap"><table class="cmp" id="tbl_$Id">$Inner</table></div>
  </div>
</section>
"@
}

function Wrap-Section-Raw {
    param([string]$Id, [string]$Title, [string]$Inner, [int]$Diffs, [string]$SingleBadge = "")
    if ($script:SingleMode) { $badge = $SingleBadge; $Diffs = 0 }
    else                    { $badge = Diff-Badge $Diffs $Id }
    @"
<section id="sec_$Id">
  <h2 class="sec-hdr $(if($Diffs -gt 0){'has-diffs'})" onclick="toggleSec('$Id')">
    <span class="tog" id="tog_$Id">&#9660;</span> $Title $badge
  </h2>
  <div class="sec-body" id="body_$Id">
    $Inner
  </div>
</section>
"@
}

# ── Insights helpers ─────────────────────────────────────────────────────────

function Get-Insights ($report) {
    $items = [System.Collections.Generic.List[object]]::new()
    function ai ([string]$cat, [string]$sev, [string]$msg) {
        [void]$items.Add([ordered]@{ Category=$cat; Severity=$sev; Message=$msg })
    }

    # Health checks — any non-Pass status
    try {
        @($report.HealthChecks.Checks) | Where-Object { $_.Status -and $_.Status -ne 'Pass' } | ForEach-Object {
            $sev = if ($_.Status -in @('Fail','Error')) { 'Critical' } elseif ($_.Status -eq 'Warning') { 'Warning' } else { 'Info' }
            ai "Health Check" $sev "[$($_.Status)] $($_.Name): $($_.Detail)"
        }
    } catch {}

    # Component status — non-OK
    try {
        @($report.ComponentStatus) | Where-Object { $_.State -and $_.State -ne 'OK' } | ForEach-Object {
            $sev = if ($_.State -eq 'Error') { 'Critical' } else { 'Warning' }
            ai "Component" $sev "$($_.ComponentName): $($_.State)"
        }
    } catch {}

    # Role server probes — stopped services and low disk
    try {
        @($report.RoleServerProbes.Probes.PSObject.Properties) | ForEach-Object {
            $srv = $_.Name; $p = $_.Value
            @($p.Services) | Where-Object { $_ -and $_.State -and $_.State -ne 'Running' } | ForEach-Object {
                ai "Service" "Critical" "${srv}: $($_.Name) is $($_.State)"
            }
            @($p.Disks) | Where-Object { $_ -and $_.SizeGB -gt 0 } | ForEach-Object {
                $pct = [math]::Round($_.FreeGB / $_.SizeGB * 100, 1)
                if     ($pct -lt 10) { ai "Disk Space" "Critical" "${srv} — $($_.Drive): $($_.FreeGB) GB free ($pct%)" }
                elseif ($pct -lt 20) { ai "Disk Space" "Warning"  "${srv} — $($_.Drive): $($_.FreeGB) GB free ($pct%)" }
            }
        }
    } catch {}

    # Logs — error and warning counts
    try {
        $errs = [int]$report.Logs.Summary.TotalErrors
        $warn = [int]$report.Logs.Summary.TotalWarnings
        if ($errs -gt 0) { ai "Logs" "Warning" "$errs error entries in log files (48 hr window)" }
        if ($warn -gt 0) { ai "Logs" "Info"    "$warn warning entries in log files (48 hr window)" }
    } catch {}

    # Content distribution failures
    try {
        $fc = [int]$report.ContentDistribution.FailureCount
        if ($fc -gt 0) { ai "Content Dist." "Critical" "$fc content distribution failure$(if($fc-ne 1){'s'})" }
    } catch {}

    return @($items)
}

function Build-InsightPanel ([array]$insights, [string]$envLabel) {
    $crits = @($insights | Where-Object { $_.Severity -eq 'Critical' })
    $warns = @($insights | Where-Object { $_.Severity -eq 'Warning' })
    $infos = @($insights | Where-Object { $_.Severity -eq 'Info' })
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='insight-panel'>")
    [void]$sb.Append("<div class='insight-hdr'><strong>$envLabel</strong>&nbsp;")
    if ($insights.Count -eq 0) {
        [void]$sb.Append("<span class='ins-badge ins-ok'>&#10003; No actions needed</span>")
    } else {
        if ($crits.Count -gt 0) { [void]$sb.Append("<span class='ins-badge ins-crit'>$($crits.Count) critical</span> ") }
        if ($warns.Count -gt 0) { [void]$sb.Append("<span class='ins-badge ins-warn'>$($warns.Count) warning</span> ") }
        if ($infos.Count -gt 0) { [void]$sb.Append("<span class='ins-badge ins-info'>$($infos.Count) info</span>") }
    }
    [void]$sb.Append("</div>")
    if ($insights.Count -eq 0) {
        [void]$sb.Append("<p class='ins-empty'>All checks passed. No actions required.</p>")
    } else {
        [void]$sb.Append("<table class='cmp ins-tbl'><thead><tr><th class='ins-col-cat'>Category</th><th>Detail</th></tr></thead><tbody>")
        foreach ($sev in @('Critical','Warning','Info')) {
            @($insights | Where-Object { $_.Severity -eq $sev }) | ForEach-Object {
                $rc = switch ($sev) { 'Critical'{'ins-crit-row'}; 'Warning'{'ins-warn-row'}; default{'ins-info-row'} }
                $bc = "ins-$($sev.ToLower())"
                [void]$sb.Append("<tr class='$rc'>")
                [void]$sb.Append("<td class='ins-col-cat'><span class='ins-cat-pill $bc'>$(He $_.Category)</span></td>")
                [void]$sb.Append("<td class='ins-col-msg'>$(He $_.Message)</td>")
                [void]$sb.Append("</tr>")
            }
        }
        [void]$sb.Append("</tbody></table>")
    }
    [void]$sb.Append("</div>")
    return $sb.ToString()
}

# ── Per-section builders ──────────────────────────────────────────────────────

$sections = [System.Text.StringBuilder]::new()

function Add-Section ([string]$Id, [string]$Title, [string]$Inner, [int]$Diffs, [string]$SingleBadge = "") {
    [void]$script:sections.Append((Wrap-Section $Id $Title $Inner $Diffs $SingleBadge))
}

Write-Step "Summary"
# 1. Summary counts
$summaryRows = [System.Text.StringBuilder]::new()
if ($singleMode) {
    [void]$summaryRows.Append("<thead><tr><th>Item</th><th>$leftCode</th></tr></thead><tbody>")
} else {
    [void]$summaryRows.Append("<thead><tr><th>Item</th><th>$leftCode</th><th>$rightCode</th><th>Status</th></tr></thead><tbody>")
}

$countItems = @(
    @{ Label="MECM Version";    L=$L.SiteInfo.Version;                     R=$R.SiteInfo.Version                     }
    @{ Label="Build Number";    L=$L.SiteInfo.BuildNumber;                 R=$R.SiteInfo.BuildNumber                 }
    @{ Label="Site Roles";      L=$L.SiteSystemRoles.Count;               R=$R.SiteSystemRoles.Count               }
    @{ Label="Boundaries";      L=$L.Boundaries.Count;                    R=$R.Boundaries.Count                    }
    @{ Label="Boundary Groups"; L=$L.BoundaryGroups.Count;                R=$R.BoundaryGroups.Count                }
    @{ Label="Client Settings"; L=$L.ClientSettings.Count;                R=$R.ClientSettings.Count                }
    @{ Label="DPs";             L=$L.DistributionPoints.Count;            R=$R.DistributionPoints.Count            }
    @{ Label="DP Groups";       L=$L.DPGroups.Count;                      R=$R.DPGroups.Count                      }
    @{ Label="Device Colls";    L=$L.Collections.DeviceCollectionCount;   R=$R.Collections.DeviceCollectionCount   }
    @{ Label="User Colls";      L=$L.Collections.UserCollectionCount;     R=$R.Collections.UserCollectionCount     }
    @{ Label="Applications";    L=$L.Applications.Count;                  R=$R.Applications.Count                  }
    @{ Label="Packages";        L=$L.Packages.PackageCount;               R=$R.Packages.PackageCount               }
    @{ Label="Task Sequences";  L=$L.Packages.TaskSequenceCount;          R=$R.Packages.TaskSequenceCount          }
    @{ Label="Driver Packages"; L=$L.Packages.DriverPkgCount;             R=$R.Packages.DriverPkgCount             }
    @{ Label="Boot Images";     L=$L.OSD.BootImages.Count;                R=$R.OSD.BootImages.Count                }
    @{ Label="OS Images";       L=$L.OSD.OSImages.Count;                  R=$R.OSD.OSImages.Count                  }
    @{ Label="OS Upgrade Pkgs"; L=$L.OSD.OSUpgradePackages.Count;         R=$R.OSD.OSUpgradePackages.Count         }
    @{ Label="EP Policies";     L=$L.EndpointProtection.PolicyCount;      R=$R.EndpointProtection.PolicyCount      }
    @{ Label="Maint. Windows";  L=$L.MaintenanceWindows.Count;            R=$R.MaintenanceWindows.Count            }
    @{ Label="Metering Rules";  L=$L.SoftwareMetering.RuleCount;          R=$R.SoftwareMetering.RuleCount          }
    @{ Label="SW Update Cats";  L=$L.SoftwareUpdates.EnabledCatCount;     R=$R.SoftwareUpdates.EnabledCatCount     }
    @{ Label="Site Components"; L=$L.ComponentStatus.Count;               R=$R.ComponentStatus.Count               }
    @{ Label="Admin Users";    L=$L.RBAC.AdminCount;                      R=$R.RBAC.AdminCount                      }
    @{ Label="Auto Deploy Rules";L=(@($L.AutoDeploymentRules) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.AutoDeploymentRules) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="Deployments";    L=$L.Deployments.TotalDeployments;         R=$R.Deployments.TotalDeployments         }
    @{ Label="Config Baselines";L=(@($L.ConfigurationBaselines) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.ConfigurationBaselines) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="Run Scripts";    L=(@($L.RunScripts) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.RunScripts) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="HW Inv. Classes";L=$L.HardwareInventory.ClassCount;         R=$R.HardwareInventory.ClassCount         }
    @{ Label="Content Failures";L=$L.ContentDistribution.FailureCount;    R=$R.ContentDistribution.FailureCount     }
    @{ Label="Maint. Tasks";    L=(@($L.SiteMaintenanceTasks) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.SiteMaintenanceTasks) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="SW Update Groups";L=$L.SoftwareUpdateGroups.Count;           R=$R.SoftwareUpdateGroups.Count           }
    @{ Label="Certificates";    L=(@($L.Certificates) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.Certificates) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="IIS App Pools";   L=(@($L.IISConfiguration.ApplicationPools) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.IISConfiguration.ApplicationPools) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="WSUS Port";       L=$L.WSUSConfiguration.PortNumber;          R=$R.WSUSConfiguration.PortNumber          }
    @{ Label="Content DPs";     L=(@($L.ContentStore.DistributionPoints) | Where-Object {$_ -isnot [string]}).Count; R=(@($R.ContentStore.DistributionPoints) | Where-Object {$_ -isnot [string]}).Count }
    @{ Label="Inacc. Sources";  L=$L.ContentStore.InaccessibleSourceCount;  R=$R.ContentStore.InaccessibleSourceCount  }
    @{ Label="HC Total";        L=$L.HealthChecks.Summary.Total;             R=$R.HealthChecks.Summary.Total             }
    @{ Label="HC Pass";         L=$L.HealthChecks.Summary.Pass;              R=$R.HealthChecks.Summary.Pass              }
    @{ Label="HC Warn";         L=$L.HealthChecks.Summary.Warning;           R=$R.HealthChecks.Summary.Warning           }
    @{ Label="HC Fail";         L=$L.HealthChecks.Summary.Fail;              R=$R.HealthChecks.Summary.Fail              }
    @{ Label="Named Svc Accts"; L=$L.ServiceAccounts.Summary.NamedServiceAccountCount; R=$R.ServiceAccounts.Summary.NamedServiceAccountCount }
    @{ Label="gMSA in use";     L=$L.ServiceAccounts.Summary.gMSACount;               R=$R.ServiceAccounts.Summary.gMSACount               }
    @{ Label="SQL DB Accounts";  L=$L.ServiceAccounts.Summary.SQLAccountCount;          R=$R.ServiceAccounts.Summary.SQLAccountCount          }
    @{ Label="Servers Probed";   L=$L.RoleServerProbes.ServersProbed;                   R=$R.RoleServerProbes.ServersProbed                   }
    @{ Label="CCM HTTP Port";   L=$L.RegistrySettings.CCM.Base.HttpPort;  R=$R.RegistrySettings.CCM.Base.HttpPort  }
    @{ Label="CCM HTTPS Port";  L=$L.RegistrySettings.CCM.Base.HttpsPort; R=$R.RegistrySettings.CCM.Base.HttpsPort }
    @{ Label="CCM Lookup MP";   L=$L.RegistrySettings.CCM.Base.LookupMPList; R=$R.RegistrySettings.CCM.Base.LookupMPList }
)

$summDiffs = 0
foreach ($ci in $countItems) {
    $ls = Val-Str $ci.L
    if ($singleMode) {
        [void]$summaryRows.Append("<tr><td class='prop'>$(He $ci.Label)</td><td class='val'>$(He $ls)</td></tr>")
    } else {
        $rs  = Val-Str $ci.R
        $d   = $ls -ne $rs
        if ($d) { $summDiffs++ }
        $cls = if ($d) { 'diff' } else { 'match' }
        $lc  = if ($d) { 'ldiff' } else { 'val' }
        $rc  = if ($d) { 'rdiff' } else { 'val' }
        $st  = if ($d) { "<span class='status-diff'>&#9888; Different</span>" } else { "<span class='status-ok'>&#10003; Match</span>" }
        [void]$summaryRows.Append("<tr class='$cls'><td class='prop'>$(He $ci.Label)</td><td class='$lc'>$(He $ls)</td><td class='$rc'>$(He $rs)</td><td>$st</td></tr>")
    }
}
[void]$summaryRows.Append("</tbody>")
Add-Section "summary" "Summary Counts" $summaryRows.ToString() $summDiffs

Write-Step "Insights"
# Insights
$lInsights = Get-Insights $L
$rInsights = if ($singleMode) { @() } else { Get-Insights $R }
$insightDiffs = (@($lInsights | Where-Object { $_.Severity -eq 'Critical' }).Count) +
               (@($rInsights | Where-Object { $_.Severity -eq 'Critical' }).Count)
$insightsSb = [System.Text.StringBuilder]::new()
[void]$insightsSb.Append("<div class='insight-row'>")
[void]$insightsSb.Append((Build-InsightPanel $lInsights $leftCode))
if (-not $singleMode) {
    [void]$insightsSb.Append((Build-InsightPanel $rInsights $rightCode))
}
[void]$insightsSb.Append("</div>")
$insightSingleBadge = if ($singleMode) {
    $lCrit = @($lInsights | Where-Object { $_.Severity -eq 'Critical' }).Count
    $lWarn = @($lInsights | Where-Object { $_.Severity -eq 'Warning'  }).Count
    $lInfo = @($lInsights | Where-Object { $_.Severity -eq 'Info'     }).Count
    Single-Badge $lCrit $lWarn $lInfo
} else { "" }
Record-Diff "insights" $insightDiffs
[void]$script:sections.Append((Wrap-Section-Raw "insights" "Insights — Actions Needed" $insightsSb.ToString() $insightDiffs $insightSingleBadge))

Write-Step "Site Information"
# 2. Site Info
$t, $d = Build-KVTable "siteinfo" $L.SiteInfo $R.SiteInfo
Add-Section "siteinfo" "Site Information" $t $d

Write-Step "Site System Roles"
# 3. Site System Roles
$t, $d = Build-ArrayTable "siteroles" $L.SiteSystemRoles $R.SiteSystemRoles "NALPath" @("NALPath","RoleName","ServerName","SiteCode","ResourceType")
Add-Section "siteroles" "Site System Roles" $t $d

Write-Step "Boundaries"
# 4. Boundaries
$t, $d = Build-ArrayTable "bounds" $L.Boundaries $R.Boundaries "BoundaryID" @("BoundaryID","DisplayName","BoundaryType","Value","GroupCount")
Add-Section "bounds" "Boundaries" $t $d

Write-Step "Boundary Groups"
# 5. Boundary Groups
$t, $d = Build-ArrayTable "boundgroups" $L.BoundaryGroups $R.BoundaryGroups "Name" @("Name","Description","DefaultSiteCode","MemberCount")
Add-Section "boundgroups" "Boundary Groups" $t $d

Write-Step "Client Settings"
# 6. Client Settings
$t, $d = Build-ArrayTable "clientsettings" $L.ClientSettings $R.ClientSettings "Name" @("Name","Priority","Type","Description","AssignmentCount")
Add-Section "clientsettings" "Client Settings" $t $d

Write-Step "Discovery Methods"
# 7. Discovery Methods — one KV block per method
$discSb   = [System.Text.StringBuilder]::new()
$discDiffs = 0
$discMethods = @("ActiveDirectorySystemDiscovery","ActiveDirectoryUserDiscovery","ActiveDirectoryGroupDiscovery",
                 "ActiveDirectoryForestDiscovery","HeartbeatDiscovery","NetworkDiscovery")
foreach ($m in $discMethods) {
    $lm = if ($L.DiscoveryMethods) { try { $L.DiscoveryMethods.$m } catch { $null } } else { $null }
    $rm = if ($R.DiscoveryMethods) { try { $R.DiscoveryMethods.$m } catch { $null } } else { $null }
    $lp = if ($lm) { try { $lm.Props } catch { $null } } else { $null }
    $rp = if ($rm) { try { $rm.Props } catch { $null } } else { $null }
    $inner, $dd = Build-KVTable "disc_$m" $lp $rp
    $discDiffs += $dd
    [void]$discSb.Append("<h3 class='sub-hdr'>$m $(Diff-Badge $dd "disc_$m")</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
}
Record-Diff "discovery" $discDiffs
[void]$sections.Append((Wrap-Section "discovery" "Discovery Methods" $discSb.ToString() $discDiffs))

Write-Step "Software Update Configuration"
# 8. Software Updates — SUP servers + categories
$suSb   = [System.Text.StringBuilder]::new()
$suDiffs = 0

# SUP Server list
$lSups = @($L.SoftwareUpdates.SUPServers | ForEach-Object { [pscustomobject]@{ Server=$_ } })
$rSups = @($R.SoftwareUpdates.SUPServers | ForEach-Object { [pscustomobject]@{ Server=$_ } })
$inner, $dd = Build-ArrayTable "su_sups" $lSups $rSups "Server" @("Server")
$suDiffs += $dd
[void]$suSb.Append("<h3 class='sub-hdr'>SUP Servers $(Diff-Badge $dd 'su_sups')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Enabled update categories
$inner, $dd = Build-ArrayTable "su_cats" $L.SoftwareUpdates.EnabledCategories $R.SoftwareUpdates.EnabledCategories "Name" @("Name","CategoryType","ID")
$suDiffs += $dd
[void]$suSb.Append("<h3 class='sub-hdr'>Enabled Classifications &amp; Products $(Diff-Badge $dd 'su_cats')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# SUP component properties
$inner, $dd = Build-KVTable "su_props" $L.SoftwareUpdates.ComponentProperties $R.SoftwareUpdates.ComponentProperties
$suDiffs += $dd
[void]$suSb.Append("<h3 class='sub-hdr'>SUP Component Properties $(Diff-Badge $dd 'su_props')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "supdate" $suDiffs
[void]$sections.Append((Wrap-Section "supdate" "Software Update Configuration" $suSb.ToString() $suDiffs))

Write-Step "Distribution Points"
# 9. Distribution Points
$t, $d = Build-ArrayTable "dps" $L.DistributionPoints $R.DistributionPoints "ServerName" `
    @("ServerName","SiteCode","IsPXE","IsMulticast","IsPullDP","IsActive","IsProtected","Priority","ContentLibPath","AvailContentLibDiskGB")
Add-Section "dps" "Distribution Points" $t $d

Write-Step "DP Groups"
# 10. DP Groups
$t, $d = Build-ArrayTable "dpgroups" $L.DPGroups $R.DPGroups "Name" @("Name","Description","MemberCount","CollectionCount")
Add-Section "dpgroups" "DP Groups" $t $d

Write-Step "Collections"
# 11. Collections
$colSb   = [System.Text.StringBuilder]::new()
$colDiffs = 0

$inner, $dd = Build-ArrayTable "dcol" $L.Collections.DeviceCollections $R.Collections.DeviceCollections "Name" `
    @("Name","CollectionID","MemberCount","LimitingCollectionID","RefreshType","IsBuiltIn")
$colDiffs += $dd
[void]$colSb.Append("<h3 class='sub-hdr'>Device Collections $(Diff-Badge $dd 'dcol')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-ArrayTable "ucol" $L.Collections.UserCollections $R.Collections.UserCollections "Name" `
    @("Name","CollectionID","MemberCount","LimitingCollectionID","RefreshType","IsBuiltIn")
$colDiffs += $dd
[void]$colSb.Append("<h3 class='sub-hdr'>User Collections $(Diff-Badge $dd 'ucol')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "collections" $colDiffs
[void]$sections.Append((Wrap-Section "collections" "Collections" $colSb.ToString() $colDiffs))

Write-Step "Applications"
# 12. Applications
$t, $d = Build-ArrayTable "apps" $L.Applications.Applications $R.Applications.Applications "Name" `
    @("Name","Publisher","SoftwareVersion","IsDeployed","NumberOfDeploymentTypes","LastModifiedBy")
Add-Section "apps" "Applications" $t $d

Write-Step "Packages & Task Sequences"
# 13. Packages
$pkgSb   = [System.Text.StringBuilder]::new()
$pkgDiffs = 0

$inner, $dd = Build-ArrayTable "pkgs" $L.Packages.Packages $R.Packages.Packages "Name" @("Name","PackageID","Version","Manufacturer","SourcePath")
$pkgDiffs += $dd; [void]$pkgSb.Append("<h3 class='sub-hdr'>Packages $(Diff-Badge $dd 'pkgs')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-ArrayTable "tseqs" $L.Packages.TaskSequences $R.Packages.TaskSequences "Name" @("Name","PackageID","Version","BootImageID")
$pkgDiffs += $dd; [void]$pkgSb.Append("<h3 class='sub-hdr'>Task Sequences $(Diff-Badge $dd 'tseqs')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-ArrayTable "drvpkgs" $L.Packages.DriverPackages $R.Packages.DriverPackages "Name" @("Name","PackageID","Version","SourcePath")
$pkgDiffs += $dd; [void]$pkgSb.Append("<h3 class='sub-hdr'>Driver Packages $(Diff-Badge $dd 'drvpkgs')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "packages" $pkgDiffs
[void]$sections.Append((Wrap-Section "packages" "Packages &amp; Task Sequences" $pkgSb.ToString() $pkgDiffs))

Write-Step "OSD"
# 14. OSD
$osdSb   = [System.Text.StringBuilder]::new()
$osdDiffs = 0

$inner, $dd = Build-ArrayTable "boot" $L.OSD.BootImages $R.OSD.BootImages "Name" @("Name","PackageID","Version","Architecture","SourcePath","BackgroundBitmapPath")
$osdDiffs += $dd; [void]$osdSb.Append("<h3 class='sub-hdr'>Boot Images $(Diff-Badge $dd 'boot')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-ArrayTable "osimg" $L.OSD.OSImages $R.OSD.OSImages "Name" @("Name","PackageID","Version","SourcePath")
$osdDiffs += $dd; [void]$osdSb.Append("<h3 class='sub-hdr'>OS Images $(Diff-Badge $dd 'osimg')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-ArrayTable "osupg" $L.OSD.OSUpgradePackages $R.OSD.OSUpgradePackages "Name" @("Name","PackageID","Version","SourcePath")
$osdDiffs += $dd; [void]$osdSb.Append("<h3 class='sub-hdr'>OS Upgrade Packages $(Diff-Badge $dd 'osupg')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "osd" $osdDiffs
[void]$sections.Append((Wrap-Section "osd" "OSD" $osdSb.ToString() $osdDiffs))

Write-Step "Endpoint Protection"
# 15. Endpoint Protection
$t, $d = Build-ArrayTable "ep" $L.EndpointProtection.Policies $R.EndpointProtection.Policies "Name" `
    @("Name","SettingType","RealTimeProtectionEnabled","DefinitionUpdatesEnabled","CloudProtectionLevel","ScheduledScanEnabled","ScheduledScanTime","ScheduledScanType")
Add-Section "ep" "Endpoint Protection" $t $d

Write-Step "Maintenance Windows"
# 16. Maintenance Windows
$t, $d = Build-ArrayTable "mw" $L.MaintenanceWindows $R.MaintenanceWindows "Name" `
    @("Name","CollectionID","ServiceWindowType","IsEnabled","Duration","IsGMT")
Add-Section "mw" "Maintenance Windows" $t $d

Write-Step "Software Metering"
# 17. Software Metering
$t, $d = Build-ArrayTable "metering" $L.SoftwareMetering.Rules $R.SoftwareMetering.Rules "RuleID" `
    @("RuleID","ProductName","FileName","FileVersion","LanguageID","Enabled")
Add-Section "metering" "Software Metering" $t $d

Write-Step "Cloud Services"
# 18. Cloud Services
$cldSb   = [System.Text.StringBuilder]::new()
$cldDiffs = 0

$lCMG = @($L.CloudServices.CMGConnectionPoints | ForEach-Object { [pscustomobject]@{ Server=$_ } })
$rCMG = @($R.CloudServices.CMGConnectionPoints | ForEach-Object { [pscustomobject]@{ Server=$_ } })
$inner, $dd = Build-ArrayTable "cmg" $lCMG $rCMG "Server" @("Server")
$cldDiffs += $dd; [void]$cldSb.Append("<h3 class='sub-hdr'>CMG Connection Points $(Diff-Badge $dd 'cmg')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-ArrayTable "azsvc" $L.CloudServices.AzureServices $R.CloudServices.AzureServices "ServiceName" `
    @("ServiceName","ServiceType","TenantName","TenantID","Region")
$cldDiffs += $dd; [void]$cldSb.Append("<h3 class='sub-hdr'>Azure Services $(Diff-Badge $dd 'azsvc')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "cloud" $cldDiffs
[void]$sections.Append((Wrap-Section "cloud" "Cloud Services" $cldSb.ToString() $cldDiffs))

Write-Step "Hierarchy Settings"
# 19. Hierarchy Settings
$t, $d = Build-KVTable "hier" $L.HierarchySettings.Properties $R.HierarchySettings.Properties
Add-Section "hier" "Hierarchy Settings" $t $d

Write-Step "Component Status"
# 20. Component Status
$compSingleBadge = if ($singleMode) {
    $cErr  = @($L.ComponentStatus | Where-Object { $_ -and $_.State -eq 'Error'   }).Count
    $cWarn = @($L.ComponentStatus | Where-Object { $_ -and $_.State -eq 'Warning' }).Count
    $cOK   = @($L.ComponentStatus | Where-Object { $_ -and $_.State -eq 'OK'      }).Count
    Single-Badge $cErr $cWarn 0 $(if ($cErr -eq 0 -and $cWarn -eq 0) { $cOK } else { 0 })
} else { "" }
$t, $d = Build-ArrayTable "comp" $L.ComponentStatus $R.ComponentStatus "ComponentName" `
    @("ComponentName","MachineName","State","ErrorCount","WarningCount","InfoCount")
Add-Section "comp" "Component Status" $t $d $compSingleBadge

Write-Step "Database Info"
# 21. Database Info
$t, $d = Build-KVTable "db" $L.DatabaseInfo $R.DatabaseInfo @("SQLConnectionStatus","SQLConnectionError","SQLServerVersion")
Add-Section "db" "Database Info" $t $d

Write-Step "Log Analysis"
# 22. Logs — viewer, not a diff.
# Log entries will always differ between environments; the goal is to let the
# user scroll through both sides' entries side by side to spot anything notable.
$logSb         = [System.Text.StringBuilder]::new()
$logDiffs      = 0
$logTotalErrors = 0

# ── Scan summary comparison (counts still usefully compared) ──────────────────
$lSum = if ($L.Logs -and $L.Logs.Summary) { $L.Logs.Summary } else { $null }
$rSum = if ($R.Logs -and $R.Logs.Summary) { $R.Logs.Summary } else { $null }
$sumInner, $dd = Build-KVTable "log_summary" $lSum $rSum
$logDiffs += $dd
[void]$logSb.Append("<h3 class='sub-hdr'>Scan Summary $(Diff-Badge $dd 'log_summary')</h3>")
[void]$logSb.Append("<div class='tbl-wrap'><table class='cmp'>$sumInner</table></div>")

# ── Per-log side-by-side viewer ───────────────────────────────────────────────
$lLogFiles = if ($L.Logs -and $L.Logs.LogFiles) { $L.Logs.LogFiles } else { $null }
$rLogFiles = if ($R.Logs -and $R.Logs.LogFiles) { $R.Logs.LogFiles } else { $null }

$allLogKeys = @()
if ($lLogFiles) { $allLogKeys += @(Get-Props $lLogFiles) }
if ($rLogFiles) { $allLogKeys += @(Get-Props $rLogFiles) }
$allLogKeys = $allLogKeys | Sort-Object -Unique

# Helper — build a scrollable entry table for one side of one log
function Build-LogTable ([string]$id, [array]$entries, [string]$envLabel) {
    if (-not $entries -or $entries.Count -eq 0) {
        return "<div class='log-panel'><p class='log-empty'>No entries in time window for $envLabel</p></div>"
    }
    $flaggedCount = @($entries | Where-Object { $_.Flagged -eq $true }).Count
    $flagBadge    = if ($flaggedCount -gt 0) { " <span class='flag-badge'>&#9873; $flaggedCount flagged</span>" } else { "" }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='log-panel' id='lp_$id'>")
    [void]$sb.Append("<div class='log-panel-hdr'>$envLabel &nbsp;<span class='log-count'>$($entries.Count) entries</span>$flagBadge &nbsp;")
    [void]$sb.Append("<button class='btn-diffs' onclick=""filterLogPanel('lp_$id',this)"" data-state='all'>Errors &amp; Warnings only</button></div>")
    [void]$sb.Append("<div class='log-scroll'><table class='cmp log-tbl'><thead><tr>")
    [void]$sb.Append("<th class='col-flag'></th><th class='col-dt'>Date / Time</th><th class='col-sev'>Sev</th><th class='col-comp'>Component</th><th class='col-msg'>Message</th>")
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($e in $entries) {
        $sev      = Val-Str $e.Severity
        $sevCls   = switch ($sev) { "Error"{"sev-err-row"}; "Warning"{"sev-warn-row"}; default{"sev-info-row"} }
        $isFlagged = $e.Flagged -eq $true
        $flagCls  = if ($isFlagged) { " flagged" } else { "" }
        $flagCell = if ($isFlagged) { "<td class='col-flag flag-ind' title='Flagged'>&#9873;</td>" } else { "<td class='col-flag'></td>" }
        [void]$sb.Append("<tr class='$sevCls$flagCls'>")
        [void]$sb.Append($flagCell)
        [void]$sb.Append("<td class='col-dt'>$(He (Val-Str $e.DateTime))</td>")
        [void]$sb.Append("<td class='col-sev'>$(He $sev)</td>")
        [void]$sb.Append("<td class='col-comp'>$(He (Val-Str $e.Component))</td>")
        [void]$sb.Append("<td class='col-msg'>$(He (Val-Str $e.Message))</td>")
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table></div></div>")
    return $sb.ToString()
}

foreach ($lk in $allLogKeys) {
    $ll = if ($lLogFiles) { try { $lLogFiles.$lk } catch { $null } } else { $null }
    $rl = if ($rLogFiles) { try { $rLogFiles.$lk } catch { $null } } else { $null }

    $label     = if ($ll -and $ll.Label) { $ll.Label } else { $lk }
    $lEntries  = if ($ll -and $ll.Entries) { @($ll.Entries) } else { @() }
    $rEntries  = if ($rl -and $rl.Entries) { @($rl.Entries) } else { @() }
    $lErrCount = if ($ll) { [int]$ll.ErrorCount } else { 0 }
    $rErrCount = if ($rl) { [int]$rl.ErrorCount } else { 0 }
    $totalErrs = $lErrCount + $rErrCount
    $logTotalErrors += $lErrCount

    # Meta row: file stats for both sides
    $lMeta = if ($ll) { [pscustomobject]@{ Exists=$ll.Exists; FileSizeKB=$ll.FileSizeKB; LastModified=$ll.LastModified; ErrorCount=$ll.ErrorCount; WarningCount=$ll.WarningCount; EntriesStored=@($lEntries).Count } } else { $null }
    $rMeta = if ($rl) { [pscustomobject]@{ Exists=$rl.Exists; FileSizeKB=$rl.FileSizeKB; LastModified=$rl.LastModified; ErrorCount=$rl.ErrorCount; WarningCount=$rl.WarningCount; EntriesStored=@($rEntries).Count } } else { $null }
    $metaInner, $mdd = Build-KVTable "lm_$lk" $lMeta $rMeta
    $logDiffs += $mdd

    $errBadge = if ($totalErrs -gt 0) { " <span class='err-badge'>$totalErrs errors</span>" } else { "" }
    [void]$logSb.Append("<h3 class='sub-hdr'>$label ($lk.log)$errBadge</h3>")
    [void]$logSb.Append("<div class='log-file-block'>")
    [void]$logSb.Append("<div class='tbl-wrap'><table class='cmp'>$metaInner</table></div>")
    [void]$logSb.Append("<div class='log-viewer'>")
    [void]$logSb.Append((Build-LogTable "$($lk)_L" $lEntries $leftCode))
    if (-not $singleMode) {
        [void]$logSb.Append((Build-LogTable "$($lk)_R" $rEntries $rightCode))
    }
    [void]$logSb.Append("</div></div>")
}

$logSingleBadge = if ($singleMode -and $logTotalErrors -gt 0) { "<span class='badge bdiff'>$logTotalErrors error$(if($logTotalErrors -ne 1){'s'})</span>" } else { "" }
Record-Diff "logs" $logDiffs
[void]$sections.Append((Wrap-Section-Raw "logs" "Log Analysis" $logSb.ToString() $logDiffs $logSingleBadge))

# ── Helper: safely unwrap a section object (returns $null if it holds an _Error key)
function Unwrap-Section ($obj) {
    if ($null -eq $obj) { return $null }
    $p = Get-Props $obj
    if ($p -contains '_Error') { return $null }
    return $obj
}

# ── Helper: safe array from a potentially null/scalar section sub-property
function Safe-Arr ($val) {
    if ($null -eq $val) { return @() }
    return @($val)
}

Write-Step "RBAC"
# 23. RBAC
$rbacSb   = [System.Text.StringBuilder]::new()
$rbacDiffs = 0

$Lrb = Unwrap-Section $L.RBAC
$Rrb = Unwrap-Section $R.RBAC

# Admin Users
$lAdmins = if ($Lrb) { @( $Lrb.AdminUsers ) } else { @() }
$rAdmins = if ($Rrb) { @( $Rrb.AdminUsers ) } else { @() }
$inner, $dd = Build-ArrayTable "rbac_admins" $lAdmins $rAdmins "LogonName" @("LogonName","IsGroup","Roles","Scopes","Collections","CreatedBy","LastModifiedBy")
$rbacDiffs += $dd
[void]$rbacSb.Append("<h3 class='sub-hdr'>Admin Users $(Diff-Badge $dd 'rbac_admins')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Security Roles
$lRoles = if ($Lrb) { @( $Lrb.Roles ) } else { @() }
$rRoles = if ($Rrb) { @( $Rrb.Roles ) } else { @() }
$inner, $dd = Build-ArrayTable "rbac_roles" $lRoles $rRoles "RoleName" @("RoleName","Description","IsBuiltIn","CopiedFrom")
$rbacDiffs += $dd
[void]$rbacSb.Append("<h3 class='sub-hdr'>Security Roles $(Diff-Badge $dd 'rbac_roles')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Security Scopes
$lScopes = if ($Lrb) { @( $Lrb.SecurityScopes ) } else { @() }
$rScopes = if ($Rrb) { @( $Rrb.SecurityScopes ) } else { @() }
$inner, $dd = Build-ArrayTable "rbac_scopes" $lScopes $rScopes "Name" @("Name","Description","IsBuiltIn")
$rbacDiffs += $dd
[void]$rbacSb.Append("<h3 class='sub-hdr'>Security Scopes $(Diff-Badge $dd 'rbac_scopes')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "rbac" $rbacDiffs
[void]$sections.Append((Wrap-Section "rbac" "RBAC" $rbacSb.ToString() $rbacDiffs))

Write-Step "Automatic Deployment Rules"
# 24. Automatic Deployment Rules
$lAdrs = if ($L.AutoDeploymentRules) { @( $L.AutoDeploymentRules ) } else { @() }
$rAdrs = if ($R.AutoDeploymentRules) { @( $R.AutoDeploymentRules ) } else { @() }
$lAdrs = @($lAdrs | Where-Object { $_ -isnot [string] })
$rAdrs = @($rAdrs | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "adrs" $lAdrs $rAdrs "Name" @("Name","CollectionName","Enabled","LastRunState","LastRunTime","LastErrorCode","Schedule")
Add-Section "adrs" "Automatic Deployment Rules" $t $d

Write-Step "Deployments"
# 25. Deployments
$depSb   = [System.Text.StringBuilder]::new()
$depDiffs = 0

$Ldep = Unwrap-Section $L.Deployments
$Rdep = Unwrap-Section $R.Deployments

# Summary KV (totals + by-type counts)
$lDepSum = if ($Ldep) { [pscustomobject]@{ TotalDeployments=$Ldep.TotalDeployments } } else { $null }
$rDepSum = if ($Rdep) { [pscustomobject]@{ TotalDeployments=$Rdep.TotalDeployments } } else { $null }
$inner, $dd = Build-KVTable "dep_sum" $lDepSum $rDepSum
$depDiffs += $dd
[void]$depSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'dep_sum')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# By-type breakdown
$inner, $dd = Build-KVTable "dep_types" ($Ldep.ByType) ($Rdep.ByType)
$depDiffs += $dd
[void]$depSb.Append("<h3 class='sub-hdr'>By Type $(Diff-Badge $dd 'dep_types')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Deployment list
$lDeps = if ($Ldep) { @( $Ldep.Deployments ) } else { @() }
$rDeps = if ($Rdep) { @( $Rdep.Deployments ) } else { @() }
$inner, $dd = Build-ArrayTable "dep_list" $lDeps $rDeps "Name" @("Name","Type","CollectionName","Intent","NumberTargeted","NumberSuccess","NumberErrors","NumberInProgress")
$depDiffs += $dd
[void]$depSb.Append("<h3 class='sub-hdr'>Deployments $(Diff-Badge $dd 'dep_list')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "deployments" $depDiffs
[void]$sections.Append((Wrap-Section "deployments" "Deployments" $depSb.ToString() $depDiffs))

Write-Step "Client Communication"
# 26. Client Communication
$ccSb   = [System.Text.StringBuilder]::new()
$ccDiffs = 0

$Lcc = Unwrap-Section $L.ClientCommunication
$Rcc = Unwrap-Section $R.ClientCommunication

# Top-level KV
$lccKv = if ($Lcc) { [pscustomobject]@{ SiteSSLMode=$Lcc.SiteSSLMode; EnhancedHTTPEnabled=$Lcc.EnhancedHTTPEnabled; DPsUsingHTTPS=$Lcc.DPsUsingHTTPS; DPsUsingHTTP=$Lcc.DPsUsingHTTP } } else { $null }
$rccKv = if ($Rcc) { [pscustomobject]@{ SiteSSLMode=$Rcc.SiteSSLMode; EnhancedHTTPEnabled=$Rcc.EnhancedHTTPEnabled; DPsUsingHTTPS=$Rcc.DPsUsingHTTPS; DPsUsingHTTP=$Rcc.DPsUsingHTTP } } else { $null }
$inner, $dd = Build-KVTable "cc_kv" $lccKv $rccKv
$ccDiffs += $dd
[void]$ccSb.Append("<h3 class='sub-hdr'>Site Communication $(Diff-Badge $dd 'cc_kv')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Management Points
$lMPs = if ($Lcc) { @( $Lcc.ManagementPoints ) } else { @() }
$rMPs = if ($Rcc) { @( $Rcc.ManagementPoints ) } else { @() }
$inner, $dd = Build-ArrayTable "cc_mps" $lMPs $rMPs "ServerName" @("ServerName","SSLState","UseProxy")
$ccDiffs += $dd
[void]$ccSb.Append("<h3 class='sub-hdr'>Management Points $(Diff-Badge $dd 'cc_mps')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "clientcomm" $ccDiffs
[void]$sections.Append((Wrap-Section "clientcomm" "Client Communication" $ccSb.ToString() $ccDiffs))

Write-Step "Hardware Inventory"
# 27. Hardware Inventory Classes
$hwSb   = [System.Text.StringBuilder]::new()
$hwDiffs = 0

$Lhw = Unwrap-Section $L.HardwareInventory
$Rhw = Unwrap-Section $R.HardwareInventory

$lHwKv = if ($Lhw) { [pscustomobject]@{ ClassCount=$Lhw.ClassCount } } else { $null }
$rHwKv = if ($Rhw) { [pscustomobject]@{ ClassCount=$Rhw.ClassCount } } else { $null }
$inner, $dd = Build-KVTable "hw_sum" $lHwKv $rHwKv
$hwDiffs += $dd
[void]$hwSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'hw_sum')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lClasses = if ($Lhw) { @( $Lhw.Classes ) } else { @() }
$rClasses = if ($Rhw) { @( $Rhw.Classes ) } else { @() }
$inner, $dd = Build-ArrayTable "hw_classes" $lClasses $rClasses "ClassName" @("ClassName","SMSClassID")
$hwDiffs += $dd
[void]$hwSb.Append("<h3 class='sub-hdr'>Inventory Classes $(Diff-Badge $dd 'hw_classes')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "hwinv" $hwDiffs
[void]$sections.Append((Wrap-Section "hwinv" "Hardware Inventory" $hwSb.ToString() $hwDiffs))

Write-Step "Configuration Baselines"
# 28. Configuration Baselines
$lBL = if ($L.ConfigurationBaselines) { @( $L.ConfigurationBaselines ) } else { @() }
$rBL = if ($R.ConfigurationBaselines) { @( $R.ConfigurationBaselines ) } else { @() }
$lBL = @($lBL | Where-Object { $_ -isnot [string] })
$rBL = @($rBL | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "baselines" $lBL $rBL "Name" @("Name","Version","IsAssigned","NumberOfDeployments","NumberOfCIs","IsEnabled","CreatedBy","DateLastModified")
Add-Section "baselines" "Configuration Baselines" $t $d

Write-Step "Alerts"
# 29. Alerts
$alertSb   = [System.Text.StringBuilder]::new()
$alertDiffs = 0

$Lal = Unwrap-Section $L.Alerts
$Ral = Unwrap-Section $R.Alerts

$lAlerts = if ($Lal) { @( $Lal.Alerts ) } else { @() }
$rAlerts = if ($Ral) { @( $Ral.Alerts ) } else { @() }
$inner, $dd = Build-ArrayTable "alerts_list" $lAlerts $rAlerts "Name" @("Name","Severity","TypeID","IsEnabled","IsClosed","OccurrenceType")
$alertDiffs += $dd
[void]$alertSb.Append("<h3 class='sub-hdr'>Alerts $(Diff-Badge $dd 'alerts_list')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lSubs = if ($Lal) { @( $Lal.Subscriptions ) } else { @() }
$rSubs = if ($Ral) { @( $Ral.Subscriptions ) } else { @() }
$inner, $dd = Build-ArrayTable "alerts_subs" $lSubs $rSubs "Name" @("Name","TypeID","EmailTo")
$alertDiffs += $dd
[void]$alertSb.Append("<h3 class='sub-hdr'>Subscriptions $(Diff-Badge $dd 'alerts_subs')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "alerts" $alertDiffs
[void]$sections.Append((Wrap-Section "alerts" "Alerts" $alertSb.ToString() $alertDiffs))

Write-Step "Run Scripts"
# 30. Run Scripts
$lScripts = if ($L.RunScripts) { @( $L.RunScripts ) } else { @() }
$rScripts = if ($R.RunScripts) { @( $R.RunScripts ) } else { @() }
$lScripts = @($lScripts | Where-Object { $_ -isnot [string] })
$rScripts = @($rScripts | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "scripts" $lScripts $rScripts "ScriptName" @("ScriptName","Author","ApprovalState","Approver","ScriptType","LastUpdateTime","ScriptHash")
Add-Section "scripts" "Run Scripts" $t $d

Write-Step "Windows Servicing Plans"
# 31. Windows Servicing Plans
$lWSP = if ($L.WindowsServicingPlans) { @( $L.WindowsServicingPlans ) } else { @() }
$rWSP = if ($R.WindowsServicingPlans) { @( $R.WindowsServicingPlans ) } else { @() }
$lWSP = @($lWSP | Where-Object { $_ -isnot [string] })
$rWSP = @($rWSP | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "wsp" $lWSP $rWSP "Name" @("Name","CollectionName","Enabled","LastRunState","LastRunTime")
Add-Section "wsp" "Windows Servicing Plans" $t $d

Write-Step "Third-Party Update Catalogs"
# 32. Third-Party Update Catalogs
$lTPC = if ($L.ThirdPartyUpdateCatalogs) { @( $L.ThirdPartyUpdateCatalogs ) } else { @() }
$rTPC = if ($R.ThirdPartyUpdateCatalogs) { @( $R.ThirdPartyUpdateCatalogs ) } else { @() }
$lTPC = @($lTPC | Where-Object { $_ -isnot [string] })
$rTPC = @($rTPC | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "tpcatalogs" $lTPC $rTPC "CatalogName" @("CatalogName","Publisher","Version","IsSubscribed","IsAutoSync","IsMSFTContent","SupportURL")
Add-Section "tpcatalogs" "Third-Party Update Catalogs" $t $d

Write-Step "Co-Management"
# 33. Co-Management
$Lcm = Unwrap-Section $L.CoManagement
$Rcm = Unwrap-Section $R.CoManagement
$cmSb   = [System.Text.StringBuilder]::new()
$cmDiffs = 0

$lCmKv = if ($Lcm) { [pscustomobject]@{ Enabled=$Lcm.Enabled; AutoEnroll=$Lcm.AutoEnroll; MDMStatus=$Lcm.MDMStatus; CoManagementWorkloads=$Lcm.CoManagementWorkloads } } else { $null }
$rCmKv = if ($Rcm) { [pscustomobject]@{ Enabled=$Rcm.Enabled; AutoEnroll=$Rcm.AutoEnroll; MDMStatus=$Rcm.MDMStatus; CoManagementWorkloads=$Rcm.CoManagementWorkloads } } else { $null }
$inner, $dd = Build-KVTable "cm_kv" $lCmKv $rCmKv
$cmDiffs += $dd
[void]$cmSb.Append("<h3 class='sub-hdr'>Settings $(Diff-Badge $dd 'cm_kv')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-KVTable "cm_wl" ($Lcm.Workloads) ($Rcm.Workloads)
$cmDiffs += $dd
[void]$cmSb.Append("<h3 class='sub-hdr'>Workloads $(Diff-Badge $dd 'cm_wl')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "comanagement" $cmDiffs
[void]$sections.Append((Wrap-Section "comanagement" "Co-Management" $cmSb.ToString() $cmDiffs))

Write-Step "Content Distribution"
# 34. Content Distribution Status
$cdSb   = [System.Text.StringBuilder]::new()
$cdDiffs = 0

$Lcd = Unwrap-Section $L.ContentDistribution
$Rcd = Unwrap-Section $R.ContentDistribution

$lCdKv = if ($Lcd) { [pscustomobject]@{ TotalEntries=$Lcd.TotalEntries; FailureCount=$Lcd.FailureCount } } else { $null }
$rCdKv = if ($Rcd) { [pscustomobject]@{ TotalEntries=$Rcd.TotalEntries; FailureCount=$Rcd.FailureCount } } else { $null }
$inner, $dd = Build-KVTable "cd_sum" $lCdKv $rCdKv
$cdDiffs += $dd
[void]$cdSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'cd_sum')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$inner, $dd = Build-KVTable "cd_states" ($Lcd.Summary) ($Rcd.Summary)
$cdDiffs += $dd
[void]$cdSb.Append("<h3 class='sub-hdr'>Status Counts $(Diff-Badge $dd 'cd_states')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lFails = if ($Lcd) { @( $Lcd.Failures ) } else { @() }
$rFails = if ($Rcd) { @( $Rcd.Failures ) } else { @() }
$inner, $dd = Build-ArrayTable "cd_fails" $lFails $rFails "PackageID" @("PackageID","PackageName","PackageType","SourceVersion","ServerNALPath","LastUpdateTime")
$cdDiffs += $dd
[void]$cdSb.Append("<h3 class='sub-hdr'>Distribution Failures $(Diff-Badge $dd 'cd_fails')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "contentdist" $cdDiffs
[void]$sections.Append((Wrap-Section "contentdist" "Content Distribution" $cdSb.ToString() $cdDiffs))

Write-Step "Host System"
# 23. Host System
$hsSb   = [System.Text.StringBuilder]::new()
$hsDiffs = 0

# Unwrap - treat an _Error object as missing
$Lhs = $null; $Rhs = $null
if ($L.HostSystem) { $p = Get-Props $L.HostSystem; if ($p -notcontains '_Error') { $Lhs = $L.HostSystem } }
if ($R.HostSystem) { $p = Get-Props $R.HostSystem; if ($p -notcontains '_Error') { $Rhs = $R.HostSystem } }

if (-not $Lhs -and -not $Rhs) {
    [void]$hsSb.Append("<p style='color:#aaa;font-style:italic'>Host System data not available in either snapshot.</p>")
} else {
    # System
    $inner, $dd = Build-KVTable "hs_sys" ($Lhs.System) ($Rhs.System)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>System $(Diff-Badge $dd 'hs_sys')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Operating System
    $inner, $dd = Build-KVTable "hs_os" ($Lhs.OperatingSystem) ($Rhs.OperatingSystem)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Operating System $(Diff-Badge $dd 'hs_os')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # CPU
    $inner, $dd = Build-KVTable "hs_cpu" ($Lhs.CPU) ($Rhs.CPU)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>CPU $(Diff-Badge $dd 'hs_cpu')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Memory summary
    $lMemSum = if ($Lhs -and $Lhs.Memory) {
        [pscustomobject]@{ TotalInstalledGB=$Lhs.Memory.TotalInstalledGB; ModuleCount=$Lhs.Memory.ModuleCount }
    } else { $null }
    $rMemSum = if ($Rhs -and $Rhs.Memory) {
        [pscustomobject]@{ TotalInstalledGB=$Rhs.Memory.TotalInstalledGB; ModuleCount=$Rhs.Memory.ModuleCount }
    } else { $null }
    $inner, $dd = Build-KVTable "hs_mem" $lMemSum $rMemSum
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Memory $(Diff-Badge $dd 'hs_mem')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Memory modules
    $lMods = @(if ($Lhs -and $Lhs.Memory -and $Lhs.Memory.Modules) { $Lhs.Memory.Modules } else { @() })
    $rMods = @(if ($Rhs -and $Rhs.Memory -and $Rhs.Memory.Modules) { $Rhs.Memory.Modules } else { @() })
    $inner, $dd = Build-ArrayTable "hs_mods" $lMods $rMods "DeviceLocator" @("DeviceLocator","BankLabel","CapacityGB","SpeedMHz","MemoryType","Manufacturer","PartNumber")
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Memory Modules $(Diff-Badge $dd 'hs_mods')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Logical Disks
    $lLd = @(if ($Lhs -and $Lhs.LogicalDisks) { $Lhs.LogicalDisks } else { @() })
    $rLd = @(if ($Rhs -and $Rhs.LogicalDisks) { $Rhs.LogicalDisks } else { @() })
    $inner, $dd = Build-ArrayTable "hs_ldisk" $lLd $rLd "Drive" @("Drive","Label","FileSystem","SizeGB","FreeGB","FreePercent")
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Logical Disks $(Diff-Badge $dd 'hs_ldisk')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Physical Disks
    $lPd = @(if ($Lhs -and $Lhs.PhysicalDisks) { $Lhs.PhysicalDisks } else { @() })
    $rPd = @(if ($Rhs -and $Rhs.PhysicalDisks) { $Rhs.PhysicalDisks } else { @() })
    $inner, $dd = Build-ArrayTable "hs_pdisk" $lPd $rPd "Model" @("Model","SizeGB","MediaType","Partitions","Interface")
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Physical Disks $(Diff-Badge $dd 'hs_pdisk')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Network
    $lNet = @(if ($Lhs -and $Lhs.Network) { $Lhs.Network } else { @() })
    $rNet = @(if ($Rhs -and $Rhs.Network) { $Rhs.Network } else { @() })
    $inner, $dd = Build-ArrayTable "hs_net" $lNet $rNet "MACAddress" @("MACAddress","Description","IPAddresses","SubnetMasks","Gateways","DNSServers","DHCPEnabled","DHCPServer")
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Network Adapters $(Diff-Badge $dd 'hs_net')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # .NET Framework
    $inner, $dd = Build-KVTable "hs_dotnet" ($Lhs.DotNetFramework) ($Rhs.DotNetFramework)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>.NET Framework $(Diff-Badge $dd 'hs_dotnet')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # IIS
    $inner, $dd = Build-KVTable "hs_iis" ($Lhs.IIS) ($Rhs.IIS)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>IIS $(Diff-Badge $dd 'hs_iis')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # SQL Instances
    $lSql = @(if ($Lhs -and $Lhs.SQLInstances) { $Lhs.SQLInstances } else { @() })
    $rSql = @(if ($Rhs -and $Rhs.SQLInstances) { $Rhs.SQLInstances } else { @() })
    $inner, $dd = Build-ArrayTable "hs_sql" $lSql $rSql "InstanceName" @("InstanceName","Version","ServiceName","State","StartMode","StartName")
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>SQL Instances $(Diff-Badge $dd 'hs_sql')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # SQL Agents
    $lSqlA = @(if ($Lhs -and $Lhs.SQLAgents) { $Lhs.SQLAgents } else { @() })
    $rSqlA = @(if ($Rhs -and $Rhs.SQLAgents) { $Rhs.SQLAgents } else { @() })
    $inner, $dd = Build-ArrayTable "hs_sqla" $lSqlA $rSqlA "ServiceName" @("ServiceName","State","StartMode","StartName")
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>SQL Agent Services $(Diff-Badge $dd 'hs_sqla')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Windows Features
    $inner, $dd = Build-KVTable "hs_feat" ($Lhs.WindowsFeatures) ($Rhs.WindowsFeatures)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Windows Features $(Diff-Badge $dd 'hs_feat')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Time Sync
    $inner, $dd = Build-KVTable "hs_time" ($Lhs.TimeSync) ($Rhs.TimeSync)
    $hsDiffs += $dd
    [void]$hsSb.Append("<h3 class='sub-hdr'>Time Sync / NTP $(Diff-Badge $dd 'hs_time')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Pending Reboot
    $lRawRb  = if ($Lhs) { $Lhs.PendingReboot }         else { $null }
    $rRawRb  = if ($Rhs) { $Rhs.PendingReboot }         else { $null }
    $lRawRs  = if ($Lhs) { $Lhs.PendingRebootReasons }  else { $null }
    $rRawRs  = if ($Rhs) { $Rhs.PendingRebootReasons }  else { $null }
    $lReboot  = Val-Str $lRawRb
    $rReboot  = Val-Str $rRawRb
    $lReasons = Val-Str $lRawRs
    $rReasons = Val-Str $rRawRs
    $rbDiff   = ($lReboot -ne $rReboot) -or ($lReasons -ne $rReasons)
    if ($rbDiff) { $hsDiffs++ }
    $rbBadge = Diff-Badge ([int]$rbDiff) "hs_reboot"
    $lrc  = if ($lReboot -ne $rReboot) { 'ldiff' } else { 'val' }
    $rrc  = if ($lReboot -ne $rReboot) { 'rdiff' } else { 'val' }
    $lrc2 = if ($lReasons -ne $rReasons) { 'ldiff' } else { 'val' }
    $rrc2 = if ($lReasons -ne $rReasons) { 'rdiff' } else { 'val' }
    $rbCls = if ($rbDiff) { 'diff' } else { 'match' }
    [void]$hsSb.Append("<h3 class='sub-hdr'>Pending Reboot $rbBadge</h3>")
    [void]$hsSb.Append("<div class='tbl-wrap'><table class='cmp'><thead><tr><th class='col-prop'>Property</th><th class='col-val'>$leftCode</th><th class='col-val'>$rightCode</th></tr></thead><tbody>")
    [void]$hsSb.Append("<tr class='$rbCls'><td class='prop'>PendingReboot</td><td class='$lrc'>$(He $lReboot)</td><td class='$rrc'>$(He $rReboot)</td></tr>")
    [void]$hsSb.Append("<tr class='$rbCls'><td class='prop'>Reasons</td><td class='$lrc2'>$(He $lReasons)</td><td class='$rrc2'>$(He $rReasons)</td></tr>")
    [void]$hsSb.Append("</tbody></table></div>")
}

Record-Diff "hostsystem" $hsDiffs
[void]$sections.Append((Wrap-Section "hostsystem" "Host System" $hsSb.ToString() $hsDiffs))

Write-Step "Site Maintenance Tasks"
# 35. Site Maintenance Tasks
$lMaint = if ($L.SiteMaintenanceTasks) { @($L.SiteMaintenanceTasks) } else { @() }
$rMaint = if ($R.SiteMaintenanceTasks) { @($R.SiteMaintenanceTasks) } else { @() }
$lMaint = @($lMaint | Where-Object { $_ -isnot [string] })
$rMaint = @($rMaint | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "maintasks" $lMaint $rMaint "TaskName" @("TaskName","IsEnabled","DaysOfWeekText","BeginTime","LatestBeginTime","NumRefreshDays")
Add-Section "maintasks" "Site Maintenance Tasks" $t $d

Write-Step "Software Update Groups"
# 36. Software Update Groups
$sugSb    = [System.Text.StringBuilder]::new()
$sugDiffs = 0
$Lsug = Unwrap-Section $L.SoftwareUpdateGroups
$Rsug = Unwrap-Section $R.SoftwareUpdateGroups
$lSugKv = if ($Lsug) { [pscustomobject]@{ Count=$Lsug.Count } } else { $null }
$rSugKv = if ($Rsug) { [pscustomobject]@{ Count=$Rsug.Count } } else { $null }
$inner, $dd = Build-KVTable "sug_sum" $lSugKv $rSugKv
$sugDiffs += $dd
[void]$sugSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'sug_sum')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
$lSugs = if ($Lsug) { @($Lsug.Groups) } else { @() }
$rSugs = if ($Rsug) { @($Rsug.Groups) } else { @() }
$inner, $dd = Build-ArrayTable "sug_list" $lSugs $rSugs "Name" @("Name","NumberOfUpdates","IsDeployed","IsExpired","DateCreated","DateLastModified","CreatedBy")
$sugDiffs += $dd
[void]$sugSb.Append("<h3 class='sub-hdr'>Groups $(Diff-Badge $dd 'sug_list')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
Record-Diff "sugroups" $sugDiffs
[void]$sections.Append((Wrap-Section "sugroups" "Software Update Groups" $sugSb.ToString() $sugDiffs))

Write-Step "Status Filter Rules"
# 37. Status Filter Rules
$sfSb    = [System.Text.StringBuilder]::new()
$sfDiffs = 0
$Lsf = Unwrap-Section $L.StatusFilterRules
$Rsf = Unwrap-Section $R.StatusFilterRules
$lsfProps = if ($Lsf) { $Lsf.ComponentProps } else { $null }
$rsfProps = if ($Rsf) { $Rsf.ComponentProps } else { $null }
$lsfLists = if ($Lsf) { $Lsf.ComponentPropLists } else { $null }
$rsfLists = if ($Rsf) { $Rsf.ComponentPropLists } else { $null }
$inner, $dd = Build-KVTable "sf_props" $lsfProps $rsfProps
$sfDiffs += $dd
[void]$sfSb.Append("<h3 class='sub-hdr'>Status Manager Properties $(Diff-Badge $dd 'sf_props')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
$inner, $dd = Build-KVTable "sf_lists" $lsfLists $rsfLists
$sfDiffs += $dd
[void]$sfSb.Append("<h3 class='sub-hdr'>Status Manager PropLists $(Diff-Badge $dd 'sf_lists')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
Record-Diff "statusfilter" $sfDiffs
[void]$sections.Append((Wrap-Section "statusfilter" "Status Filter Rules" $sfSb.ToString() $sfDiffs))

Write-Step "Certificates"
# 38. Certificates
$lCerts = if ($L.Certificates) { @($L.Certificates) } else { @() }
$rCerts = if ($R.Certificates) { @($R.Certificates) } else { @() }
$lCerts = @($lCerts | Where-Object { $_ -isnot [string] })
$rCerts = @($rCerts | Where-Object { $_ -isnot [string] })
$t, $d = Build-ArrayTable "certs" $lCerts $rCerts "Thumbprint" @("Thumbprint","FQDN","CertificateType","IssuedTo","IssuedBy","ValidFrom","ValidUntil","IsBlocked")
Add-Section "certs" "Site Certificates" $t $d

Write-Step "IIS Configuration"
# 39. IIS Configuration
$iisCmpSb    = [System.Text.StringBuilder]::new()
$iisCmpDiffs = 0
$Liis = Unwrap-Section $L.IISConfiguration
$Riis = Unwrap-Section $R.IISConfiguration

$lIisKv = if ($Liis) { [pscustomobject]@{ Version=$Liis.Version; W3SVCState=$Liis.W3SVCState; WASState=$Liis.WASState; WebAdminModuleAvailable=$Liis.WebAdminModuleAvailable } } else { $null }
$rIisKv = if ($Riis) { [pscustomobject]@{ Version=$Riis.Version; W3SVCState=$Riis.W3SVCState; WASState=$Riis.WASState; WebAdminModuleAvailable=$Riis.WebAdminModuleAvailable } } else { $null }
$inner, $dd = Build-KVTable "iis_kv" $lIisKv $rIisKv
$iisCmpDiffs += $dd
[void]$iisCmpSb.Append("<h3 class='sub-hdr'>IIS Summary $(Diff-Badge $dd 'iis_kv')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lSites = if ($Liis -and $Liis.Websites) { @($Liis.Websites) } else { @() }
$rSites = if ($Riis -and $Riis.Websites) { @($Riis.Websites) } else { @() }
$inner, $dd = Build-ArrayTable "iis_sites" $lSites $rSites "Name" @("Name","State","PhysicalPath","Bindings")
$iisCmpDiffs += $dd
[void]$iisCmpSb.Append("<h3 class='sub-hdr'>Websites $(Diff-Badge $dd 'iis_sites')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lPools = if ($Liis -and $Liis.ApplicationPools) { @($Liis.ApplicationPools) } else { @() }
$rPools = if ($Riis -and $Riis.ApplicationPools) { @($Riis.ApplicationPools) } else { @() }
$inner, $dd = Build-ArrayTable "iis_pools" $lPools $rPools "Name" @("Name","State","ManagedRuntime","PipelineMode","IdentityType","IdentityUser","StartMode","Enable32Bit")
$iisCmpDiffs += $dd
[void]$iisCmpSb.Append("<h3 class='sub-hdr'>Application Pools $(Diff-Badge $dd 'iis_pools')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lApps = if ($Liis -and $Liis.MECMApplications) { @($Liis.MECMApplications) } else { @() }
$rApps = if ($Riis -and $Riis.MECMApplications) { @($Riis.MECMApplications) } else { @() }
$inner, $dd = Build-ArrayTable "iis_apps" $lApps $rApps "AppPath" @("AppPath","Site","PhysicalPath","AppPool")
$iisCmpDiffs += $dd
[void]$iisCmpSb.Append("<h3 class='sub-hdr'>MECM Applications $(Diff-Badge $dd 'iis_apps')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lSSL = if ($Liis -and $Liis.SSLBindings) { @($Liis.SSLBindings) } else { @() }
$rSSL = if ($Riis -and $Riis.SSLBindings) { @($Riis.SSLBindings) } else { @() }
$inner, $dd = Build-ArrayTable "iis_ssl" $lSSL $rSSL "IPPort" @("IPPort","Thumbprint","Host")
$iisCmpDiffs += $dd
[void]$iisCmpSb.Append("<h3 class='sub-hdr'>SSL Bindings $(Diff-Badge $dd 'iis_ssl')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "iisconfig" $iisCmpDiffs
[void]$sections.Append((Wrap-Section "iisconfig" "IIS Configuration" $iisCmpSb.ToString() $iisCmpDiffs))

Write-Step "WSUS Configuration"
# 40. WSUS Configuration
$Lwsus = Unwrap-Section $L.WSUSConfiguration
$Rwsus = Unwrap-Section $R.WSUSConfiguration
# Skip transient disk-free values from the diff
$inner, $dd = Build-KVTable "wsus_kv" $Lwsus $Rwsus @("ContentDirDriveFreeGB","ContentDirDriveFreePct")
Add-Section "wsusconfig" "WSUS Configuration" $inner $dd

Write-Step "Content Store"
# 41. Content Store
$csCmpSb    = [System.Text.StringBuilder]::new()
$csCmpDiffs = 0
$Lcs = Unwrap-Section $L.ContentStore
$Rcs = Unwrap-Section $R.ContentStore

$inner, $dd = Build-KVTable "cs_sum" ($Lcs.PackageStatusSummary) ($Rcs.PackageStatusSummary)
$csCmpDiffs += $dd
[void]$csCmpSb.Append("<h3 class='sub-hdr'>Package Status Summary $(Diff-Badge $dd 'cs_sum')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lDPs = if ($Lcs -and $Lcs.DistributionPoints) { @($Lcs.DistributionPoints) } else { @() }
$rDPs = if ($Rcs -and $Rcs.DistributionPoints) { @($Rcs.DistributionPoints) } else { @() }
$inner, $dd = Build-ArrayTable "cs_dps" $lDPs $rDPs "ServerName" @("ServerName","ContentLibPath","IsPXE","IsMulticast","IsPullDP","IsActive")
$csCmpDiffs += $dd
[void]$csCmpSb.Append("<h3 class='sub-hdr'>DP Content Libraries $(Diff-Badge $dd 'cs_dps')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$lAccKv = if ($Lcs) { [pscustomobject]@{ InaccessibleSourceCount=$Lcs.InaccessibleSourceCount; PackageSourceSampleLimit=$Lcs.PackageSourceSampleLimit } } else { $null }
$rAccKv = if ($Rcs) { [pscustomobject]@{ InaccessibleSourceCount=$Rcs.InaccessibleSourceCount; PackageSourceSampleLimit=$Rcs.PackageSourceSampleLimit } } else { $null }
$inner, $dd = Build-KVTable "cs_acc" $lAccKv $rAccKv
$csCmpDiffs += $dd
[void]$csCmpSb.Append("<h3 class='sub-hdr'>Package Source Accessibility $(Diff-Badge $dd 'cs_acc')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "contentstore" $csCmpDiffs
[void]$sections.Append((Wrap-Section "contentstore" "Content Store" $csCmpSb.ToString() $csCmpDiffs))

Write-Step "Group Policy"
# 42. Group Policy Settings
$gpCmpSb    = [System.Text.StringBuilder]::new()
$gpCmpDiffs = 0
$Lgp = Unwrap-Section $L.GroupPolicySettings
$Rgp = Unwrap-Section $R.GroupPolicySettings

foreach ($cat in @("WindowsUpdate","WUAutoUpdate","BITS","WindowsFirewall","RemoteDesktop","WinDefender","SCEPAntimalware","SMBClient","MECM_Client")) {
    $lCat = if ($Lgp) { try { $Lgp.$cat } catch { $null } } else { $null }
    $rCat = if ($Rgp) { try { $Rgp.$cat } catch { $null } } else { $null }
    $inner, $dd = Build-KVTable "gp_$cat" $lCat $rCat
    $gpCmpDiffs += $dd
    [void]$gpCmpSb.Append("<h3 class='sub-hdr'>$cat $(Diff-Badge $dd "gp_$cat")</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
}

$lRsop = if ($Lgp) { [pscustomobject]@{ RSoPComputerSummary=$Lgp.RSoPComputerSummary } } else { $null }
$rRsop = if ($Rgp) { [pscustomobject]@{ RSoPComputerSummary=$Rgp.RSoPComputerSummary } } else { $null }
$inner, $dd = Build-KVTable "gp_rsop" $lRsop $rRsop
$gpCmpDiffs += $dd
[void]$gpCmpSb.Append("<h3 class='sub-hdr'>RSoP Summary $(Diff-Badge $dd 'gp_rsop')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "grouppolicy" $gpCmpDiffs
[void]$sections.Append((Wrap-Section "grouppolicy" "Group Policy Settings" $gpCmpSb.ToString() $gpCmpDiffs))

Write-Step "Health Checks"
# 43. Health Checks
$hcCmpSb    = [System.Text.StringBuilder]::new()
$hcCmpDiffs = 0
$Lhc = Unwrap-Section $L.HealthChecks
$Rhc = Unwrap-Section $R.HealthChecks

# Summary KV comparison
$lHcSum = if ($Lhc) { $Lhc.Summary } else { $null }
$rHcSum = if ($Rhc) { $Rhc.Summary } else { $null }
$inner, $dd = Build-KVTable "hc_summary" $lHcSum $rHcSum @("EffectivePrefix")
$hcCmpDiffs += $dd
[void]$hcCmpSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'hc_summary')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Per-check comparison — align by check Name
$lChecks = if ($Lhc -and $Lhc.Checks) { @($Lhc.Checks) } else { @() }
$rChecks = if ($Rhc -and $Rhc.Checks) { @($Rhc.Checks) } else { @() }

$allNames = (@($lChecks | ForEach-Object { $_.Name }) + @($rChecks | ForEach-Object { $_.Name })) | Select-Object -Unique | Sort-Object

$hcTblSb = [System.Text.StringBuilder]::new()
if ($singleMode) {
    [void]$hcTblSb.Append("<thead><tr><th>Check</th><th>Category</th><th>Status</th><th>Detail</th></tr></thead><tbody>")
} else {
    [void]$hcTblSb.Append("<thead><tr><th>Check</th><th>Category</th><th>$leftCode Status</th><th>$rightCode Status</th><th>$leftCode Detail</th><th>$rightCode Detail</th><th>Match</th></tr></thead><tbody>")
}
$hcRowDiffs = 0

foreach ($name in $allNames) {
    $lChk = $lChecks | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    $rChk = $rChecks | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    $lStatus = if ($lChk) { $lChk.Status } else { "" }
    $rStatus = if ($rChk) { $rChk.Status } else { "" }
    $lDetail = if ($lChk) { $lChk.Detail } else { "" }
    $rDetail = if ($rChk) { $rChk.Detail } else { "" }
    $cat     = if ($lChk) { $lChk.Category } elseif ($rChk) { $rChk.Category } else { "" }
    $lsClass = switch ($lStatus) { 'Pass' {'pass-cell'} 'Warning' {'warn-cell'} 'Fail' {'fail-cell'} 'Error' {'fail-cell'} default {''} }

    if ($singleMode) {
        [void]$hcTblSb.Append("<tr><td class='prop'>$(He $name)</td><td class='val'>$(He $cat)</td><td class='val $lsClass'>$(He $lStatus)</td><td class='val'>$(He $lDetail)</td></tr>")
    } else {
        $rsClass = switch ($rStatus) { 'Pass' {'pass-cell'} 'Warning' {'warn-cell'} 'Fail' {'fail-cell'} 'Error' {'fail-cell'} default {''} }
        $differ  = ($lStatus -ne $rStatus)
        if ($differ) { $hcRowDiffs++ }
        $cls = if ($differ) { 'diff' } else { 'match' }
        $lc  = if ($differ) { 'ldiff' } else { 'val' }
        $rc  = if ($differ) { 'rdiff' } else { 'val' }
        $st  = if ($differ) { "<span class='status-diff'>&#9888; Different</span>" } else { "<span class='status-ok'>&#10003; Match</span>" }
        [void]$hcTblSb.Append("<tr class='$cls'><td class='prop'>$(He $name)</td><td class='val'>$(He $cat)</td><td class='$lc $lsClass'>$(He $lStatus)</td><td class='$rc $rsClass'>$(He $rStatus)</td><td class='val'>$(He $lDetail)</td><td class='val'>$(He $rDetail)</td><td>$st</td></tr>")
    }
}
[void]$hcTblSb.Append("</tbody>")

$hcCmpDiffs += $hcRowDiffs
[void]$hcCmpSb.Append("<h3 class='sub-hdr'>Per-Check Results $(Diff-Badge $hcRowDiffs 'hc_checks')</h3><div class='tbl-wrap'><table class='cmp'>$($hcTblSb.ToString())</table></div>")

$hcSingleBadge = if ($singleMode) {
    $hcFail = @($lChecks | Where-Object { $_.Status -in @('Fail','Error') }).Count
    $hcWarn = @($lChecks | Where-Object { $_.Status -eq 'Warning'         }).Count
    $hcPass = @($lChecks | Where-Object { $_.Status -eq 'Pass'            }).Count
    $hcParts = @()
    if ($hcFail -gt 0) { $hcParts += "<span class='badge bdiff'>$hcFail fail</span>" }
    if ($hcWarn -gt 0) { $hcParts += "<span class='badge bwarn'>$hcWarn warning$(if($hcWarn -ne 1){'s'})</span>" }
    if ($hcPass -gt 0) { $hcParts += "<span class='badge bok'>$hcPass pass</span>" }
    $hcParts -join " "
} else { "" }
Record-Diff "healthchecks" $hcCmpDiffs
[void]$sections.Append((Wrap-Section "healthchecks" "Health Checks" $hcCmpSb.ToString() $hcCmpDiffs $hcSingleBadge))

Write-Step "Service Accounts"
# 44. Service Accounts
$saCmpSb    = [System.Text.StringBuilder]::new()
$saCmpDiffs = 0
$Lsa = Unwrap-Section $L.ServiceAccounts
$Rsa = Unwrap-Section $R.ServiceAccounts

# Summary KV
$lSaSum = if ($Lsa) { $Lsa.Summary } else { $null }
$rSaSum = if ($Rsa) { $Rsa.Summary } else { $null }
$inner, $dd = Build-KVTable "sa_summary" $lSaSum $rSaSum @("UniqueNamedAccounts")
$saCmpDiffs += $dd
[void]$saCmpSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'sa_summary')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Unique named accounts list
$lAccts = if ($Lsa -and $Lsa.Summary -and $Lsa.Summary.UniqueNamedAccounts) { @($Lsa.Summary.UniqueNamedAccounts) } else { @() }
$rAccts = if ($Rsa -and $Rsa.Summary -and $Rsa.Summary.UniqueNamedAccounts) { @($Rsa.Summary.UniqueNamedAccounts) } else { @() }
$allAccts = (@($lAccts) + @($rAccts)) | Select-Object -Unique | Sort-Object
$acctTblSb = [System.Text.StringBuilder]::new()
[void]$acctTblSb.Append("<thead><tr><th>Account</th><th>In $leftCode</th><th>In $rightCode</th><th>Match</th></tr></thead><tbody>")
$acctDiffs = 0
foreach ($a in $allAccts) {
    $inL  = $lAccts -contains $a
    $inR  = $rAccts -contains $a
    $diff = -not ($inL -and $inR)
    if ($diff) { $acctDiffs++ }
    $cls  = if ($diff) { if (-not $inL) { 'only-right' } else { 'only-left' } } else { 'match' }
    $lc   = if ($inL) { "<span class='status-ok'>&#10003; Yes</span>" } else { "<em class='missing'>not present</em>" }
    $rc   = if ($inR) { "<span class='status-ok'>&#10003; Yes</span>" } else { "<em class='missing'>not present</em>" }
    $st   = if ($diff) { "<span class='status-diff'>&#9888; Mismatch</span>" } else { "<span class='status-ok'>&#10003; Match</span>" }
    [void]$acctTblSb.Append("<tr class='$cls'><td class='prop'>$(He $a)</td><td>$lc</td><td>$rc</td><td>$st</td></tr>")
}
[void]$acctTblSb.Append("</tbody>")
$saCmpDiffs += $acctDiffs
[void]$saCmpSb.Append("<h3 class='sub-hdr'>Named Accounts $(Diff-Badge $acctDiffs 'sa_accts')</h3><div class='tbl-wrap'><table class='cmp'>$($acctTblSb.ToString())</table></div>")

# Windows services comparison (keyed on ServiceName)
$lSvcs = if ($Lsa -and $Lsa.WindowsServices) { @($Lsa.WindowsServices) } else { @() }
$rSvcs = if ($Rsa -and $Rsa.WindowsServices) { @($Rsa.WindowsServices) } else { @() }
$inner, $dd = Build-ArrayTable "sa_svcs" $lSvcs $rSvcs "ServiceName" @("IsNamedAcct","IsgMSA","DisplayName")
$saCmpDiffs += $dd
[void]$saCmpSb.Append("<h3 class='sub-hdr'>Windows Services $(Diff-Badge $dd 'sa_svcs')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Local groups comparison
$lGrps = if ($Lsa -and $Lsa.LocalGroups) { @($Lsa.LocalGroups) } else { @() }
$rGrps = if ($Rsa -and $Rsa.LocalGroups) { @($Rsa.LocalGroups) } else { @() }
$inner, $dd = Build-ArrayTable "sa_groups" $lGrps $rGrps "GroupName" @("MemberCount")
$saCmpDiffs += $dd
[void]$saCmpSb.Append("<h3 class='sub-hdr'>Local Groups $(Diff-Badge $dd 'sa_groups')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# SQL accounts comparison (keyed on LoginName)
$lSQL = if ($Lsa -and $Lsa.SQLAccounts) { @($Lsa.SQLAccounts | Where-Object { -not $_._Note -and -not $_._Error }) } else { @() }
$rSQL = if ($Rsa -and $Rsa.SQLAccounts) { @($Rsa.SQLAccounts | Where-Object { -not $_._Note -and -not $_._Error }) } else { @() }
$inner, $dd = Build-ArrayTable "sa_sql" $lSQL $rSQL "LoginName" @()
$saCmpDiffs += $dd
[void]$saCmpSb.Append("<h3 class='sub-hdr'>SQL Database Logins $(Diff-Badge $dd 'sa_sql')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Component accounts comparison
$lComp = if ($Lsa -and $Lsa.ComponentAccounts) { @($Lsa.ComponentAccounts | Where-Object { -not $_._Error }) } else { @() }
$rComp = if ($Rsa -and $Rsa.ComponentAccounts) { @($Rsa.ComponentAccounts | Where-Object { -not $_._Error }) } else { @() }
$inner, $dd = Build-ArrayTable "sa_comp" $lComp $rComp "Component" @()
$saCmpDiffs += $dd
[void]$saCmpSb.Append("<h3 class='sub-hdr'>MECM Component Accounts $(Diff-Badge $dd 'sa_comp')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

Record-Diff "serviceaccounts" $saCmpDiffs
[void]$sections.Append((Wrap-Section "serviceaccounts" "Service Accounts" $saCmpSb.ToString() $saCmpDiffs))

Write-Step "Role Server Probes"
# 45. Role Server Probes
# Compares by ROLE (not server name) so environments with different host names compare correctly.
$rspCmpSb    = [System.Text.StringBuilder]::new()
$rspCmpDiffs = 0
$Lrsp = Unwrap-Section $L.RoleServerProbes
$Rrsp = Unwrap-Section $R.RoleServerProbes

# Helper: build role→serverName lookup from a RoleMap PSCustomObject (JSON-deserialised)
function Get-RoleToServer ($roleMap) {
    $h = @{}
    if (-not $roleMap) { return $h }
    foreach ($prop in $roleMap.PSObject.Properties) {
        $srvName = $prop.Name
        foreach ($role in @($prop.Value)) {
            if (-not $h.ContainsKey($role)) { $h[$role] = $srvName }
        }
    }
    return $h
}

$lRoleToSrv = Get-RoleToServer ($Lrsp.RoleMap)
$rRoleToSrv = Get-RoleToServer ($Rrsp.RoleMap)

# All unique roles across both environments
$allRoles = (@($lRoleToSrv.Keys) + @($rRoleToSrv.Keys)) | Select-Object -Unique | Sort-Object

# Role map overview table
$rmTblSb = [System.Text.StringBuilder]::new()
[void]$rmTblSb.Append("<thead><tr><th>Role</th><th>$leftCode Server</th><th>$rightCode Server</th><th>Match</th></tr></thead><tbody>")
$rmDiffs = 0
foreach ($role in $allRoles) {
    $lSrv = if ($lRoleToSrv.ContainsKey($role)) { $lRoleToSrv[$role] } else { "" }
    $rSrv = if ($rRoleToSrv.ContainsKey($role)) { $rRoleToSrv[$role] } else { "" }
    $diff = ($lSrv -ne $rSrv)
    $cls  = if ($diff) { if (-not $lSrv) { 'only-right' } elseif (-not $rSrv) { 'only-left' } else { 'diff' } } else { 'match' }
    $lc   = if ($diff) { 'ldiff' } else { 'val' }
    $rc   = if ($diff) { 'rdiff' } else { 'val' }
    if ($diff) { $rmDiffs++ }
    $st   = if ($diff) { "<span class='status-diff'>&#9888; Different</span>" } else { "<span class='status-ok'>&#10003; Match</span>" }
    [void]$rmTblSb.Append("<tr class='$cls'><td class='prop'>$(He $role)</td><td class='$lc'>$(He $lSrv)</td><td class='$rc'>$(He $rSrv)</td><td>$st</td></tr>")
}
[void]$rmTblSb.Append("</tbody>")
$rspCmpDiffs += $rmDiffs
[void]$rspCmpSb.Append("<h3 class='sub-hdr'>Role Assignment $(Diff-Badge $rmDiffs 'rsp_rolemap')</h3><div class='tbl-wrap'><table class='cmp'>$($rmTblSb.ToString())</table></div>")

# Per-server deep comparison — iterates every server in Probes (not just one server per role)
function Get-ProbeServers ($probesObj) {
    $h = [ordered]@{}
    if (-not $probesObj) { return $h }
    foreach ($p in $probesObj.PSObject.Properties) {
        $h[$p.Name] = if ($p.Value -and $p.Value.Roles) { @($p.Value.Roles) } else { @() }
    }
    return $h
}
$lServers = Get-ProbeServers ($Lrsp.Probes)
$rServers = Get-ProbeServers ($Rrsp.Probes)

# Build role→[servers] for R to find the best L↔R match by role overlap
$rRoleServers = @{}
foreach ($rSrv in $rServers.Keys) {
    foreach ($role in $rServers[$rSrv]) {
        if (-not $rRoleServers.ContainsKey($role)) { $rRoleServers[$role] = [System.Collections.Generic.List[string]]::new() }
        [void]$rRoleServers[$role].Add($rSrv)
    }
}

$matchedR    = [System.Collections.Generic.HashSet[string]]::new()
$serverPairs = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($lSrv in $lServers.Keys) {
    $lRoles = $lServers[$lSrv]
    $bestR  = $null; $bestScore = 0
    foreach ($role in $lRoles) {
        if (-not $rRoleServers.ContainsKey($role)) { continue }
        foreach ($rCandidate in $rRoleServers[$role]) {
            if ($matchedR.Contains($rCandidate)) { continue }
            $score = @($rServers[$rCandidate] | Where-Object { $lRoles -contains $_ }).Count
            if ($score -gt $bestScore) { $bestScore = $score; $bestR = $rCandidate }
        }
    }
    if (-not $bestR -and $rServers.ContainsKey($lSrv) -and -not $matchedR.Contains($lSrv)) { $bestR = $lSrv }
    [void]$serverPairs.Add([pscustomobject]@{ L=$lSrv; R=$bestR })
    if ($bestR) { [void]$matchedR.Add($bestR) }
}
foreach ($rSrv in $rServers.Keys) {
    if (-not $matchedR.Contains($rSrv)) {
        [void]$serverPairs.Add([pscustomobject]@{ L=$null; R=$rSrv })
    }
}

foreach ($pair in $serverPairs) {
    $lSrv   = $pair.L
    $rSrv   = $pair.R
    $lProbe = if ($lSrv -and $Lrsp.Probes) { try { $Lrsp.Probes.$lSrv } catch { $null } } else { $null }
    $rProbe = if ($rSrv -and $Rrsp.Probes) { try { $Rrsp.Probes.$rSrv } catch { $null } } else { $null }

    $srvSb     = [System.Text.StringBuilder]::new()
    $srvDiffs  = 0
    $safeId    = ($(if ($lSrv) { $lSrv } else { $rSrv }) -replace '[^a-zA-Z0-9]','_').ToLower()
    $lLabel    = if ($lSrv) { "${leftCode}: $lSrv" }   else { "${leftCode}: (not present)" }
    $rLabel    = if ($rSrv) { "${rightCode}: $rSrv" } else { "${rightCode}: (not present)" }

    # OS comparison
    $lOS = if ($lProbe) { $lProbe.OS } else { $null }
    $rOS = if ($rProbe) { $rProbe.OS } else { $null }
    $inner, $dd = Build-KVTable "rsp_os_$safeId" $lOS $rOS @()
    $srvDiffs += $dd
    [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>OS / Hardware $(Diff-Badge $dd "rsp_os_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Disk comparison
    $lDisks = if ($lProbe -and $lProbe.Disks) { @($lProbe.Disks | Where-Object { $_.Drive }) } else { @() }
    $rDisks = if ($rProbe -and $rProbe.Disks) { @($rProbe.Disks | Where-Object { $_.Drive }) } else { @() }
    $inner, $dd = Build-ArrayTable "rsp_disk_$safeId" $lDisks $rDisks "Drive" @("SizeGB","FreeGB","FreePct")
    $srvDiffs += $dd
    [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>Disk Space $(Diff-Badge $dd "rsp_disk_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # Services
    $lSvcs = if ($lProbe -and $lProbe.Services) { @($lProbe.Services | Where-Object { $_.Name }) } else { @() }
    $rSvcs = if ($rProbe -and $rProbe.Services) { @($rProbe.Services | Where-Object { $_.Name }) } else { @() }
    $inner, $dd = Build-ArrayTable "rsp_svc_$safeId" $lSvcs $rSvcs "Name" @("State","StartMode","StartName")
    $srvDiffs += $dd
    [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>Services $(Diff-Badge $dd "rsp_svc_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

    # IIS App Pools (if present)
    $lIIS = if ($lProbe -and $lProbe.IIS -and $lProbe.IIS.AppPools) { @($lProbe.IIS.AppPools) } else { @() }
    $rIIS = if ($rProbe -and $rProbe.IIS -and $rProbe.IIS.AppPools) { @($rProbe.IIS.AppPools) } else { @() }
    if ($lIIS.Count -gt 0 -or $rIIS.Count -gt 0) {
        $inner, $dd = Build-ArrayTable "rsp_iis_$safeId" $lIIS $rIIS "Name" @("State","IdentityType","User")
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>IIS App Pools $(Diff-Badge $dd "rsp_iis_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    # IIS Websites (if present)
    $lWebsites = if ($lProbe -and $lProbe.IIS -and $lProbe.IIS.Websites) { @($lProbe.IIS.Websites) } else { @() }
    $rWebsites = if ($rProbe -and $rProbe.IIS -and $rProbe.IIS.Websites) { @($rProbe.IIS.Websites) } else { @() }
    if ($lWebsites.Count -gt 0 -or $rWebsites.Count -gt 0) {
        $inner, $dd = Build-ArrayTable "rsp_web_$safeId" $lWebsites $rWebsites "Name" @("State","PhysicalPath")
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>IIS Websites $(Diff-Badge $dd "rsp_web_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    # IIS SSL Bindings (if present)
    $lSSL = if ($lProbe -and $lProbe.IIS -and $lProbe.IIS.SSLBindings) { @($lProbe.IIS.SSLBindings) } else { @() }
    $rSSL = if ($rProbe -and $rProbe.IIS -and $rProbe.IIS.SSLBindings) { @($rProbe.IIS.SSLBindings) } else { @() }
    if ($lSSL.Count -gt 0 -or $rSSL.Count -gt 0) {
        $inner, $dd = Build-ArrayTable "rsp_ssl_$safeId" $lSSL $rSSL "IPPort" @("Thumbprint")
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>IIS SSL Bindings $(Diff-Badge $dd "rsp_ssl_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    # Certificates (if present)
    $lCerts = if ($lProbe -and $lProbe.Certificates) { @($lProbe.Certificates | Where-Object { -not $_._Note }) } else { @() }
    $rCerts = if ($rProbe -and $rProbe.Certificates) { @($rProbe.Certificates | Where-Object { -not $_._Note }) } else { @() }
    if ($lCerts.Count -gt 0 -or $rCerts.Count -gt 0) {
        $inner, $dd = Build-ArrayTable "rsp_cert_$safeId" $lCerts $rCerts "Thumbprint" @("Subject","NotAfter","DaysLeft","Template")
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>Certificates $(Diff-Badge $dd "rsp_cert_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    # Local Group Membership (if present)
    $lGroups = if ($lProbe -and $lProbe.LocalGroups) { @($lProbe.LocalGroups) } else { @() }
    $rGroups = if ($rProbe -and $rProbe.LocalGroups) { @($rProbe.LocalGroups) } else { @() }
    if ($lGroups.Count -gt 0 -or $rGroups.Count -gt 0) {
        $inner, $dd = Build-ArrayTable "rsp_grp_$safeId" $lGroups $rGroups "Group" @("Count","Members")
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>Local Group Membership $(Diff-Badge $dd "rsp_grp_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    # Installed Windows Features (if present — requires WinRM on target)
    $lFeat = if ($lProbe -and $lProbe.InstalledFeatures -and @($lProbe.InstalledFeatures).Count -gt 0) {
        @($lProbe.InstalledFeatures | ForEach-Object { [ordered]@{ Feature = $_ } })
    } else { @() }
    $rFeat = if ($rProbe -and $rProbe.InstalledFeatures -and @($rProbe.InstalledFeatures).Count -gt 0) {
        @($rProbe.InstalledFeatures | ForEach-Object { [ordered]@{ Feature = $_ } })
    } else { @() }
    if ($lFeat.Count -gt 0 -or $rFeat.Count -gt 0) {
        $inner, $dd = Build-ArrayTable "rsp_feat_$safeId" $lFeat $rFeat "Feature" @()
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>Installed Windows Features $(Diff-Badge $dd "rsp_feat_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    # WSUS Registry (if present)
    $lWSUS = if ($lProbe -and $lProbe.WSUSRegistry -and -not $lProbe.WSUSRegistry._Note) { $lProbe.WSUSRegistry } else { $null }
    $rWSUS = if ($rProbe -and $rProbe.WSUSRegistry -and -not $rProbe.WSUSRegistry._Note) { $rProbe.WSUSRegistry } else { $null }
    if ($lWSUS -or $rWSUS) {
        $inner, $dd = Build-KVTable "rsp_wsus_$safeId" $lWSUS $rWSUS @()
        $srvDiffs += $dd
        [void]$srvSb.Append("<h4 style='margin:10px 0 4px'>WSUS Registry $(Diff-Badge $dd "rsp_wsus_$safeId")</h4><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
    }

    $rspCmpDiffs += $srvDiffs
    $title = if ($singleMode) { $lSrv } else { "$lLabel / $rLabel" }
    [void]$rspCmpSb.Append("<div class='sub-section'><h3 class='sub-hdr'>Server: $title $(Diff-Badge $srvDiffs "rsp_$safeId")</h3>$($srvSb.ToString())</div>")
}

Record-Diff "roleserverprobes" $rspCmpDiffs
[void]$sections.Append((Wrap-Section "roleserverprobes" "Role Server Probes" $rspCmpSb.ToString() $rspCmpDiffs))

Write-Step "Registry Settings"
# 46. Registry Settings
$regCmpSb    = [System.Text.StringBuilder]::new()
$regCmpDiffs = 0
$Lreg = Unwrap-Section $L.RegistrySettings
$Rreg = Unwrap-Section $R.RegistrySettings

# Helper: compare a flat KV object that lives under a parent PSCustomObject
function Compare-RegGroup {
    param([string]$SecId, [string]$Title, $LParent, $RParent, [string]$Key)
    $lObj = if ($LParent) { try { $LParent.$Key } catch { $null } } else { $null }
    $rObj = if ($RParent) { try { $RParent.$Key } catch { $null } } else { $null }
    $inner, $dd = Build-KVTable $SecId $lObj $rObj @()
    return "<h3 class='sub-hdr'>$Title $(Diff-Badge $dd $SecId)</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>", $dd
}

# ── SMS sub-sections ──────────────────────────────────────────────────────────
$Lsms = if ($Lreg) { try { $Lreg.SMS } catch { $null } } else { $null }
$Rsms = if ($Rreg) { try { $Rreg.SMS } catch { $null } } else { $null }

foreach ($grp in @(
    @{Id="reg_sms_ident";  Title="SMS\\Identification";  Key="Identification"}
    @{Id="reg_sms_sql";    Title="SMS\\SQL Server";       Key="SqlServer"}
    @{Id="reg_sms_sec";    Title="SMS\\Security";         Key="Security"}
    @{Id="reg_sms_iis";    Title="SMS\\IIS";              Key="IIS"}
    @{Id="reg_sms_mp";     Title="SMS\\MP";               Key="MP"}
    @{Id="reg_sms_dp";     Title="SMS\\DP";               Key="DP"}
    @{Id="reg_sms_wsus";   Title="SMS\\WSUS";             Key="WSUS"}
    @{Id="reg_sms_setup";  Title="SMS\\Setup";            Key="Setup"}
)) {
    $html, $dd = Compare-RegGroup $grp.Id $grp.Title $Lsms $Rsms $grp.Key
    $regCmpDiffs += $dd
    [void]$regCmpSb.Append($html)
}

# SMS\Tracing — global values
$LsmsTracing = if ($Lsms) { try { $Lsms.Tracing } catch { $null } } else { $null }
$RsmsTracing = if ($Rsms) { try { $Rsms.Tracing } catch { $null } } else { $null }
$LtracGlobal = if ($LsmsTracing) { try { $LsmsTracing.Global } catch { $null } } else { $null }
$RtracGlobal = if ($RsmsTracing) { try { $RsmsTracing.Global } catch { $null } } else { $null }
$inner, $dd = Build-KVTable "reg_sms_tracing_global" $LtracGlobal $RtracGlobal @()
$regCmpDiffs += $dd
[void]$regCmpSb.Append("<h3 class='sub-hdr'>SMS\Tracing (Global) $(Diff-Badge $dd 'reg_sms_tracing_global')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# SMS\Tracing — per-component (only show components where any field differs)
$LtracComps = if ($LsmsTracing) { try { $LsmsTracing.Components } catch { $null } } else { $null }
$RtracComps = if ($RsmsTracing) { try { $RsmsTracing.Components } catch { $null } } else { $null }
$allComps = @((Get-Props $LtracComps) + (Get-Props $RtracComps)) | Sort-Object -Unique
if ($allComps.Count -gt 0) {
    $tracFields  = @('MaxFileSize','Enabled','DebugLogging','LoggingLevel','LogMaxHistory')
    $tracTblSb   = [System.Text.StringBuilder]::new()
    $tracDiffs   = 0
    [void]$tracTblSb.Append("<thead><tr><th>Component</th>")
    foreach ($f in $tracFields) { [void]$tracTblSb.Append("<th>$leftCode $f</th><th>$rightCode $f</th>") }
    [void]$tracTblSb.Append("</tr></thead><tbody>")
    foreach ($comp in $allComps) {
        $lc = if ($LtracComps) { try { $LtracComps.$comp } catch { $null } } else { $null }
        $rc = if ($RtracComps) { try { $RtracComps.$comp } catch { $null } } else { $null }
        $rowDiff = $false
        $cells   = "<td class='prop'>$(He $comp)</td>"
        foreach ($f in $tracFields) {
            $lv = if ($lc) { try { "$($lc.$f)" } catch { '' } } else { '' }
            $rv = if ($rc) { try { "$($rc.$f)" } catch { '' } } else { '' }
            $fd = ($lv -ne $rv)
            if ($fd) { $rowDiff = $true }
            $lcls = if ($fd) { 'ldiff' } else { 'val' }
            $rcls = if ($fd) { 'rdiff' } else { 'val' }
            $cells += "<td class='$lcls'>$(He $lv)</td><td class='$rcls'>$(He $rv)</td>"
        }
        if ($rowDiff) { $tracDiffs++ }
        $rowCls = if ($rowDiff) { 'diff' } else { 'match' }
        [void]$tracTblSb.Append("<tr class='$rowCls'>$cells</tr>")
    }
    [void]$tracTblSb.Append("</tbody>")
    $regCmpDiffs += $tracDiffs
    [void]$regCmpSb.Append("<h3 class='sub-hdr'>SMS\Tracing (Per-Component) $(Diff-Badge $tracDiffs 'reg_sms_tracing_comps')</h3><div class='tbl-wrap'><table class='cmp'>$($tracTblSb.ToString())</table></div>")
}

# ── CCM sub-sections ──────────────────────────────────────────────────────────
$Lccm = if ($Lreg) { try { $Lreg.CCM } catch { $null } } else { $null }
$Rccm = if ($Rreg) { try { $Rreg.CCM } catch { $null } } else { $null }

foreach ($grp in @(
    @{Id="reg_ccm_base";    Title="CCM (Root)";            Key="Base"}
    @{Id="reg_ccm_eval";    Title="CCM\CcmEval";           Key="CcmEval"}
    @{Id="reg_ccm_exec";    Title="CCM\CcmExec";           Key="CcmExec"}
    @{Id="reg_ccm_log";     Title="CCM\Logging";           Key="Logging"}
    @{Id="reg_ccm_sec";     Title="CCM\Security";          Key="Security"}
    @{Id="reg_ccm_locsvc";  Title="CCM\LocationServices";  Key="LocationServices"}
    @{Id="reg_ccm_su";      Title="CCM\SoftwareUpdates";   Key="SoftwareUpdates"}
    @{Id="reg_ccm_inv";     Title="CCM\Inventory";         Key="Inventory"}
)) {
    $html, $dd = Compare-RegGroup $grp.Id $grp.Title $Lccm $Rccm $grp.Key
    $regCmpDiffs += $dd
    [void]$regCmpSb.Append($html)
}

# ── CCMSetup ──────────────────────────────────────────────────────────────────
$LccmSetup = if ($Lreg) { try { $Lreg.CCMSetup } catch { $null } } else { $null }
$RccmSetup = if ($Rreg) { try { $Rreg.CCMSetup } catch { $null } } else { $null }
$inner, $dd = Build-KVTable "reg_ccmsetup" $LccmSetup $RccmSetup @()
$regCmpDiffs += $dd
[void]$regCmpSb.Append("<h3 class='sub-hdr'>CCMSetup $(Diff-Badge $dd 'reg_ccmsetup')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# ── Windows Update Policy ─────────────────────────────────────────────────────
$Lwu = if ($Lreg) { try { $Lreg.WindowsUpdate } catch { $null } } else { $null }
$Rwu = if ($Rreg) { try { $Rreg.WindowsUpdate } catch { $null } } else { $null }

foreach ($grp in @(
    @{Id="reg_wu_policy"; Title="Windows Update Policy";    Key="Policy"}
    @{Id="reg_wu_au";     Title="Windows Update AU Settings"; Key="AU"}
)) {
    $html, $dd = Compare-RegGroup $grp.Id $grp.Title $Lwu $Rwu $grp.Key
    $regCmpDiffs += $dd
    [void]$regCmpSb.Append($html)
}

Record-Diff "registry" $regCmpDiffs
[void]$sections.Append((Wrap-Section "registry" "Registry Settings" $regCmpSb.ToString() $regCmpDiffs))

Write-Step "OS Event Logs"
# 47. OS Event Log Analysis
$oslogSb           = [System.Text.StringBuilder]::new()
$oslogDiffs        = 0
$oslogTotalFlagged = 0

$Losl = Unwrap-Section $L.OSEventLogs
$Rosl = Unwrap-Section $R.OSEventLogs

# Summary KV
$inner, $dd = Build-KVTable "osl_summary" ($Losl.Summary) ($Rosl.Summary) @()
$oslogDiffs += $dd
[void]$oslogSb.Append("<h3 class='sub-hdr'>Summary $(Diff-Badge $dd 'osl_summary')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# Per-log viewer — reuse Build-LogTable (same entry shape: DateTime/Severity/Component/Message/Flagged)
foreach ($logKey in @('SystemLog','ApplicationLog','SecurityLog')) {
    $lLogObj = if ($Losl) { try { $Losl.$logKey } catch { $null } } else { $null }
    $rLogObj = if ($Rosl) { try { $Rosl.$logKey } catch { $null } } else { $null }
    $label   = if ($lLogObj -and $lLogObj.Label) { $lLogObj.Label } elseif ($rLogObj -and $rLogObj.Label) { $rLogObj.Label } else { $logKey }
    $lEntries = if ($lLogObj -and $lLogObj.Entries) { @($lLogObj.Entries) } else { @() }
    $rEntries = if ($rLogObj -and $rLogObj.Entries) { @($rLogObj.Entries) } else { @() }
    $lErrCnt  = @($lEntries | Where-Object { $_.Flagged -eq $true }).Count
    $rErrCnt  = @($rEntries | Where-Object { $_.Flagged -eq $true }).Count
    $oslogTotalFlagged += $lErrCnt
    $errBadge = if (($lErrCnt + $rErrCnt) -gt 0) { " <span class='err-badge'>$($lErrCnt+$rErrCnt) flagged</span>" } else { "" }
    [void]$oslogSb.Append("<h3 class='sub-hdr'>$label$errBadge</h3>")
    [void]$oslogSb.Append("<div class='log-file-block'><div class='log-viewer'>")
    [void]$oslogSb.Append((Build-LogTable "osl_${logKey}_L" $lEntries $leftCode))
    if (-not $singleMode) {
        [void]$oslogSb.Append((Build-LogTable "osl_${logKey}_R" $rEntries $rightCode))
    }
    [void]$oslogSb.Append("</div></div>")
}

$oslogSingleBadge = if ($singleMode -and $oslogTotalFlagged -gt 0) { "<span class='badge bdiff'>$oslogTotalFlagged flagged</span>" } else { "" }
Record-Diff "oslogs" $oslogDiffs
[void]$sections.Append((Wrap-Section-Raw "oslogs" "OS Event Logs" $oslogSb.ToString() $oslogDiffs $oslogSingleBadge))

Write-Step "Firewall Configuration"
# 48. Firewall Configuration
$fwCmpSb    = [System.Text.StringBuilder]::new()
$fwCmpDiffs = 0
$Lfw = Unwrap-Section $L.FirewallConfig
$Rfw = Unwrap-Section $R.FirewallConfig

# ── Issues (highlighted at top) ───────────────────────────────────────────────
$lFwIssues = if ($Lfw -and $Lfw.Issues) { @($Lfw.Issues) } else { @() }
$rFwIssues = if ($Rfw -and $Rfw.Issues) { @($Rfw.Issues) } else { @() }
if ($lFwIssues.Count -gt 0 -or $rFwIssues.Count -gt 0) {
    $issSb = [System.Text.StringBuilder]::new()
    [void]$issSb.Append("<table class='cmp'><thead><tr><th>Site</th><th>Severity</th><th>Area</th><th>Description</th></tr></thead><tbody>")
    foreach ($iss in $lFwIssues) {
        $sc = switch ($iss.Severity) { 'Critical'{'fail-cell'} 'Warning'{'warn-cell'} default{''} }
        [void]$issSb.Append("<tr class='diff'><td class='prop ldiff'>$leftCode</td><td class='$sc'>$(He $iss.Severity)</td><td class='val'>$(He $iss.Area)</td><td class='val'>$(He $iss.Description)</td></tr>")
    }
    foreach ($iss in $rFwIssues) {
        $sc = switch ($iss.Severity) { 'Critical'{'fail-cell'} 'Warning'{'warn-cell'} default{''} }
        [void]$issSb.Append("<tr class='diff'><td class='prop rdiff'>$rightCode</td><td class='$sc'>$(He $iss.Severity)</td><td class='val'>$(He $iss.Area)</td><td class='val'>$(He $iss.Description)</td></tr>")
    }
    [void]$issSb.Append("</tbody></table>")
    $issDiffs = $lFwIssues.Count + $rFwIssues.Count
    $fwCmpDiffs += $issDiffs
    [void]$fwCmpSb.Append("<h3 class='sub-hdr'>Issues $(Diff-Badge $issDiffs 'fw_issues')</h3><div class='tbl-wrap'>$($issSb.ToString())</div>")
}

# ── Per-profile comparison ─────────────────────────────────────────────────────
$lFwProfs = if ($Lfw -and $Lfw.Profiles) { @($Lfw.Profiles) } else { @() }
$rFwProfs = if ($Rfw -and $Rfw.Profiles) { @($Rfw.Profiles) } else { @() }
foreach ($profName in @('Domain','Private','Public')) {
    $lPr = $lFwProfs | Where-Object { $_.Name -eq $profName } | Select-Object -First 1
    $rPr = $rFwProfs | Where-Object { $_.Name -eq $profName } | Select-Object -First 1
    $inner, $dd = Build-KVTable "fw_prof_$profName" $lPr $rPr @()
    $fwCmpDiffs += $dd
    [void]$fwCmpSb.Append("<h3 class='sub-hdr'>Profile: $profName $(Diff-Badge $dd "fw_prof_$profName")</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")
}

# ── Key port status comparison ─────────────────────────────────────────────────
$lPorts = if ($Lfw -and $Lfw.PortStatus) { @($Lfw.PortStatus) } else { @() }
$rPorts = if ($Rfw -and $Rfw.PortStatus) { @($Rfw.PortStatus) } else { @() }
$allFwPorts = (@($lPorts | ForEach-Object { $_.Port }) + @($rPorts | ForEach-Object { $_.Port })) | Select-Object -Unique | Sort-Object { [int]$_ }
$portTblSb = [System.Text.StringBuilder]::new()
if ($singleMode) {
    [void]$portTblSb.Append("<thead><tr><th>Port</th><th>Proto</th><th>MECM Role</th><th>Status</th></tr></thead><tbody>")
} else {
    [void]$portTblSb.Append("<thead><tr><th>Port</th><th>Proto</th><th>MECM Role</th><th>$leftCode</th><th>$rightCode</th><th>Match</th></tr></thead><tbody>")
}
$portDiffs = 0
foreach ($p in $allFwPorts) {
    $lps     = $lPorts | Where-Object { $_.Port -eq $p } | Select-Object -First 1
    $rps     = $rPorts | Where-Object { $_.Port -eq $p } | Select-Object -First 1
    $lSt     = if ($lps) { $lps.Status   } else { '' }
    $rSt     = if ($rps) { $rps.Status   } else { '' }
    $role    = if ($lps) { $lps.Role     } elseif ($rps) { $rps.Role     } else { '' }
    $prot    = if ($lps) { $lps.Protocol } elseif ($rps) { $rps.Protocol } else { '' }
    $lsClass = if ($lSt -eq 'Blocked') { 'fail-cell' } elseif ($lSt -like 'No-Rule*Block*') { 'warn-cell' } elseif ($lSt -eq 'Allowed') { 'pass-cell' } else { '' }
    if ($singleMode) {
        [void]$portTblSb.Append("<tr><td class='prop'>$(He $p)</td><td class='val'>$(He $prot)</td><td class='val'>$(He $role)</td><td class='val $lsClass'>$(He $lSt)</td></tr>")
    } else {
        $diff    = ($lSt -ne $rSt)
        if ($diff) { $portDiffs++ }
        $cls     = if ($diff) { 'diff'  } else { 'match' }
        $lc      = if ($diff) { 'ldiff' } else { 'val'   }
        $rc      = if ($diff) { 'rdiff' } else { 'val'   }
        $st      = if ($diff) { "<span class='status-diff'>&#9888; Different</span>" } else { "<span class='status-ok'>&#10003; Match</span>" }
        $rsClass = if ($rSt -eq 'Blocked') { 'fail-cell' } elseif ($rSt -like 'No-Rule*Block*') { 'warn-cell' } elseif ($rSt -eq 'Allowed') { 'pass-cell' } else { '' }
        [void]$portTblSb.Append("<tr class='$cls'><td class='prop'>$(He $p)</td><td class='val'>$(He $prot)</td><td class='val'>$(He $role)</td><td class='$lc $lsClass'>$(He $lSt)</td><td class='$rc $rsClass'>$(He $rSt)</td><td>$st</td></tr>")
    }
}
[void]$portTblSb.Append("</tbody>")
$fwCmpDiffs += $portDiffs
[void]$fwCmpSb.Append("<h3 class='sub-hdr'>Key Port Status $(Diff-Badge $portDiffs 'fw_ports')</h3><div class='tbl-wrap'><table class='cmp'>$($portTblSb.ToString())</table></div>")

# ── MECM/WSUS related rules comparison ────────────────────────────────────────
$lFwRules = if ($Lfw -and $Lfw.Rules) { @($Lfw.Rules) } else { @() }
$rFwRules = if ($Rfw -and $Rfw.Rules) { @($Rfw.Rules) } else { @() }
$inner, $dd = Build-ArrayTable "fw_rules" $lFwRules $rFwRules "Name" @("Name","Direction","Action","Enabled","Profile","Protocol","LocalPort")
$fwCmpDiffs += $dd
[void]$fwCmpSb.Append("<h3 class='sub-hdr'>MECM / WSUS Related Rules $(Diff-Badge $dd 'fw_rules')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

$fwSingleBadge = if ($singleMode) {
    $fwIssCrit = @($lFwIssues | Where-Object { $_.Severity -eq 'Critical'       }).Count
    $fwIssWarn = @($lFwIssues | Where-Object { $_.Severity -eq 'Warning'        }).Count
    $fwBlocked = @($lPorts    | Where-Object { $_.Status -eq 'Blocked'          }).Count
    $fwNoRule  = @($lPorts    | Where-Object { $_.Status -like 'No-Rule*Block*' }).Count
    $fwAllowed = @($lPorts    | Where-Object { $_.Status -eq 'Allowed'          }).Count
    $fwCrit    = $fwIssCrit + $fwBlocked
    $fwWarn    = $fwIssWarn + $fwNoRule
    Single-Badge $fwCrit $fwWarn 0 $(if ($fwCrit -eq 0 -and $fwWarn -eq 0) { $fwAllowed } else { 0 })
} else { "" }
Record-Diff "fwconfig" $fwCmpDiffs
[void]$sections.Append((Wrap-Section-Raw "fwconfig" "Firewall Configuration" $fwCmpSb.ToString() $fwCmpDiffs $fwSingleBadge))

# 49. Script Execution Log
Write-Step "Script Execution Log"
$execLogSb    = [System.Text.StringBuilder]::new()
$execLogDiffs = 0

$LexecLog = if ($L.ScriptExecutionLog) { $L.ScriptExecutionLog } else { $null }
$RexecLog = if ($R.ScriptExecutionLog) { $R.ScriptExecutionLog } else { $null }

# ── Summary row ───────────────────────────────────────────────────────────────
$lExecSum = if ($LexecLog -and $LexecLog.Summary) { $LexecLog.Summary } else { $null }
$rExecSum = if ($RexecLog -and $RexecLog.Summary) { $RexecLog.Summary } else { $null }
$inner, $dd = Build-KVTable "execlog_summary" $lExecSum $rExecSum @()
$execLogDiffs += $dd
[void]$execLogSb.Append("<h3 class='sub-hdr'>Collection Summary $(Diff-Badge $dd 'execlog_summary')</h3><div class='tbl-wrap'><table class='cmp'>$inner</table></div>")

# ── Per-environment log viewers ────────────────────────────────────────────────
$lEntries = if ($LexecLog -and $LexecLog.Entries) { @($LexecLog.Entries) } else { @() }
$rEntries = if ($RexecLog -and $RexecLog.Entries) { @($RexecLog.Entries) } else { @() }
$lErrCnt  = @($lEntries | Where-Object { $_.Severity -eq 'Error'   }).Count
$lWarnCnt = @($lEntries | Where-Object { $_.Severity -eq 'Warning' }).Count
$rErrCnt  = @($rEntries | Where-Object { $_.Severity -eq 'Error'   }).Count
if (($lErrCnt + $rErrCnt) -gt 0) {
    $execLogDiffs += ($lErrCnt + $rErrCnt)
}
[void]$execLogSb.Append("<h3 class='sub-hdr'>Execution Timeline</h3>")
[void]$execLogSb.Append("<div class='log-file-block'><div class='log-viewer'>")
if ($lEntries.Count -eq 0 -and -not $LexecLog) {
    [void]$execLogSb.Append("<div class='log-panel'><p class='log-empty'>No execution log in $leftCode JSON &mdash; regenerate with updated Get-MECMConfig.ps1</p></div>")
} else {
    [void]$execLogSb.Append((Build-LogTable "execlog_L" $lEntries $leftCode))
}
if (-not $singleMode) {
    if ($rEntries.Count -eq 0 -and -not $RexecLog) {
        [void]$execLogSb.Append("<div class='log-panel'><p class='log-empty'>No execution log in $rightCode JSON &mdash; regenerate with updated Get-MECMConfig.ps1</p></div>")
    } else {
        [void]$execLogSb.Append((Build-LogTable "execlog_R" $rEntries $rightCode))
    }
}
[void]$execLogSb.Append("</div></div>")

# ── Report generation warnings (non-terminating PS errors during Compare) ─────
$cmpErrCount = $global:Error.Count - $script:CmpErrStart
if ($cmpErrCount -gt 0) {
    $cmpErrSb = [System.Text.StringBuilder]::new()
    [void]$cmpErrSb.Append("<div class='log-panel' id='lp_cmpgen'>")
    [void]$cmpErrSb.Append("<div class='log-panel-hdr'>Compare Script &nbsp;<span class='log-count'>$cmpErrCount non-fatal error$(if($cmpErrCount -ne 1){'s'}) suppressed during report generation</span> &nbsp;")
    [void]$cmpErrSb.Append("<button class='btn-diffs' onclick=""filterLogPanel('lp_cmpgen',this)"" data-state='all'>Errors &amp; Warnings only</button></div>")
    [void]$cmpErrSb.Append("<div class='log-scroll'><table class='cmp log-tbl'><thead><tr>")
    [void]$cmpErrSb.Append("<th class='col-flag'></th><th class='col-dt'>Source</th><th class='col-sev'>Sev</th><th class='col-comp'>Location</th><th class='col-msg'>Error</th>")
    [void]$cmpErrSb.Append("</tr></thead><tbody>")
    for ($i = $cmpErrCount - 1; $i -ge 0; $i--) {
        $ce    = $global:Error[$i]
        $ceMsg = if ($ce -and $ce.Exception) { $ce.Exception.Message } else { "$ce" }
        $ceLoc = if ($ce -and $ce.InvocationInfo -and $ce.InvocationInfo.ScriptLineNumber) {
                     "Line $($ce.InvocationInfo.ScriptLineNumber)"
                 } else { "Compare script" }
        [void]$cmpErrSb.Append("<tr class='sev-warn-row flagged'>")
        [void]$cmpErrSb.Append("<td class='col-flag flag-ind' title='Flagged'>&#9873;</td>")
        [void]$cmpErrSb.Append("<td class='col-dt'>$(He 'Compare-MECMConfig')</td>")
        [void]$cmpErrSb.Append("<td class='col-sev'>Warning</td>")
        [void]$cmpErrSb.Append("<td class='col-comp'>$(He $ceLoc)</td>")
        [void]$cmpErrSb.Append("<td class='col-msg'>$(He $ceMsg)</td>")
        [void]$cmpErrSb.Append("</tr>")
    }
    [void]$cmpErrSb.Append("</tbody></table></div></div>")
    [void]$execLogSb.Append("<h3 class='sub-hdr'>Report Generation Warnings <span class='err-badge'>$cmpErrCount</span></h3>")
    [void]$execLogSb.Append("<div class='log-file-block'>$($cmpErrSb.ToString())</div>")
    $execLogDiffs += $cmpErrCount
}

$execSingleBadge = if ($singleMode) { Single-Badge $lErrCnt $lWarnCnt } else { "" }
Record-Diff "scriptexeclog" $execLogDiffs
[void]$sections.Append((Wrap-Section-Raw "scriptexeclog" "Script Execution Log" $execLogSb.ToString() $execLogDiffs $execSingleBadge))

# ── Navigation ────────────────────────────────────────────────────────────────

Write-Step "Building HTML report"
$navItems = [System.Text.StringBuilder]::new()
$navDefs  = @(
    @{Id="summary";       Label="Summary"}
    @{Id="insights";      Label="Insights"}
    @{Id="siteinfo";      Label="Site Info"}
    @{Id="siteroles";     Label="Site Roles"}
    @{Id="bounds";        Label="Boundaries"}
    @{Id="boundgroups";   Label="Boundary Groups"}
    @{Id="clientsettings";Label="Client Settings"}
    @{Id="discovery";     Label="Discovery"}
    @{Id="supdate";       Label="Software Updates"}
    @{Id="dps";           Label="Distribution Points"}
    @{Id="dpgroups";      Label="DP Groups"}
    @{Id="collections";   Label="Collections"}
    @{Id="apps";          Label="Applications"}
    @{Id="packages";      Label="Packages / TS"}
    @{Id="osd";           Label="OSD"}
    @{Id="ep";            Label="Endpoint Protection"}
    @{Id="mw";            Label="Maint. Windows"}
    @{Id="metering";      Label="SW Metering"}
    @{Id="cloud";         Label="Cloud Services"}
    @{Id="hier";          Label="Hierarchy Settings"}
    @{Id="comp";          Label="Components"}
    @{Id="db";            Label="Database"}
    @{Id="logs";          Label="Log Analysis"}
    @{Id="rbac";          Label="RBAC"}
    @{Id="adrs";          Label="Auto Deploy Rules"}
    @{Id="deployments";   Label="Deployments"}
    @{Id="clientcomm";    Label="Client Comms"}
    @{Id="hwinv";         Label="HW Inventory"}
    @{Id="baselines";     Label="Baselines"}
    @{Id="alerts";        Label="Alerts"}
    @{Id="scripts";       Label="Run Scripts"}
    @{Id="wsp";           Label="Servicing Plans"}
    @{Id="tpcatalogs";    Label="3rd Party Catalogs"}
    @{Id="comanagement";  Label="Co-Management"}
    @{Id="contentdist";   Label="Content Distribution"}
    @{Id="hostsystem";    Label="Host System"}
    @{Id="maintasks";     Label="Maint. Tasks"}
    @{Id="sugroups";      Label="SW Update Groups"}
    @{Id="statusfilter";  Label="Status Filters"}
    @{Id="certs";         Label="Certificates"}
    @{Id="iisconfig";    Label="IIS Config"}
    @{Id="wsusconfig";   Label="WSUS Config"}
    @{Id="contentstore"; Label="Content Store"}
    @{Id="grouppolicy";  Label="Group Policy"}
    @{Id="healthchecks";    Label="Health Checks"}
    @{Id="serviceaccounts";   Label="Service Accounts"}
    @{Id="roleserverprobes";  Label="Role Server Probes"}
    @{Id="registry";          Label="Registry Settings"}
    @{Id="oslogs";            Label="OS Event Logs"}
    @{Id="fwconfig";          Label="Firewall"}
    @{Id="scriptexeclog";     Label="Script Exec Log"}
)

foreach ($n in $navDefs) {
    $cnt  = if ($script:SectionDiffs.Contains($n.Id)) { $script:SectionDiffs[$n.Id] } else { 0 }
    $cls  = if ($cnt -gt 0) { ' has-diffs' } else { '' }
    $pill = if ($cnt -gt 0) { " <span class='anc-pill'>$cnt</span>" } else { "" }
    [void]$navItems.Append("<span class='anc$cls' onclick='jump(""sec_$($n.Id)"")'>$($n.Label)$pill</span>")
}

# ── Assemble HTML ─────────────────────────────────────────────────────────────

$genDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$totalStr = "$($script:TotalDiffs) difference$(if($script:TotalDiffs -ne 1){'s'}) found"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(if($singleMode){"MECM Config: $leftCode"}else{"MECM Config Compare: $leftCode vs $rightCode"})</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;background:#f0f2f5;color:#222;margin:0}
a{color:inherit;text-decoration:none}

/* ─── Top bar ─── */
.topbar{position:sticky;top:0;z-index:100;background:#1a2535;color:#eee;padding:10px 18px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;box-shadow:0 2px 6px #0005}
.topbar h1{font-size:15px;font-weight:600;white-space:nowrap}
.site-pills{display:flex;gap:8px;flex-wrap:wrap}
.pill-l,.pill-r{font-size:11px;padding:3px 10px;border-radius:12px;white-space:nowrap}
.pill-l{background:#2980b9;color:#fff}
.pill-r{background:#27ae60;color:#fff}
.total-diffs{margin-left:auto;font-size:12px;background:#c0392b;color:#fff;padding:3px 12px;border-radius:12px;white-space:nowrap}
.total-diffs.none{background:#27ae60}

/* ─── Anchor bar ─── */
.anchor-bar{position:sticky;top:45px;z-index:90;background:#fff;border-bottom:2px solid #dde;display:flex;align-items:stretch;overflow-x:auto;white-space:nowrap;scrollbar-width:thin;box-shadow:0 2px 4px #0001}
.anchor-bar::-webkit-scrollbar{height:4px}
.anchor-bar::-webkit-scrollbar-thumb{background:#ccc;border-radius:2px}
.anc{display:inline-flex;align-items:center;gap:5px;padding:7px 13px;font-size:11px;cursor:pointer;border-right:1px solid #f0f0f0;transition:background .12s;flex-shrink:0;color:#222}
.anc:hover{background:#f0f4ff}
.anc.has-diffs{color:#c0392b;font-weight:600}
.anc-pill{background:#c0392b;color:#fff;font-size:10px;padding:1px 5px;border-radius:8px}

/* ─── Main content ─── */
.content{padding:18px}

/* ─── Sections ─── */
section{background:#fff;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 4px #0001;overflow:hidden}
.sec-hdr{padding:12px 16px;background:#2c3e50;color:#eee;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:14px;user-select:none}
.sec-hdr.has-diffs{background:#922b21}
.sec-hdr:hover{filter:brightness(1.1)}
.tog{font-size:11px;transition:transform .2s}
.tog.collapsed{transform:rotate(-90deg)}
.sec-body{padding:12px}
.sub-hdr{font-size:12px;font-weight:600;margin:14px 0 6px;color:#444;padding-bottom:4px;border-bottom:1px solid #eee}

/* ─── Badges ─── */
.badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:600;margin-left:4px}
.bdiff{background:#e74c3c;color:#fff}
.bok{background:#27ae60;color:#fff}
.bwarn{background:#e67e22;color:#fff}
.binfo{background:#2980b9;color:#fff}

/* ─── Status icons ─── */
.status-diff{color:#c0392b;font-weight:600}
.status-ok{color:#27ae60}

/* ─── Controls ─── */
.tbl-ctrl{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.btn-diffs{font-size:11px;padding:4px 12px;border:1px solid #bbb;border-radius:4px;background:#f5f5f5;cursor:pointer}
.btn-diffs:hover{background:#e8e8e8}
.row-counts{font-size:11px;color:#888}

/* ─── Table ─── */
.tbl-wrap{overflow-x:auto}
table.cmp{border-collapse:collapse;width:100%;font-size:12px}
table.cmp th{background:#34495e;color:#eee;padding:7px 10px;text-align:left;font-weight:600;white-space:nowrap;position:sticky;top:0}
table.cmp td{padding:5px 10px;border-bottom:1px solid #f0f0f0;vertical-align:top;word-break:break-word;max-width:380px}
table.cmp tr:last-child td{border-bottom:none}
td.prop{background:#f7f8fa;font-weight:600;white-space:nowrap;color:#333;max-width:220px}
td.col-key,td.key-cell{background:#f7f8fa;font-weight:600;max-width:240px;white-space:nowrap}
td.val{background:#fff}
td.ldiff{background:#fde8e8}
td.rdiff{background:#fde8e8}
td.missing{background:#f5f5f5;color:#aaa;font-style:italic}
tr.only-left  td.ldiff{background:#fdf3cd}
tr.only-right td.rdiff{background:#dbeeff}
tr.only-left  td.key-cell{background:#fdf3cd}
tr.only-right td.key-cell{background:#dbeeff}
tr.match{background:#fff}
tr.diff{background:#fff8f8}
table.cmp tr:hover td{filter:brightness(0.97)}
td.pass-cell{background:#eafaf1;color:#1e8449;font-weight:600}
td.warn-cell{background:#fef9e7;color:#9a7d0a;font-weight:600}
td.fail-cell{background:#fdedec;color:#c0392b;font-weight:600}
th.col-prop{width:220px}
th.col-val{min-width:160px}
th.col-l,th.col-r{min-width:130px}
th.col-key{min-width:160px}

/* ─── Log entry tables ─── */
.log-file-block{margin-bottom:12px}
.log-tbl td.col-dt{white-space:nowrap;font-size:11px;width:140px}
.log-tbl td.col-sev{width:70px;text-align:center;font-weight:700;font-size:11px}
.log-tbl td.col-comp{width:200px;font-size:11px;white-space:nowrap}
.log-tbl td.col-msg{font-size:11px;word-break:break-word}
tr.sev-err   td{background:#fff0f0}
tr.sev-warn  td{background:#fffbe6}
tr.sev-info  td{background:#fff}
td.sev-err-cell{color:#c0392b}
td.sev-warn-cell{color:#d68910}
td.sev-info-cell{color:#555}
p.side-label{font-weight:600;font-size:12px;margin:8px 0 4px;color:#333}
h4.entry-hdr{font-size:12px;font-weight:600;margin:10px 0 4px;color:#555;border-bottom:1px solid #eee;padding-bottom:3px}

/* ─── Legend ─── */
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:11px;padding:8px 12px;background:#fafafa;border:1px solid #eee;border-radius:4px;margin-bottom:14px}
.leg-item{display:flex;align-items:center;gap:5px}
.leg-box{width:14px;height:14px;border-radius:2px;flex-shrink:0}
.topbar-btns{display:flex;gap:6px;margin-left:8px}
.btn-top{font-size:11px;padding:4px 10px;border:none;border-radius:4px;background:#34495e;color:#eee;cursor:pointer}
.btn-top:hover{background:#4a6278}

/* ─── Insights section ─── */
.insight-row{display:flex;gap:12px;align-items:flex-start}
.insight-panel{flex:1;min-width:0;border:1px solid #ddd;border-radius:5px;overflow:hidden}
.insight-hdr{background:#2c3e50;color:#fff;padding:8px 12px;font-size:13px;display:flex;align-items:center;flex-wrap:wrap;gap:6px}
.ins-badge{border-radius:10px;padding:2px 9px;font-size:11px;font-weight:600}
.ins-ok{background:#27ae60;color:#fff}
.ins-crit{background:#e74c3c;color:#fff}
.ins-warn{background:#e67e22;color:#fff}
.ins-info{background:#2980b9;color:#fff}
.ins-tbl{width:100%}
.ins-col-cat{width:130px}
.ins-col-msg{word-break:break-word;font-size:12px}
tr.ins-crit-row td{background:#fff5f5}
tr.ins-warn-row td{background:#fff8f0}
tr.ins-info-row td{background:#f0f7ff}
.ins-cat-pill{border-radius:3px;padding:1px 7px;font-size:11px;font-weight:600;white-space:nowrap}
.ins-cat-pill.ins-critical{background:#fde8e8;color:#c0392b;border:1px solid #f5c6c6}
.ins-cat-pill.ins-warning{background:#fef3e2;color:#d35400;border:1px solid #f5deb3}
.ins-cat-pill.ins-info{background:#e8f4ff;color:#2471a3;border:1px solid #b3d7f5}
.ins-empty{padding:18px;text-align:center;color:#27ae60;font-size:13px;font-weight:600}

/* ─── Log viewer (side-by-side panels) ─── */
.log-viewer{display:flex;gap:10px;align-items:flex-start}
.log-panel{flex:1;min-width:0;border:1px solid #ddd;border-radius:4px;overflow:hidden}
.log-panel-hdr{background:#34495e;color:#fff;padding:6px 10px;display:flex;align-items:center;flex-wrap:wrap;gap:6px;font-size:12px;font-weight:600}
.log-count{background:rgba(255,255,255,0.2);border-radius:10px;padding:1px 8px;font-size:11px;font-weight:400}
.btn-diffs{font-size:11px;padding:2px 8px;border:1px solid rgba(255,255,255,0.4);border-radius:3px;background:transparent;color:#eee;cursor:pointer}
.btn-diffs:hover{background:rgba(255,255,255,0.15)}
.log-scroll{max-height:500px;overflow-y:auto}
tr.sev-err-row td{background:#fff0f0}
tr.sev-warn-row td{background:#fffbe6}
tr.sev-info-row td{background:#fff}
tr.sev-err-row.flagged td{background:#ffd6d6}
tr.sev-warn-row.flagged td{background:#fff0b3}
tr.sev-info-row.flagged td{background:#e8f4f8}
tr.flagged td.col-flag{color:#c0392b;font-size:13px;text-align:center}
tr.flagged{border-left:3px solid #e74c3c}
.log-tbl td.col-flag{width:18px;padding:2px 2px;text-align:center;font-size:12px}
.log-tbl th.col-flag{width:18px;padding:2px}
.log-empty{padding:20px;text-align:center;color:#888;font-style:italic;font-size:13px}
.err-badge{background:#e74c3c;color:#fff;border-radius:10px;padding:1px 7px;font-size:11px}
.flag-badge{background:#e67e22;color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;margin-left:4px}
</style>
</head>
<body>

<div class="topbar">
  <h1>$(if($singleMode){"MECM Config: $leftCode"}else{"MECM Config Comparison"})</h1>
  <div class="site-pills">
    <span class="pill-l">&#9654; $leftLabel</span>
    $(if(-not $singleMode){"<span class='pill-r'>&#9654; $rightLabel</span>"})
  </div>
  <span class="total-diffs $(if($script:TotalDiffs -eq 0){'none'})">$(if($singleMode){"Configuration Viewer"}else{$totalStr})</span>
  <div class="topbar-btns">
    <button class="btn-top" onclick="toggleAll(true)">Expand All</button>
    <button class="btn-top" onclick="toggleAll(false)">Collapse All</button>
    <button class="btn-top" onclick="exportCSV()">Export CSV</button>
  </div>
</div>

<div class="anchor-bar">$($navItems.ToString())</div>
<main class="content">

    $(if(-not $singleMode){@"
    <div class="legend">
      <div class="leg-item"><div class="leg-box" style="background:#fde8e8"></div>Values differ</div>
      <div class="leg-item"><div class="leg-box" style="background:#fdf3cd"></div>Only in $leftCode</div>
      <div class="leg-item"><div class="leg-box" style="background:#dbeeff"></div>Only in $rightCode</div>
      <div class="leg-item"><div class="leg-box" style="background:#fff;border:1px solid #ddd"></div>Match</div>
    </div>
"@})

    $($sections.ToString())

    <p style="text-align:center;color:#aaa;font-size:11px;margin-top:8px">$(if($singleMode){"Generated $genDate &bull; $($L.Metadata.GeneratedOn)"}else{"Generated $genDate &bull; $($L.Metadata.GeneratedOn) vs $($R.Metadata.GeneratedOn)"})</p>
</main>

<script>
function jump(id){
  var baseId=id.replace(/^sec_/,'');
  var b=document.getElementById('body_'+baseId),t=document.getElementById('tog_'+baseId);
  if(b&&b.style.display==='none'){b.style.display='';if(t)t.classList.remove('collapsed');}
  requestAnimationFrame(function(){
    var el=document.getElementById(id);
    if(!el)return;
    var topbarH=(document.querySelector('.topbar')||{offsetHeight:45}).offsetHeight;
    var anchorH=(document.querySelector('.anchor-bar')||{offsetHeight:34}).offsetHeight;
    window.scrollTo({top:el.getBoundingClientRect().top+window.scrollY-(topbarH+anchorH+6),behavior:'smooth'});
  });
}
function toggleSec(id){
  var b=document.getElementById('body_'+id),t=document.getElementById('tog_'+id);
  if(!b)return;
  if(b.style.display==='none'){b.style.display='';t.classList.remove('collapsed')}
  else{b.style.display='none';t.classList.add('collapsed')}
}

function toggleDiff(btn,id){
  var tbl=document.getElementById('tbl_'+id);
  if(!tbl){
    // sub-section tables don't have IDs, find all in the section body
    tbl=document.getElementById('body_'+id);
  }
  var showDiffOnly=btn.dataset.state==='all';
  var rows=tbl?tbl.querySelectorAll('tr.match'):[];
  rows.forEach(function(r){r.style.display=showDiffOnly?'none':'';});
  btn.textContent=showDiffOnly?'Show all rows':'Show differences only';
  btn.dataset.state=showDiffOnly?'diffs':'all';
  updateCounts(id,tbl,showDiffOnly);
}

function updateCounts(id,tbl,diffOnly){
  var rc=document.getElementById('rc_'+id);
  if(!rc||!tbl)return;
  var all=tbl.querySelectorAll('tbody tr').length;
  var diffs=tbl.querySelectorAll('tbody tr.diff').length;
  rc.textContent=diffOnly?(diffs+' diff row(s) shown'):(all+' rows total, '+diffs+' different');
}

// Init row counts on load
document.querySelectorAll('[id^="tbl_"]').forEach(function(tbl){
  var id=tbl.id.replace('tbl_','');
  var rc=document.getElementById('rc_'+id);
  if(!rc)return;
  var all=tbl.querySelectorAll('tbody tr').length;
  var diffs=tbl.querySelectorAll('tbody tr.diff').length;
  rc.textContent=all+' rows total, '+diffs+' different';
});

// Collapse all sections on load
toggleAll(false);

function toggleAll(expand){
  document.querySelectorAll('section').forEach(function(sec){
    var id=sec.id.replace('sec_','');
    var b=document.getElementById('body_'+id);
    var t=document.getElementById('tog_'+id);
    if(!b)return;
    if(expand){b.style.display='';if(t)t.classList.remove('collapsed');}
    else{b.style.display='none';if(t)t.classList.add('collapsed');}
  });
}

function filterLogPanel(panelId,btn){
  var panel=document.getElementById(panelId);
  if(!panel)return;
  var state=btn.dataset.state;
  if(state==='all'){
    // Filter to errors & warnings only
    panel.querySelectorAll('tr.sev-info-row').forEach(function(r){r.style.display='none';});
    panel.querySelectorAll('tr.sev-err-row,tr.sev-warn-row').forEach(function(r){r.style.display='';});
    btn.textContent='Flagged only';
    btn.dataset.state='erronly';
  } else if(state==='erronly'){
    // Filter to flagged only
    panel.querySelectorAll('tr.sev-info-row,tr.sev-err-row,tr.sev-warn-row').forEach(function(r){r.style.display='none';});
    panel.querySelectorAll('tr.flagged').forEach(function(r){r.style.display='';});
    btn.textContent='Show all entries';
    btn.dataset.state='flaggedonly';
  } else {
    // Show all
    panel.querySelectorAll('tr').forEach(function(r){r.style.display='';});
    btn.textContent='Errors & Warnings only';
    btn.dataset.state='all';
  }
}

function exportCSV(){
  var rows=[['Section','Property / Key','Left','Right']];

  function secLabel(tr){
    var sec=tr.closest('section');
    var hdr=sec?sec.querySelector('.sec-hdr'):null;
    var raw=hdr?hdr.textContent:'';
    return raw.replace(/[▼▶▾▸]/g,'')
              .replace(/\s+\d+\s+diffs?\b/i,'')
              .replace(/\s+Match\b/i,'')
              .trim();
  }

  // All comparison rows — match, diff, only-left, only-right
  // Skip actual log entry rows (they carry sev-*-row classes, not these)
  document.querySelectorAll('tr.diff,tr.match,tr.only-left,tr.only-right').forEach(function(tr){
    if(tr.querySelector('td.col-dt,td.col-sev')) return; // log entry row — skip
    var cells=tr.querySelectorAll('td');
    if(cells.length<2) return;
    var key=cells[0].textContent.trim();
    if(!key) return;
    var lVal=cells.length>=3?cells[1].textContent.trim():'';
    var rVal=cells.length>=3?cells[cells.length-1].textContent.trim():'';
    rows.push([secLabel(tr),key,lVal,rVal]);
  });

  // Insights panels — different structure (Category | Detail, no left/right)
  document.querySelectorAll('.insight-panel').forEach(function(panel){
    var envEl=panel.querySelector('.insight-hdr strong');
    var env=envEl?envEl.textContent.trim():'';
    panel.querySelectorAll('tr.ins-crit-row,tr.ins-warn-row,tr.ins-info-row').forEach(function(tr){
      var cells=tr.querySelectorAll('td');
      if(cells.length<2) return;
      var sev=tr.className.indexOf('crit')>-1?'Critical':tr.className.indexOf('warn')>-1?'Warning':'Info';
      var cat=cells[0].textContent.trim();
      var msg=cells[1].textContent.trim();
      rows.push(['Insights ('+env+')',sev+': '+cat,msg,'']);
    });
  });

  var csv=rows.map(function(r){
    return r.map(function(c){return '"'+c.replace(/"/g,'""')+'"';}).join(',');
  }).join('\r\n');
  var a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='MECM_Compare.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
</script>
</body>
</html>
"@

# ── Write output ──────────────────────────────────────────────────────────────

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile   = if ($singleMode) {
    Join-Path $OutputPath "MECM_Config_${leftCode}_View_${timestamp}.html"
} else {
    Join-Path $OutputPath "MECM_Compare_${leftCode}_vs_${rightCode}_${timestamp}.html"
}
Write-Step "Writing HTML file"
$html | Out-File -FilePath $outFile -Encoding utf8

Write-Host ""
Write-Host "HTML report written to:" -ForegroundColor Green
Write-Host "  $outFile" -ForegroundColor White
Write-Host ""
if ($singleMode) {
    Write-Host "Mode: Single-site configuration viewer ($leftCode)" -ForegroundColor Cyan
} else {
    Write-Host "Total differences: $($script:TotalDiffs)" -ForegroundColor $(if($script:TotalDiffs -gt 0){"Yellow"}else{"Green"})
}
Write-Host ""

# Open in default browser
Start-Process $outFile
