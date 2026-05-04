[MECM-Config-Scripts-Guide.txt](https://github.com/user-attachments/files/27376202/MECM-Config-Scripts-Guide.txt)
================================================================================
  MECM ENVIRONMENT CONFIGURATION SCRIPTS — USER GUIDE
  Scripts: Get-MECMConfig.ps1  |  Compare-MECMConfig.ps1
================================================================================

OVERVIEW
--------
These two scripts provide a read-only baselining and comparison toolset for
Microsoft Endpoint Configuration Manager (MECM / SCCM) environments.

  Get-MECMConfig.ps1
      Connects to an MECM site, collects configuration across 46 sections,
      and saves a single JSON snapshot file. Run this on each environment
      you want to baseline or compare.

  Compare-MECMConfig.ps1
      Takes two JSON snapshots (produced by Get-MECMConfig.ps1) and generates
      a self-contained HTML report showing every difference side by side,
      along with an Insights section that lists all actions needed per
      environment.

No changes are ever made to any system. Both scripts are read-only.


================================================================================
  REQUIREMENTS
================================================================================

MANDATORY
  - PowerShell 5.1 or later (enforced — script will not start on older versions)
  - Must run on the MECM Primary Site Server, or on a machine that holds the
    SMS Provider role for the site
  - The account running the script must be an MECM Full Administrator, or have
    read access to the SMS WMI namespace (root\SMS\site_<SiteCode>)
  - Network access to the SMS Provider machine if using -SMSProvider remotely

BUILT INTO WINDOWS SERVER — no download or install needed
  - ServerManager PowerShell module    (used for Get-WindowsFeature)
  - WebAdministration PowerShell module (used for IIS queries — present when
    the IIS / Web-Server Windows feature is installed)
  - IISAdministration PowerShell module (present on Windows Server 2016+ with
    IIS — falls back to WebAdministration automatically if not available)
  - gpresult.exe                        (used for Group Policy section)
  - System.Data.SqlClient (.NET 4.x)    (used for SQL database queries)
  - Cert:\ PSDrive / ADSI WinNT provider (used for certs and local groups)
  - WMI / DCOM                          (used for remote role server probing)

CONDITIONAL — sections degrade gracefully when the role is absent
  - IIS (Web-Server feature): required for sections 39, 40, health check IIS
    tests, and service account app pool enumeration. If IIS is not installed
    those sub-sections return an explanatory note rather than failing.
  - WSUS (WSUS-Services feature): section 40 returns "WSUS not installed" note.
  - WDS (WDS feature): health check returns NotInstalled status, not an error.
  - SQL access: section 20 (Database) and section 44 (Service Accounts / SQL
    logins) skip SQL queries and record the reason in the output.
  - WinRM / PSRemoting (port 5985): required for section 45 IIS, certificate,
    and Windows Feature probing on remote role servers. If WinRM is unavailable
    the WMI-based data (OS, disk, services, local groups) is still collected
    via DCOM and the WinRM-dependent fields note why they are empty.
  - Remote Registry service: used by section 45 to read WSUS registry on the
    SUP server. Falls back to Invoke-Command (WinRM) if unavailable.

NOT REQUIRED
  - Internet access — no downloads, no NuGet, no PowerShell Gallery
  - ActiveDirectory module — not used
  - RSAT tools beyond ServerManager — not used
  - Any third-party modules — not used


================================================================================
  GET-MECMCONFIG.PS1 — COLLECTING A SNAPSHOT
================================================================================

USAGE
  .\Get-MECMConfig.ps1 [parameters]

PARAMETERS

  -OutputPath <string>
      Folder where the JSON snapshot file will be saved.
      Default: the current working directory.
      Example: -OutputPath "C:\MECM\Snapshots"

  -SiteCode <string>
      The three-character MECM site code (e.g. "P01", "RAF").
      Default: auto-detected from the SMS Provider WMI.

  -SMSProvider <string>
      Hostname of the SMS Provider server.
      Default: the local machine ($env:COMPUTERNAME).
      Use this when running the script from a workstation or jump host rather
      than directly on the site server.
      Example: -SMSProvider "PROD-SITE01"

  -LogHoursBack <int>
      How many hours back to scan MECM log files for errors and warnings.
      Default: 48 hours.
      Example: -LogHoursBack 72

  -LogMaxLines <int>
      Maximum number of lines to read from the tail of each log file.
      Default: 5000.

  -SitePrefix <string>
      The 3-4 character site/environment prefix used in certificate template
      names (e.g. "DIEP", "DIES", "FIES", "FIEP").
      Default: auto-detected from the first 3-4 characters of the computer name.
      Only needed if your computer name does not start with the site prefix.
      Example: -SitePrefix "FIES"

  -SkipRemoteProbes
      Switch. When specified, section 45 (Role Server Probes) is skipped
      entirely. Use this if DCOM/WMI is blocked between servers, or if you
      only want to collect MECM configuration data and not host-level data
      from role servers.
      Example: -SkipRemoteProbes

  -RemoteTimeoutSec <int>
      WMI connection timeout in seconds when probing remote role servers.
      Default: 30 seconds.
      Increase this on slow or high-latency links.
      Example: -RemoteTimeoutSec 60

EXAMPLES

  # Basic — run on the site server, auto-detect everything
  .\Get-MECMConfig.ps1

  # Save to a specific folder
  .\Get-MECMConfig.ps1 -OutputPath "C:\MECM\Snapshots"

  # Run from a jump host against a named SMS Provider
  .\Get-MECMConfig.ps1 -SMSProvider "PROD-SITE01" -OutputPath "C:\Reports"

  # Full production run with explicit site code and prefix
  .\Get-MECMConfig.ps1 -SiteCode "P01" -SMSProvider "PROD-SITE01" `
      -SitePrefix "DIEP" -OutputPath "C:\Reports"

  # Skip remote host probing (faster, MECM config data only)
  .\Get-MECMConfig.ps1 -SkipRemoteProbes

  # Distributed environment — all defaults, script auto-discovers role servers
  .\Get-MECMConfig.ps1 -SMSProvider "PROD-SITE01" -RemoteTimeoutSec 60

OUTPUT
  A single JSON file named:
      MECM_Config_<SiteCode>_<YYYYMMDD_HHmmss>.json

  The file is saved to -OutputPath (default: current directory).
  All data is self-contained in this one file — no supporting files needed.

  A summary is printed to the console on completion showing:
    - Site code, name, version, and build number
    - Counts for all major configuration areas
    - Log analysis results (errors/warnings found in log files)
    - Role server probe results (one line per server with disk space)
    - Named service accounts discovered
    - Health check pass/fail/warning breakdown
    - Any sections that encountered errors


================================================================================
  DATA COLLECTED — SECTION SUMMARY
================================================================================

  Section  Description
  -------  -------------------------------------------------------------------
   1       Site Information         — site code, name, version, hierarchy
   2       Site System Roles        — all servers and their roles in the site
   3       Boundaries               — IP ranges, subnets, AD sites defined
   4       Boundary Groups          — boundary group memberships and fallback
   5       Client Settings          — all client setting policies and values,
                                      including default and all custom policies.
                                      Shows assigned collections and the full
                                      set of configured agent settings per
                                      policy (hardware inventory schedule,
                                      software inventory, policy interval, etc.)
   6       Discovery Methods        — enabled discovery agents and schedules
   7       Software Updates         — SUP settings, enabled categories/products
   8       Distribution Points      — DP list, settings, HTTPS/HTTP mode
   9       DP Groups                — DP group membership
  10       Collections              — device and user collection counts
  11       Applications             — application names and deployment types
  12       Packages & Task Sequences — packages, TS, driver packages, boot images
  13       OSD                      — boot images, OS images, upgrade packages
  14       Endpoint Protection      — antimalware policy settings
  15       Maintenance Windows      — maintenance window schedules
  16       Software Metering        — software metering rules
  17       Cloud Services           — Azure/CMG service configuration
  18       Hierarchy Settings       — site definition properties (SQL, ports)
  19       Component Status         — component health from last summarisation
  20       Database Info            — SQL version, DB size, connection status
  21       Logs                     — log file analysis across 20 MECM log files.
                                      Scans the last 48 hours (configurable).
                                      Stores up to 300 entries per log file
                                      (newest first) for viewing in the compare
                                      report. Both CMTrace XML and simple-format
                                      log entries are parsed. Each entry records
                                      date/time, severity, component, message,
                                      and a Flagged boolean for entries that
                                      match error/warning keyword criteria.
  22       Host System              — OS, hardware, disks, features of site server
  23       RBAC                     — admin users, roles, security scopes
  24       Automatic Deployment Rules — ADR names, schedules, targets
  25       Deployments              — deployment summary across all packages/apps
  26       Client Communication     — HTTP/HTTPS mode, PKI settings
  27       Hardware Inventory Classes — enabled HW inventory class names
  28       Configuration Baselines  — baseline names and revision counts
  29       Alerts                   — active MECM alerts
  30       Run Scripts              — approved PowerShell scripts in the console
  31       Windows Servicing Plans  — Windows 10/11 servicing plan settings
  32       Third-Party Update Catalogs — subscribed third-party SUP catalogs
  33       Co-Management            — co-management workload configuration
  34       Content Distribution     — package distribution failure summary
  35       Site Maintenance Tasks   — scheduled SQL maintenance task settings
  36       Software Update Groups   — update group names and member counts
  37       Status Message Filter Rules — status message filter configuration
  38       Certificates             — MECM certificates in the site (WMI)
  39       IIS Configuration        — websites, app pools, SSL bindings (local)
  40       WSUS Configuration       — WSUS registry, services, IIS pool (local)
  41       Content Store            — DP content library details, source paths
  42       Group Policy Settings    — MECM-relevant registry policy values, RSoP
  43       Health Checks            — CI baseline-style pass/fail checks:
                                       services (IISADMIN, WDSServer, CcmExec),
                                       IIS app pools, Windows features,
                                       disk space thresholds, IIS authentication,
                                       certificate validity and expiry, SSL binding,
                                       DP virtual directory health (SMS_DP_SMSPKG$
                                         + DataLib/FileLib/PkgLib),
                                       firewall port accessibility for key MECM /
                                         WSUS ports (80, 443, 10123, 135, 1433,
                                         8530/8531 when WSUS installed) — checks
                                         for explicit block rules and warns when
                                         no Allow rule exists with a blocking
                                         Domain profile default
  44       Service Accounts         — named Windows service accounts, MECM
                                       component account settings, IIS app pool
                                       identities, local group membership,
                                       SQL database logins, gMSA detection
  45       Role Server Probes       — per-server data for ALL role servers
                                       auto-discovered from section 2:
                                         OS info, disk space, services (WMI/DCOM)
                                         local groups (ADSI — no WinRM needed)
                                         IIS, certificates (WinRM if available)
                                         Windows features (WinRM if available)
                                         WSUS registry on SUP server
  48       Firewall Configuration    — Windows Firewall profile states and
                                       MECM/WSUS-relevant rule configuration:
                                         Profiles: Domain/Private/Public enabled
                                           state, default inbound/outbound action,
                                           logging settings
                                         Key Port Status: per-port effective
                                           inbound status (Allowed / Blocked /
                                           No-Rule) for all 12 MECM/WSUS ports:
                                           80, 443, 8530, 8531, 10123, 2701, 135,
                                           445, 1433, 4022, 1434/UDP, 9/UDP
                                         Rules: all enabled inbound/outbound rules
                                           whose LocalPort matches a key MECM port
                                           or whose display name matches an MECM/
                                           WSUS/SMS/ConfigMgr/SQL pattern
                                         Issues: auto-generated list of problems
                                           — profile disabled, port explicitly
                                           blocked, critical port with no Allow
                                           rule when Domain profile default is
                                           Block. Issues are colour-coded Critical
                                           or Warning in the compare report.
                                       Collection uses two bulk cmdlet calls
                                       (Get-NetFirewallRule + Get-NetFirewallPort
                                       Filter) rather than per-rule lookups to
                                       keep runtime acceptable on servers with
                                       hundreds of firewall rules.

  46       Registry Settings        — MECM-related registry values from the
                                       local machine, grouped into four areas:
                                         SMS (server-side): Identification,
                                           SQL Server, Security, IIS, MP, DP,
                                           WSUS, Setup, and Tracing (global
                                           settings + per-component table for
                                           all ~75 component log configurations)
                                         CCM (client-side): root values plus
                                           CcmEval, CcmExec, Logging, Security,
                                           LocationServices, SoftwareUpdates,
                                           and Inventory sub-keys
                                         CCMSetup: last install parameters and
                                           last valid MP used during client setup
                                         Windows Update Policy: WSUS server URL,
                                           AU options, and update policy values
                                       Large binary values (certificate blobs,
                                       serialised keys) are omitted automatically.


================================================================================
  CLIENT SETTINGS (SECTION 5)
================================================================================

Section 5 collects all client settings policies from two WMI classes:

  SMS_ClientSettingsDefault
      The built-in Default Client Agent Settings policy (Priority 10000,
      applies to all devices). Shows policy metadata. The agent configuration
      values for the default policy are MECM built-in defaults and are not
      enumerable via WMI.

  SMS_ClientSettings
      All custom client settings policies. Each custom policy shows:
        - Priority (lower number = higher priority)
        - Type (Custom or Custom User)
        - Collection assignments (which collections the policy targets)
        - Agent configurations — the specific agent settings tabs that were
          explicitly configured in that policy, with all property values.
          Examples: SMS_HardwareInventoryAgentConfig (schedule, max random
          delay), SMS_PolicyAgentConfig (policy download interval), etc.
          Only agents that were explicitly configured appear here; agents not
          configured in a custom policy inherit from the default.

In the compare report, custom client settings are diffed by policy name.
Collection assignments and all agent configuration properties are compared.


================================================================================
  REMOTE ROLE SERVER PROBING (SECTION 45)
================================================================================

In distributed MECM environments where the Management Point, Distribution Point,
WSUS/SUP, and SQL Server are on separate hosts, section 45 automatically probes
each server. The script discovers role servers from section 2 data — no manual
configuration is needed.

  Protocol    Port(s)       Used for                           Required?
  ----------  ------------  ---------------------------------  ----------------
  DCOM/WMI    TCP 135 +     OS info, disk space, services,     Core data —
              dynamic RPC   local groups                        yes for basic
  ADSI WinNT  (same)        Local group membership             probe to work
  WinRM HTTP  TCP 5985      IIS config, certificates,          Optional —
  WinRM HTTPS TCP 5986      Windows features                   falls back
  Remote Reg  TCP 445       WSUS registry on SUP server        Optional —
                                                               falls back to
                                                               WinRM

If only DCOM is available (WinRM blocked), you still get: OS version, RAM,
all disk drives and free space, all relevant services and their startup
accounts, and local Administrators / SMS Admins group membership.

To skip remote probing entirely (MECM config data only, faster runtime):
  .\Get-MECMConfig.ps1 -SkipRemoteProbes


================================================================================
  COMPARE-MECMCONFIG.PS1 — COMPARING TWO SNAPSHOTS
================================================================================

USAGE
  .\Compare-MECMConfig.ps1 -LeftFile <path> [-RightFile <path>] [parameters]

PARAMETERS

  -LeftFile <string>   [MANDATORY]
      Path to the reference or baseline JSON snapshot (the "left" side in the
      HTML report). Typically the production environment. When -RightFile is
      omitted, this is the only file used and the report runs in single-site
      configuration viewer mode.
      Example: -LeftFile "C:\MECM\Snapshots\MECM_Config_P01_20260430.json"

  -RightFile <string>  [OPTIONAL]
      Path to the comparison JSON snapshot (the "right" side in the report).
      Typically the test or target environment.
      If omitted, the script runs in single-site viewer mode — see below.
      Example: -RightFile "C:\MECM\Snapshots\MECM_Config_T01_20260430.json"

  -OutputPath <string>
      Folder to save the HTML report.
      Default: same folder as -LeftFile.

EXAMPLES

  # View a single site's full configuration (no -RightFile needed)
  .\Compare-MECMConfig.ps1 `
      -LeftFile "C:\MECM\Snapshots\MECM_Config_P01_20260430.json"

  # Compare production vs test environment
  .\Compare-MECMConfig.ps1 `
      -LeftFile  "C:\Reports\MECM_Config_P01_20260430.json" `
      -RightFile "C:\Reports\MECM_Config_T01_20260430.json"

  # Save report to a specific folder
  .\Compare-MECMConfig.ps1 `
      -LeftFile  ".\MECM_Config_P01_20260430.json" `
      -RightFile ".\MECM_Config_T01_20260430.json" `
      -OutputPath "C:\Reports\Compare"

  # Compare the same environment before and after a change
  .\Compare-MECMConfig.ps1 `
      -LeftFile  ".\MECM_Config_P01_before.json" `
      -RightFile ".\MECM_Config_P01_after.json"

OUTPUT — Two-site compare mode
  A single self-contained HTML file named:
      MECM_Compare_<LeftSiteCode>_vs_<RightSiteCode>_<timestamp>.html

OUTPUT — Single-site viewer mode
  A single self-contained HTML file named:
      MECM_Config_<SiteCode>_View_<timestamp>.html

  Open in any modern web browser — no server or internet connection needed.

HTML REPORT FEATURES
  - Sidebar navigation: click any section to jump directly to it
  - Sections with differences show a red diff count badge
  - Sections with no differences are shown collapsed by default
  - Colour coding in diff tables:
      Green  — values match
      Red    — values differ (both sides shown)
      Yellow — entry only in the left (reference) snapshot
      Blue   — entry only in the right (comparison) snapshot
  - Expand All / Collapse All buttons in the top bar
  - Export CSV: downloads a spreadsheet of ALL data (all rows, all sections)
    including a dedicated Insights block for action items.
    File is saved as MECM_Compare.csv.
  - Health check status cells: green (Pass), amber (Warning), red (Fail)
  - Insights section — see below
  - Log viewer — see below

SINGLE-SITE CONFIGURATION VIEWER MODE
  When -RightFile is omitted, the script runs in single-site viewer mode.
  The same JSON file is used for both sides of every comparison, so all rows
  show as matching (no red diff badges). This gives you a clean, fully
  navigable view of the entire site configuration in one HTML file — all 46
  sections, the Insights panel, and log viewer are fully functional.

  Differences from two-site compare mode:
    - Report title shows "MECM Config: <SiteCode>" instead of "vs" framing
    - Top bar badge shows "Configuration Viewer" instead of a diff count
    - Only one site pill shown in the top bar
    - Output file named MECM_Config_<SiteCode>_View_<timestamp>.html
    - All sidebar diff badges show 0 (everything matches itself)

  Useful for:
    - Reviewing a full site baseline without a second environment to compare
    - Sharing a read-only configuration report with someone who does not have
      access to the MECM console
    - Checking a snapshot before storing it as a long-term baseline
    - Post-change verification: run a new snapshot and open it in viewer mode
      to confirm the expected state before running a formal comparison

ROLE SERVER COMPARISON IN THE REPORT
  When environments have different server names (which they always will),
  the Role Server Probes section matches servers by ROLE rather than name.
  For example, the SMS Distribution Point server in production is compared
  against the SMS Distribution Point server in the test environment, regardless
  of their hostnames. This makes the comparison meaningful across environments.


================================================================================
  INSIGHTS — ACTIONS NEEDED
================================================================================

The Insights section appears near the top of the compare report (second item
in the sidebar, after the Summary). It provides a side-by-side panel for each
environment listing all items that require attention.

Items are automatically derived from the collected data:

  Category       Source                  Triggers
  -----------    ----------------------  ----------------------------------------
  Health Check   Section 43              Any check with status Fail, Error,
                                         Warning, or NotInstalled
  Component      Section 19              Any component with State != OK (Error
                                         or Warning)
  Service        Section 45 (probes)     Any monitored service that is not in
                                         the Running state on a role server
  Disk Space     Section 45 (probes)     Drive free space below 20% (Warning)
                                         or below 10% (Critical)
  Logs           Section 21              Total error entries > 0 (Warning),
                                         total warning entries > 0 (Info)
  Content Dist.  Section 34              Content distribution failure count > 0

Each item is assigned a severity:
  Critical  — red  — immediate attention required
  Warning   — amber — attention recommended
  Info      — blue  — informational, review when convenient

Items within each panel are sorted Critical first, then Warning, then Info.

If no issues are found for an environment, the panel shows:
  "All checks passed. No actions required."

The Insights section is also included in the CSV export (see Export CSV).


================================================================================
  LOG ANALYSIS AND LOG VIEWER (SECTION 21)
================================================================================

COLLECTION (Get-MECMConfig.ps1)

Section 21 scans 20 MECM log files in the site server's Logs directory over
the configured time window (default: 48 hours, see -LogHoursBack).

Log files scanned:
  smsexec, smsprov, smsdbmon, hman, sitestat, compsumm, replmgr, objreplmgr,
  sender, certmgr, distmgr, pkgxfermgr, smsdpprov, wcm, wsyncmgr, mpcontrol,
  mpfdm, colleval, policypv, statesys, offermgr, schedulermgr

Both log file formats produced by MECM are parsed:
  - CMTrace XML format:    <![LOG[message]LOG]!><time="..." date="..." type="N"...>
                           Severity is read directly from the type field (1/2/3).
  - CMTrace simple format: message  $$<Component><MM-DD-YYYY HH:MM:SS...>
                           Severity is inferred from message keywords (error,
                           failed, warning, etc.).

Up to 300 log entries per file are stored in the JSON (newest first).
Each entry records: date/time, severity (Error/Warning/Info), component,
message text, and a Flagged boolean.

An entry is Flagged when:
  - Severity is Error (type 3): always flagged
  - Severity is Warning (type 2): flagged if the message matches known keywords
    (failed, timeout, certificate, access denied, 0x80xx, etc.)
  - Severity is Info (type 1): flagged only when the message matches both a
    component-specific keyword AND a failure indicator word

LOG VIEWER (Compare-MECMConfig.ps1)

In the compare report, each log file shows two side-by-side scrollable panels —
one for the left environment, one for the right. This lets you scroll through
real log activity on both sides independently.

Each panel header shows:
  - Environment site code
  - Total entry count
  - Flagged entry count badge (orange, with flag icon) — only shown when > 0

Each row in the log table shows:
  - Flag column: ⚑ icon for flagged entries
  - Date / Time
  - Severity  (Error / Warning / Info)
  - Component
  - Message

Row colour coding:
  Red background    — Error entries
  Amber background  — Warning entries
  White background  — Info entries
  Flagged entries   — stronger tint + red left border + ⚑ in flag column

Filter button (per panel — cycles through three states):
  "Errors & Warnings only"  — hides all Info rows, shows Errors and Warnings
  "Flagged only"            — shows only flagged entries (any severity)
  "Show all entries"        — returns to full view

Note: production environments will typically have very different log content.
The log viewer is intentionally NOT a diff tool — it is a side-by-side viewer
for scrolling through and reviewing log activity on each environment. Use the
filter buttons to focus on problems.


================================================================================
  HEALTH CHECKS (SECTION 43)
================================================================================

Section 43 runs a set of pass/fail checks on the local server (the machine
running the script). These are based on CI baseline checks and cover:

  Category       Check
  -----------    ---------------------------------------------------------------
  Services       IISADMIN service running
                 WDSServer (Windows Deployment Services) service running
                 CcmExec (SMS Agent Host) service running
  App Pools      DefaultAppPool — Started
                 SMS Distribution Points Pool — Started
  Features       Web Server (IIS) feature installed
                 Windows Deployment Services feature installed
  Disk           C:\ drive has at least 10 GB free
                 U:\ drive has at least 50 GB free (NotInstalled if drive absent)
  IIS Auth       Anonymous Authentication enabled on Default Web Site
                 Windows Authentication enabled on Default Web Site
  Certificates   ConfigMgr Client Distribution Point Certificate — valid,
                 not expiring within 30 days
                 ConfigMgr Web Server Certificate — valid, not expiring within
                 30 days
  SSL Binding    Port 443 SSL certificate thumbprint matches the Web Server cert

Status values:
  Pass         — check succeeded
  Warning      — check passed but attention needed (certificate expiring soon)
  Fail         — check failed
  Error        — check threw an unexpected exception
  NotInstalled — component not present on this server (not a failure)

The site prefix (DIEP, DIES, FIES, FIEP, etc.) used for certificate template
matching is auto-detected from the computer name, or can be set explicitly
with -SitePrefix.

Failed and warning checks are surfaced automatically in the Insights section
of the compare report.


================================================================================
  SERVICE ACCOUNTS (SECTION 44)
================================================================================

Section 44 enumerates all service account information from multiple sources:

  Source                    Data collected
  ------------------------  ----------------------------------------------------
  Win32_Service (WMI)       All MECM-related and named-account services with
                            their StartName (the account they run under),
                            state, and start mode. gMSA accounts (name ending
                            in $) are flagged separately.
  SMS_SCI_Component (WMI)   MECM component property lists where the property
                            name includes Account, User, Login, or Credential.
                            This captures Network Access Accounts, discovery
                            accounts, and other MECM-stored account references.
                            Passwords are never stored in readable form in WMI.
  IIS App Pools             Identity type and username for each app pool.
                            Only SpecificUser entries (named accounts) are
                            flagged as requiring attention.
  Local Groups              Membership of: Administrators, SMS Admins,
                            ConfigMgr Remote Control Users, Distributed COM
                            Users, Performance Monitor Users, Performance Log
                            Users. Uses ADSI WinNT — no WinRM needed.
  SQL Database Logins       All non-system logins with access to the ConfigMgr
                            database, their type, and their database roles.
                            Requires SQL access (skips gracefully if unavailable).
  Summary                   Unique named account list across all sources,
                            gMSA count, total entries per source.

The console output at the end of the run prints the complete list of unique
named accounts found across all sources.


================================================================================
  REGISTRY SETTINGS (SECTION 46)
================================================================================

Section 46 reads MECM-related registry values from the local machine using the
Registry PSDrive (HKLM:\). It does not query remote servers — only the machine
running the script is read. The data is divided into four top-level groups.

SMS (server-side MECM registry)
  HKLM:\SOFTWARE\Microsoft\SMS\Identification
      Site code, site name, parent site code, SQL Server name, and database
      name. This is the primary site identity record.

  HKLM:\SOFTWARE\Microsoft\SMS\SQL Server
      SQL connection details used by the SMS Provider: server name, database
      name, failover partner, and authentication settings.

  HKLM:\SOFTWARE\Microsoft\SMS\Security
      PKI/certificate configuration. Large binary values (SerializedKey,
      CryptInfo) are automatically skipped to keep the JSON file readable.

  HKLM:\SOFTWARE\Microsoft\SMS\IIS
      IIS integration settings used by site roles that require IIS (HTTP/HTTPS
      ports, virtual directories).

  HKLM:\SOFTWARE\Microsoft\SMS\MP
      Management Point registry configuration (port, HTTPS state).

  HKLM:\SOFTWARE\Microsoft\SMS\DP
      Distribution Point registry settings.

  HKLM:\SOFTWARE\Microsoft\SMS\WSUS
      WSUS integration settings used by the Software Update Point role.

  HKLM:\SOFTWARE\Microsoft\SMS\Setup
      Installation paths and installer version recorded by the MECM setup.

  HKLM:\SOFTWARE\Microsoft\SMS\Tracing
      Global tracing settings plus a per-component table. The component table
      covers approximately 75 SMS components and records five values for each:
        MaxFileSize     — maximum log file size in KB
        Enabled         — whether logging is enabled (1/0)
        DebugLogging    — verbose debug logging (1/0)
        LoggingLevel    — severity level (0=All, 1=Warning, 2=Error only)
        LogMaxHistory   — number of log history files to keep
      In the compare report the component table shows all components in a
      single wide table; only rows where any field differs are flagged.

CCM (client-side / client agent registry)
  HKLM:\SOFTWARE\Microsoft\CCM           — root values: HTTP/HTTPS ports,
                                            LookupMPList (assigned MP list)
  HKLM:\SOFTWARE\Microsoft\CCM\CcmEval  — health evaluation interval,
                                            NotifyOnly mode, MaxMissCycles
  HKLM:\SOFTWARE\Microsoft\CCM\CcmExec  — provisioning mode flag
  HKLM:\SOFTWARE\Microsoft\CCM\Logging  — CCM logging settings
  HKLM:\SOFTWARE\Microsoft\CCM\Security — PKI certificate store and options
                                            (large binary values omitted)
  HKLM:\SOFTWARE\Microsoft\CCM\LocationServices
                                         — last used MP, VPN detection flag
  HKLM:\SOFTWARE\Microsoft\CCM\SoftwareUpdates
                                         — client-side SU settings
  HKLM:\SOFTWARE\Microsoft\CCM\Inventory — hardware inventory settings

CCMSetup
  HKLM:\SOFTWARE\Microsoft\CCMSetup
      Records the parameters used during the last successful client install
      (LastSuccessfulInstallParams) and the last MP used during setup
      (LastValidMP). Useful for verifying that both environments installed
      the client using the same parameters.

Windows Update Policy
  HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
      WSUS server URL (WUServer / WUStatusServer), alternate URL,
      and FillEmptyContentUrls flag.

  HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
      AUOptions (notify/download/auto-install), UseWUServer flag,
      NoAutoRebootWithLoggedOnUsers, scheduled install day/time.

Binary value handling
  Any binary registry value larger than 64 bytes is replaced in the JSON
  output with a "<Binary N bytes — skipped>" placeholder. Values named
  SerializedKey, CryptInfo, or CcmRootCertList are always omitted regardless
  of size. This prevents certificate blobs from bloating the JSON file.

In the compare report, each sub-group is shown as a separate KV table with a
diff badge. The Tracing per-component table is only shown if any tracing
component values differ between the two environments.


================================================================================
  TYPICAL WORKFLOW
================================================================================

  Step 1: Collect a snapshot from the reference (production) environment
  ----------------------------------------------------------------------
  Log on to the production MECM site server (or a machine with SMS Provider).
  Run:
      .\Get-MECMConfig.ps1 -OutputPath "C:\MECM\Snapshots"

  This creates a file like:
      C:\MECM\Snapshots\MECM_Config_P01_20260430_143022.json

  Copy that JSON file to wherever you will run the comparison.

  Step 2: Collect a snapshot from the comparison environment
  ----------------------------------------------------------
  Log on to the test / target MECM site server and run the same script:
      .\Get-MECMConfig.ps1 -OutputPath "C:\MECM\Snapshots"

  This creates:
      C:\MECM\Snapshots\MECM_Config_T01_20260430_150145.json

  Step 3: Run the comparison
  --------------------------
  On any machine with PowerShell 5.1, run:
      .\Compare-MECMConfig.ps1 `
          -LeftFile  "C:\MECM\Snapshots\MECM_Config_P01_20260430_143022.json" `
          -RightFile "C:\MECM\Snapshots\MECM_Config_T01_20260430_150145.json"

  The HTML report is created in the same folder as the left file (or -OutputPath).
  Open it in a web browser to review differences.

  Step 4: Review the report
  -------------------------
  Start with the Insights section (second item in the sidebar). It lists all
  Critical, Warning, and Info items for each environment at a glance — this
  tells you immediately what needs to be addressed before the environments
  can be considered equivalent.

  Then review the Summary section for a count of differences across all areas.
  Sections with a red badge in the sidebar have differences — click to jump.

  For logs, use the Log Analysis section. Each log file shows side-by-side
  panels for both environments. Use the filter button on each panel to focus
  on errors, warnings, or flagged entries. The two sides are independent
  viewers, not a diff — production logs will look different from test logs.

  For the Role Server Probes section, the report matches servers by role
  (e.g. MP vs MP, DP vs DP) even if the hostnames are different.

  Use Export CSV to extract all data and action items to a spreadsheet.


================================================================================
  EXPORT CSV
================================================================================

The Export CSV button (top bar of the compare report) downloads a file named
MECM_Compare.csv containing all data from the report in a flat spreadsheet
format.

Columns:
  Section         — the report section the row belongs to
  Property / Key  — the property name, item key, or insight category
  Left            — value for the left (reference) environment
  Right           — value for the right (comparison) environment

What is included:
  - All comparison rows from every section (both matching and differing rows)
  - Insights rows: each action item listed as "Insights (SiteCode)", with the
    severity and category in the Property column and the full detail in Left.
    The Right column is blank for insights (they are per-environment, not diffs).

What is excluded:
  - Log entry rows (too large; log file metadata rows such as file size,
    error count, and last modified date ARE included)

The CSV can be opened in Excel, imported into a ticket system, or attached to
a change record for sign-off.


================================================================================
  TROUBLESHOOTING
================================================================================

"Unable to retrieve data" in a section
    The section threw an exception. The error message is recorded in the JSON
    under the section's _Error key and listed at the end of the console output
    under "Sections with errors". Most common causes:
      - WMI namespace access denied: ensure the account is an MECM admin
      - SMS Provider not reachable: check -SMSProvider value and network access
      - SQL connection failed: section 20 will note this; other sections unaffected

Script takes a long time to run
    Section 45 (Role Server Probes) probes each role server in turn. In large
    environments or on slow links this can take several minutes. Options:
      - Use -SkipRemoteProbes to collect MECM config only (much faster)
      - Use -RemoteTimeoutSec 15 to fail faster on unreachable servers

WMI queries fail for remote role servers
    DCOM/RPC must be permitted from the script host to each role server.
    Firewall: TCP 135 inbound on role servers, plus dynamic RPC ports (or
    restrict with DCOM port range policies). This is separate from WinRM.

WinRM-dependent data is empty (IIS, certs, features in section 45)
    WinRM is not enabled by default on all servers. Enable with:
      Enable-PSRemoting -Force
    run on each role server, or via Group Policy:
      Computer Config > Policies > Windows Settings > Scripts > Startup
    The WMI-based probe data (OS, disk, services, local groups) is collected
    regardless of WinRM status.

Health checks show wrong certificate (wrong site prefix)
    Specify the prefix explicitly:
      .\Get-MECMConfig.ps1 -SitePrefix "FIES"

Compare report shows all role server data as different
    This is expected when comparing environments with different server names.
    The Role Server Probes section matches by ROLE (e.g. Management Point vs
    Management Point), not by hostname, so the data shown is correct. If a
    role exists in one environment but not the other it will be flagged.

Log viewer shows "No entries in time window"
    All entries in the scanned log files were older than the configured time
    window (-LogHoursBack, default 48). Either there has been no recent MECM
    activity, or the logs have rolled. Try increasing the window:
      .\Get-MECMConfig.ps1 -LogHoursBack 168   # 7 days

Insights section shows services as Critical (stopped)
    SMS_SITE_BACKUP and smstsmgr are expected to be stopped unless a backup
    or task sequence is actively running. Review other stopped services to
    determine whether they are expected on that server role.

JSON file is missing sections
    Each section is independent. A failure in one section does not affect others.
    Check the "Sections with errors" output at the end of the console run to
    identify which sections failed and why.

Client Settings shows only 1 entry
    On a minimal MECM install with no custom client settings policies, only the
    Default Client Agent Settings entry will appear. Custom entries appear when
    additional client settings policies have been created in the MECM console.

Registry Settings section is empty or very sparse
    Section 46 reads registry only from the local machine. If the script is run
    on a workstation or jump host that does not have the MECM client or SMS
    Provider role installed, most keys will not exist. Run on the site server
    itself to get the full SMS registry. CCM keys are present only on machines
    with the MECM client installed.

Compare report shows Registry tracing table with no rows
    The Tracing per-component table is suppressed when no component differs
    between the two environments. If both environments have identical Tracing
    settings (which is typical for freshly installed sites) the table is
    omitted to reduce noise.


================================================================================
  FILE REFERENCE
================================================================================

  Get-MECMConfig.ps1
      Run on each MECM site server or SMS Provider.
      Produces: MECM_Config_<SiteCode>_<timestamp>.json

  Compare-MECMConfig.ps1
      Run anywhere with PowerShell 5.1 and access to both JSON files.
      Produces: MECM_Compare_<Left>_vs_<Right>_<timestamp>.html

  MECM_Config_*.json
      The snapshot file. Safe to copy and store — contains no credentials or
      passwords. Keep these files to track configuration changes over time.

  MECM_Compare_*.html
      Self-contained diff report. No external dependencies — can be emailed,
      shared on a file share, or opened offline.

  MECM_Compare.csv
      CSV export from the compare report. Contains all section data and all
      Insights action items. Generated on demand from the Export CSV button.


================================================================================
  VERSION
================================================================================

  Script version : 2.0
  Compatible with: MECM 2203 and later (tested on 2403 / 2409 / 2503 / 2509)
  PowerShell     : 5.1 required
  Platform       : Windows Server 2016, 2019, 2022

  Changes in 2.0
  --------------
  - New Section 48: Firewall Configuration. Collects Windows Firewall profile
    states (Domain/Private/Public) and all firewall rules whose LocalPort
    matches a key MECM or WSUS port (80, 443, 8530, 8531, 10123, 2701, 135,
    445, 1433, 4022, 1434/UDP, 9/UDP) or whose display name matches an MECM /
    SMS / ConfigMgr / WSUS / SQL Server pattern. Produces a per-port effective
    status table (Allowed / Blocked / No-Rule with profile default) and an
    auto-generated Issues list that flags disabled profiles, explicitly blocked
    MECM ports (Critical severity), and critical ports with no explicit Allow
    rule when the Domain profile blocks inbound by default (Warning).
  - Section 43 (Health Checks): added FirewallPorts category — per-port checks
    for HTTP (80), HTTPS (443), Client Notification (10123), DCOM (135), SQL
    (1433), and WSUS HTTP/HTTPS (8530/8531 when WSUS feature installed).
    Each check reports Pass (explicit Allow rule found), Fail (explicit Block
    rule), or Warning (no rule + Domain profile default is Block). Uses the
    same two-pass bulk collection as Section 48 to keep runtime acceptable.
  - Compare report: Firewall Configuration section added (Section 48) with nav
    entry "Firewall". Layout: Issues table (colour-coded by severity), Profile
    KV diff per profile, Key Port Status comparison table (pass-cell /
    warn-cell / fail-cell colour coding), MECM/WSUS related rules diff table.
    Uses Wrap-Section-Raw (no non-functional "Show differences only" button).

  Changes in 1.9
  --------------
  - IIS DP Virtual Directory health check added to Section 43 (Health Checks).
    Verifies that SMS_DP_SMSPKG$ exists as a virtual application under Default
    Web Site, and that all three sub-virtual directories (DataLib, FileLib,
    PkgLib) are present in IIS, their physical paths exist on disk, and
    IIS_IUSRS/IUSR has read access to those paths. All four items report
    individually as IISVirtualDirs category checks so failures are pinpointed.
    These entries are commonly lost when IIS is reinstalled, breaking content
    delivery silently until clients start reporting download failures.
  - CI script added: iis SMS_DP_SMSPKG_VirtualDirs.ps1 — returns 0 (compliant)
    when all four IIS entries exist and their disk paths are present; returns
    1 (non-compliant) on any missing VD or missing physical path.
  - Compare report: IISVirtualDirs category rows now appear in the Health Checks
    section per-check table alongside all other health check categories.

  Changes in 1.8
  --------------
  - Single-site viewer mode: -RightFile is now optional in
    Compare-MECMConfig.ps1. When omitted the report opens as a full
    configuration viewer for the single site — all 46 sections, Insights,
    and log viewer are functional with no diff framing. Output file named
    MECM_Config_<SiteCode>_View_<timestamp>.html.
  - Registry fix: empty-string (Default) registry value names are now
    skipped in Get-MECMConfig.ps1 — they caused ConvertFrom-Json to fail
    in PowerShell 5.1 when loading a JSON file containing the registry
    section.

  Changes in 1.7
  --------------
  - Registry Settings (Section 46): new section collecting MECM-related
    registry values from the local machine. Covers SMS (Identification, SQL
    Server, Security, IIS, MP, DP, WSUS, Setup, Tracing global + per-component
    table for ~75 components), CCM client-side keys (root, CcmEval, CcmExec,
    Logging, Security, LocationServices, SoftwareUpdates, Inventory), CCMSetup,
    and Windows Update Policy (Policy + AU). Large binary values are
    automatically omitted.
  - Compare report: Registry Settings section added with dedicated nav entry.
    Each sub-group shown as a KV diff table. Tracing per-component table shows
    all ~75 components side by side; only shown when differences exist.
  - Summary table in compare report: added CCM HTTP/HTTPS port and SMS
    Identification key count for quick cross-environment sanity check.

  Changes in 1.6
  --------------
  - Log analysis: stores all parsed entries (not just flagged), up to 300 per
    log file. Both CMTrace XML and simple log formats are now parsed correctly.
  - Log viewer: redesigned as side-by-side scrollable panels per environment.
    Flagged entries highlighted with flag indicator column, flag badge in panel
    header, and 3-state filter (All / Errors & Warnings / Flagged only).
  - Client Settings: fixed to include default policy (SMS_ClientSettingsDefault)
    alongside custom policies. Agent configurations now lazy-loaded correctly.
    Collection assignments shown per policy.
  - Insights section: new section in the compare report listing all Critical,
    Warning, and Info action items per environment derived automatically from
    health checks, component status, services, disk space, logs, and content
    distribution.
  - Export CSV: now exports all data rows (not just differing rows), plus all
    Insights action items. File renamed to MECM_Compare.csv.

================================================================================
