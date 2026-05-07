SELECT
    sys.Name0                                                   AS ComputerName,
    sys.Resource_Domain_OR_Workgr0                              AS Domain,

    -- Instance name (default instance = MSSQLSERVER, named = MSSQL$NAME)
    svc.ServiceName0                                            AS ServiceName,
    CASE
        WHEN svc.ServiceName0 = 'MSSQLSERVER'
            THEN 'MSSQLSERVER (Default)'
        WHEN svc.ServiceName0 LIKE 'MSSQL$%'
            THEN SUBSTRING(svc.ServiceName0, 7, 100)
        ELSE svc.ServiceName0
    END                                                         AS InstanceName,

    -- Full instance connection string
    CASE
        WHEN svc.ServiceName0 = 'MSSQLSERVER'
            THEN svc.HostName0
        WHEN svc.ServiceName0 LIKE 'MSSQL$%'
            THEN svc.HostName0 + '\' + SUBSTRING(svc.ServiceName0, 7, 100)
        ELSE svc.HostName0
    END                                                         AS ConnectionName,

    -- Version derived from binary path (e.g. MSSQL15 = SQL 2019)
    CASE
        WHEN svc.BinaryPath0 LIKE '%MSSQL17%' THEN 'SQL Server 2025 (v17)'
        WHEN svc.BinaryPath0 LIKE '%MSSQL16%' THEN 'SQL Server 2022 (v16)'
        WHEN svc.BinaryPath0 LIKE '%MSSQL15%' THEN 'SQL Server 2019 (v15)'
        WHEN svc.BinaryPath0 LIKE '%MSSQL14%' THEN 'SQL Server 2017 (v14)'
        WHEN svc.BinaryPath0 LIKE '%MSSQL13%' THEN 'SQL Server 2016 (v13)'
        WHEN svc.BinaryPath0 LIKE '%MSSQL12%' THEN 'SQL Server 2014 (v12)'
        WHEN svc.BinaryPath0 LIKE '%MSSQL11%' THEN 'SQL Server 2012 (v11)'
        ELSE 'Unknown (check BinaryPath)'
    END                                                         AS SQLVersion,

    -- Edition and exact version from advanced properties (when collected)
    MAX(CASE WHEN ap.PropertyName0 = 'SKUNAME'  THEN ap.PropertyStrValue0 END) AS Edition,
    MAX(CASE WHEN ap.PropertyName0 = 'VERSION'  THEN ap.PropertyStrValue0 END) AS ProductVersion,

    svc.State0                                                  AS ServiceState,
    svc.StartMode0                                              AS StartMode,
    svc.StartName0                                              AS ServiceAccount,
    svc.BinaryPath0                                             AS BinaryPath,
    sys.Operating_System_Name_and0                              AS OperatingSystem,
    hinv.LastHWScan                                             AS LastHardwareInventory

FROM v_GS_SQLSERVICE                    svc
JOIN v_R_System                         sys  ON svc.ResourceID  = sys.ResourceID
LEFT JOIN v_GS_SQLSERVICEADVANCEDPROPERTY ap  ON svc.ResourceID  = ap.ResourceID
                                             AND svc.ServiceName0 = ap.ServiceName0
LEFT JOIN v_GS_WORKSTATION_STATUS       hinv ON svc.ResourceID  = hinv.ResourceID

WHERE svc.SQLServiceType0 = 1           -- Database Engine instances only

GROUP BY
    sys.Name0,
    sys.Resource_Domain_OR_Workgr0,
    svc.ServiceName0,
    svc.HostName0,
    svc.State0,
    svc.StartMode0,
    svc.StartName0,
    svc.BinaryPath0,
    sys.Operating_System_Name_and0,
    hinv.LastHWScan

ORDER BY sys.Name0, svc.ServiceName0;
