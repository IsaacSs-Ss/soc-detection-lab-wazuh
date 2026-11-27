<#
.SYNOPSIS
    Aprovisiona de forma idempotente y segura la telemetría de un endpoint Windows 10/11 para Wazuh SIEM/XDR v4.9.2.
.DESCRIPTION
    Autor: Isaac Sánchez Samaniego
    Automatiza la instrumentación defensiva de Fase 2 en la máquina virtual Windows del laboratorio:
    1. Verifica ejecución con privilegios administrativos (Run as Administrator).
    2. Verifica firmas digitales Authenticode (`Get-AuthenticodeSignature`) de los binarios
       descargados o locales antes de su ejecución privilegiada e instala o actualiza de forma
       idempotente Microsoft Sysmon (Sysmon64.exe) con `sysmon-config.xml`.
    3. Habilita por GUID universal independiente del idioma (`{0CCE922B-69AE-11D9-BED3-505054503030}`)
       la auditoría nativa de creación de procesos (`Security Event ID 4688`) junto con el registro
       completo de `CommandLine` en directivas de sistema.
    4. Instala Wazuh Agent v4.9.2 apuntando a la IP interna Host-Only del Manager (sin IPs reales
       hardcodeadas en el repositorio) e inyecta de manera idempotente en `ossec.conf` el canal
       `Microsoft-Windows-Sysmon/Operational` en formato `eventchannel`.
    5. Reinicia y verifica el estado operativo de los servicios `Sysmon64` y `WazuhSvc`.
.PARAMETER ManagerIp
    Dirección IPv4 privada del adaptador Host-Only (ej. VMnet1) donde escucha Wazuh Manager (1514/1515 TCP).
.PARAMETER AgentName
    Nombre identificador con el que se registrará el endpoint Windows ante Wazuh Manager.
.PARAMETER SysmonConfigPath
    Ruta al archivo XML de configuración de Sysmon. Si se omite, intenta resolver `..\sysmon\sysmon-config.xml`.
.EXAMPLE
    .\setup-windows-endpoint.ps1 -ManagerIp "192.168.56.1" -AgentName "win-soc-endpoint" -SysmonConfigPath "C:\Lab\sysmon-config.xml"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "IP privada Host-Only del Wazuh Manager (ej. 192.168.56.1)")]
    [ValidatePattern('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[a-zA-Z0-9.-]+$')]
    [string]$ManagerIp,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentName = "win-soc-endpoint",

    [Parameter(Mandatory = $false)]
    [string]$SysmonConfigPath = "",

    [Parameter(Mandatory = $false)]
    [string]$WazuhVersion = "4.9.2",

    [Parameter(Mandatory = $false)]
    [string]$WorkDir = "$env:TEMP\soc-endpoint-bootstrap"
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-ValidAuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$ComponentName
    )
    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        throw "No se encontró el archivo de $ComponentName para verificar su firma digital: $FilePath"
    }
    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    if ($null -eq $sig -or $sig.Status -ne 'Valid') {
        $sigStatus = if ($null -ne $sig) { "$($sig.Status) - $($sig.StatusMessage)" } else { "Sin firma" }
        throw "Fallo de verificación Authenticode en $ComponentName ($FilePath): estado '$sigStatus'. Ejecución abortada."
    }
    Write-Host "      -> Firma Authenticode válida en $ComponentName ($($sig.SignerCertificate.Subject))." -ForegroundColor Green
}

function Ensure-EventChannelBlock {
    param(
        [Parameter(Mandatory = $true)][xml]$XmlDoc,
        [Parameter(Mandatory = $true)][string]$ChannelLocation
    )
    $ossecNode = $XmlDoc.SelectSingleNode("/ossec_config")
    if ($null -eq $ossecNode) {
        throw "No se encontró el nodo raíz <ossec_config> en ossec.conf."
    }

    $existing = $XmlDoc.SelectNodes("//localfile[location='$ChannelLocation']")
    if ($null -ne $existing -and $existing.Count -gt 0) {
        Write-Host "      -> Canal '$ChannelLocation' ya presente en ossec.conf (sin cambios)." -ForegroundColor Yellow
        return $false
    }

    $localfileElem = $XmlDoc.CreateElement("localfile")
    $locationElem = $XmlDoc.CreateElement("location")
    $locationElem.InnerText = $ChannelLocation
    $formatElem = $XmlDoc.CreateElement("log_format")
    $formatElem.InnerText = "eventchannel"

    [void]$localfileElem.AppendChild($locationElem)
    [void]$localfileElem.AppendChild($formatElem)
    [void]$ossecNode.AppendChild($localfileElem)
    Write-Host "      -> Canal '$ChannelLocation' (eventchannel) inyectado en ossec.conf." -ForegroundColor Green
    return $true
}

if (-not (Test-IsAdministrator)) {
    throw "Este script requiere privilegios elevados. Abre PowerShell como Administrador y vuelve a ejecutarlo."
}

if ([string]::IsNullOrWhiteSpace($SysmonConfigPath)) {
    $candidatePath = Join-Path $PSScriptRoot "..\sysmon\sysmon-config.xml"
    if (Test-Path $candidatePath -PathType Leaf) {
        $SysmonConfigPath = (Resolve-Path $candidatePath).Path
    } else {
        throw "No se especificó -SysmonConfigPath y no se encontró '..\sysmon\sysmon-config.xml'. Proporciona la ruta explícita al archivo XML."
    }
} else {
    if (-not (Test-Path $SysmonConfigPath -PathType Leaf)) {
        throw "El archivo de configuración Sysmon indicado no existe: $SysmonConfigPath"
    }
    $SysmonConfigPath = (Resolve-Path $SysmonConfigPath).Path
}

Write-Host "[1/5] Validando sintaxis XML de la configuración Sysmon..." -ForegroundColor Cyan
[void][xml](Get-Content -Path $SysmonConfigPath -Raw -Encoding UTF8)
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "[2/5] Configurando de forma idempotente Microsoft Sysmon (Sysmon64)..." -ForegroundColor Cyan
$sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonSvc) {
    $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

$sysmonExe = Join-Path $env:SystemRoot "Sysmon64.exe"
if (-not (Test-Path $sysmonExe -PathType Leaf)) {
    $localSysmon = Join-Path $WorkDir "Sysmon64.exe"
    if (-not (Test-Path $localSysmon -PathType Leaf)) {
        $sysmonZip = Join-Path $WorkDir "Sysmon.zip"
        Write-Host "      -> Descargando paquete oficial Sysinternals Sysmon..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip -UseBasicParsing
        Expand-Archive -Path $sysmonZip -DestinationPath $WorkDir -Force
    }
    $sysmonExe = $localSysmon
}

Assert-ValidAuthenticodeSignature -FilePath $sysmonExe -ComponentName "Sysmon64.exe"

if ($null -eq $sysmonSvc) {
    Write-Host "      -> Instalando servicio Sysmon64 con configuración modular..." -ForegroundColor Cyan
    & $sysmonExe -accepteula -i $SysmonConfigPath
    if ($LASTEXITCODE -ne 0) {
        throw "La instalación de Sysmon64 devolvió código de error $LASTEXITCODE."
    }
} else {
    Write-Host "      -> Servicio $($sysmonSvc.Name) detectado; actualizando reglas activas..." -ForegroundColor Yellow
    & $sysmonExe -accepteula -c $SysmonConfigPath
    if ($LASTEXITCODE -ne 0) {
        throw "La actualización de reglas de Sysmon devolvió código de error $LASTEXITCODE."
    }
}

$sysmonActive = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $sysmonActive -or $sysmonActive.Status -ne "Running") {
    throw "El servicio de Sysmon no se encuentra en ejecución tras aplicar la configuración."
}
[void](Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop)
Write-Host "      -> Canal Microsoft-Windows-Sysmon/Operational activo y verificado." -ForegroundColor Green

Write-Host "[3/5] Habilitando auditoría Security 4688 con línea de comandos completa (GUID universal)..." -ForegroundColor Cyan
# GUID universal de 'Audit Process Creation' independiente del idioma de Windows
& auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "auditpol.exe falló al habilitar la subcategoría {0CCE922B-69AE-11D9-BED3-505054503030}."
}

$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegPath)) {
    New-Item -Path $auditRegPath -Force | Out-Null
}
New-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
Write-Host "      -> Security Event ID 4688 + ProcessCreationIncludeCmdLine_Enabled=1 aplicados." -ForegroundColor Green

Write-Host "[4/5] Verificando instalación de Wazuh Agent v$WazuhVersion..." -ForegroundColor Cyan
$ossecDir = "${env:ProgramFiles(x86)}\ossec-agent"
$ossecConfPath = Join-Path $ossecDir "ossec.conf"
$wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

if ($null -eq $wazuhSvc -or -not (Test-Path $ossecConfPath -PathType Leaf)) {
    $msiName = "wazuh-agent-$WazuhVersion-1.msi"
    $msiPath = Join-Path $WorkDir $msiName
    if (-not (Test-Path $msiPath -PathType Leaf)) {
        $msiUrl = "https://packages.wazuh.com/4.x/windows/$msiName"
        Write-Host "      -> Descargando instalador oficial Wazuh Agent ($msiName)..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    }
    Assert-ValidAuthenticodeSignature -FilePath $msiPath -ComponentName "Instalador MSI Wazuh Agent ($msiName)"
    Write-Host "      -> Ejecutando instalación silenciosa hacia Manager $ManagerIp..." -ForegroundColor Cyan
    $msiArgs = @(
        "/i", "`"$msiPath`"",
        "/q",
        "WAZUH_MANAGER=`"$ManagerIp`"",
        "WAZUH_REGISTRATION_SERVER=`"$ManagerIp`"",
        "WAZUH_AGENT_NAME=`"$AgentName`""
    )
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "msiexec.exe devolvió código de salida $($proc.ExitCode) al instalar Wazuh Agent."
    }
} else {
    Write-Host "      -> Servicio WazuhSvc ya instalado en $ossecDir." -ForegroundColor Yellow
}

Write-Host "[5/5] Sincronizando ossec.conf e inyectando canales EventChannel de forma idempotente..." -ForegroundColor Cyan
$backupPath = "$ossecConfPath.bak"
if (-not (Test-Path $backupPath -PathType Leaf)) {
    Copy-Item -Path $ossecConfPath -Destination $backupPath -Force
}

[xml]$ossecXml = Get-Content -Path $ossecConfPath -Raw -Encoding UTF8
$serverAddrNode = $ossecXml.SelectSingleNode("/ossec_config/client/server/address")
if ($null -ne $serverAddrNode) {
    $serverAddrNode.InnerText = $ManagerIp
}
$protocolNode = $ossecXml.SelectSingleNode("/ossec_config/client/server/protocol")
if ($null -ne $protocolNode) {
    $protocolNode.InnerText = "tcp"
}

$clientNode = $ossecXml.SelectSingleNode("/ossec_config/client")
$enrollNode = $ossecXml.SelectSingleNode("/ossec_config/client/enrollment")
if ($null -eq $enrollNode -and $null -ne $clientNode) {
    $enrollNode = $ossecXml.CreateElement("enrollment")
    [void]$clientNode.AppendChild($enrollNode)
}
if ($null -ne $enrollNode) {
    foreach ($pair in @(
        @{ Name = "enabled"; Value = "yes" },
        @{ Name = "manager_address"; Value = $ManagerIp },
        @{ Name = "port"; Value = "1515" },
        @{ Name = "agent_name"; Value = $AgentName }
    )) {
        $child = $enrollNode.SelectSingleNode($pair.Name)
        if ($null -eq $child) {
            $child = $ossecXml.CreateElement($pair.Name)
            [void]$enrollNode.AppendChild($child)
        }
        $child.InnerText = $pair.Value
    }
}

[void](Ensure-EventChannelBlock -XmlDoc $ossecXml -ChannelLocation "Microsoft-Windows-Sysmon/Operational")
[void](Ensure-EventChannelBlock -XmlDoc $ossecXml -ChannelLocation "Microsoft-Windows-PowerShell/Operational")

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$sw = New-Object System.IO.StringWriter
$xwSettings = New-Object System.Xml.XmlWriterSettings
$xwSettings.Indent = $true
$xwSettings.IndentChars = "  "
$xwSettings.NewLineChars = "`n"
$xwSettings.OmitXmlDeclaration = $true
$xw = [System.Xml.XmlWriter]::Create($sw, $xwSettings)
$ossecXml.Save($xw)
$xw.Close()
[System.IO.File]::WriteAllText($ossecConfPath, $sw.ToString() + "`n", $utf8NoBom)

Restart-Service -Name "WazuhSvc" -Force
$wazuhFinal = Get-Service -Name "WazuhSvc"
if ($wazuhFinal.Status -ne "Running") {
    throw "El servicio WazuhSvc no alcanzó el estado Running."
}

Write-Host "`n[OK] Endpoint Windows '$AgentName' instrumentado y conectado a $ManagerIp." -ForegroundColor Green
Write-Host "IMPORTANTE (Aislamiento OPSEC previo a Fase 3):" -ForegroundColor Yellow
Write-Host "  1. Desconecta/deshabilita ahora el adaptador NAT temporal (VMnet8), dejando solo Host-Only (VMnet1)." -ForegroundColor White
Write-Host "  2. Verifica estado 'Active' en el Manager y toma un Snapshot limpio antes de ejecutar pruebas atómicas." -ForegroundColor White
