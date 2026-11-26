<#
.SYNOPSIS
    Prepara de forma segura, idempotente y reproducible el entorno local de Wazuh Single-Node.
.DESCRIPTION
    1. Genera `.env` y `infrastructure/.env` (UTF-8 sin BOM + LF, ignorados en Git) con
       contraseñas aleatorias compatibles con Wazuh API y OpenSearch Security.
    2. Detecta de forma independiente del idioma la IPv4 del adaptador aislado Host-Only
       (VMware VMnet1 / VirtualBox Host-Only) sin caer jamás en la interfaz Wi-Fi/LAN.
    3. Ajusta `vm.max_map_count=262144` en el kernel Linux de Docker/WSL2.
    4. Genera certificados X.509 internos mediante `wazuh/wazuh-certs-generator:0.0.2`.
    5. Calcula hashes bcrypt reales mediante `hash.sh` pasando secretos por variable de
       entorno (nunca en argumentos CLI visibles) y renderiza `internal_users.yml`.
#>

[CmdletBinding()]
param(
    [string]$AgentBindIp = "",
    [switch]$ForceRegenerateSecrets
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$InfraDir = Join-Path $RepoRoot "infrastructure"
$RootEnvPath = Join-Path $RepoRoot ".env"
$InfraEnvPath = Join-Path $InfraDir ".env"

function Write-Utf8LfFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $normalized = $Content.Replace("`r`n", "`n")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $normalized, $utf8NoBom)
}

function Remove-GhostDirectory {
    param([string]$TargetPath)
    if ((Test-Path $TargetPath) -and (Test-Path $TargetPath -PathType Container)) {
        Write-Host "      -> Limpiando directorio fantasma creado por Docker en: $TargetPath" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $TargetPath
    }
}

function New-WazuhSafePassword {
    param([int]$Length = 24)
    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray()
    $lower = "abcdefghijkmnopqrstuvwxyz".ToCharArray()
    $digits = "23456789".ToCharArray()
    # Símbolos aceptados por Wazuh API create_user.py y seguros en Docker Compose (.env)
    $symbols = ".*-?!+_".ToCharArray()
    $all = $upper + $lower + $digits + $symbols

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $Length
    $rng.GetBytes($bytes)

    $chars = New-Object System.Collections.Generic.List[char]
    $chars.Add($upper[$bytes[0] % $upper.Length])
    $chars.Add($lower[$bytes[1] % $lower.Length])
    $chars.Add($digits[$bytes[2] % $digits.Length])
    $chars.Add($symbols[$bytes[3] % $symbols.Length])

    for ($i = 4; $i -lt $Length; $i++) {
        $chars.Add($all[$bytes[$i] % $all.Length])
    }

    $shuffleBytes = New-Object byte[] $Length
    $rng.GetBytes($shuffleBytes)
    $shuffled = $chars.ToArray()
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = $shuffleBytes[$i] % ($i + 1)
        $tmp = $shuffled[$i]
        $shuffled[$i] = $shuffled[$j]
        $shuffled[$j] = $tmp
    }
    return -join $shuffled
}

function Get-DetectedHostOnlyIp {
    try {
        $netIp = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.InterfaceAlias -match "VMnet1|VirtualBox Host-Only" -and $_.IPAddress -notmatch "^169\.254\." } |
            Select-Object -First 1
        if ($null -ne $netIp -and -not [string]::IsNullOrWhiteSpace($netIp.IPAddress)) {
            return $netIp.IPAddress
        }
    } catch {
        # Fallback seguro por interfaz de red .NET independiente del idioma del sistema operativo
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.Name -match "VMnet1|VirtualBox Host-Only" -or $_.Description -match "VMnet1|VirtualBox Host-Only" }
        foreach ($nic in $nics) {
            foreach ($uni in $nic.GetIPProperties().UnicastAddresses) {
                if ($uni.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $ipStr = $uni.Address.IPAddressToString
                    if ($ipStr -notmatch "^169\.254\.") {
                        return $ipStr
                    }
                }
            }
        }
    }
    return "127.0.0.1"
}

Write-Host "[1/5] Verificando disponibilidad del motor Docker..." -ForegroundColor Cyan
docker info --format "{{.ServerVersion}}" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "El motor de Docker no responde. Asegúrate de que Docker Desktop haya terminado de iniciar y vuelve a ejecutar este script."
}

if ($ForceRegenerateSecrets) {
    Write-Host "      -> -ForceRegenerateSecrets activo: limpiando volúmenes previos para evitar desincronización de hashes..." -ForegroundColor Yellow
    Push-Location $InfraDir
    try {
        docker compose -f docker-compose.yml down -v 2>$null | Out-Null
    } catch {} finally {
        Pop-Location
    }
}

Write-Host "[2/5] Ajustando vm.max_map_count=262144 en el kernel Linux de Docker..." -ForegroundColor Cyan
docker run --rm --privileged alpine:3.20 sysctl -w vm.max_map_count=262144 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "No se pudo ajustar vm.max_map_count=262144 mediante el contenedor privilegiado."
}

if ((-not (Test-Path $RootEnvPath -PathType Leaf)) -or $ForceRegenerateSecrets) {
    Write-Host "[3/5] Generando archivo .env local (UTF-8 sin BOM + LF) con credenciales seguras..." -ForegroundColor Cyan
    if ([string]::IsNullOrWhiteSpace($AgentBindIp)) {
        $AgentBindIp = Get-DetectedHostOnlyIp
    }
    $indexerPass = New-WazuhSafePassword -Length 24
    $dashboardPass = New-WazuhSafePassword -Length 24
    $apiPass = New-WazuhSafePassword -Length 24

    $envContent = @"
WAZUH_IMAGE_VERSION=4.9.2
WAZUH_LOCAL_BIND_IP=127.0.0.1
WAZUH_AGENT_BIND_IP=$AgentBindIp
INDEXER_USERNAME=admin
INDEXER_PASSWORD=$indexerPass
DASHBOARD_USERNAME=kibanaserver
DASHBOARD_PASSWORD=$dashboardPass
API_USERNAME=wazuh-wui
API_PASSWORD=$apiPass
WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_VERIFY_SSL=false
TRIAGE_MIN_ALERT_LEVEL=10
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
CTI_HTTP_TIMEOUT_SECONDS=10
CTI_CACHE_TTL_HOURS=24
CTI_CACHE_DB_PATH=automation/.cti_cache.sqlite3
"@
    Write-Utf8LfFile -Path $RootEnvPath -Content $envContent
    Write-Host "      -> Adaptador Host-Only vinculado para agentes: $AgentBindIp" -ForegroundColor Green
} else {
    Write-Host "[3/5] Archivo .env existente detectado; conservando credenciales actuales." -ForegroundColor Yellow
    if (-not [string]::IsNullOrWhiteSpace($AgentBindIp)) {
        $existingEnv = Get-Content $RootEnvPath -Raw
        $updatedEnv = [regex]::Replace($existingEnv, "(?m)^WAZUH_AGENT_BIND_IP=.*$", "WAZUH_AGENT_BIND_IP=$AgentBindIp")
        Write-Utf8LfFile -Path $RootEnvPath -Content $updatedEnv
        Write-Host "      -> WAZUH_AGENT_BIND_IP actualizado a: $AgentBindIp" -ForegroundColor Green
    }
}

Write-Utf8LfFile -Path $InfraEnvPath -Content (Get-Content $RootEnvPath -Raw)

$envMap = @{}
Get-Content $RootEnvPath | ForEach-Object {
    if ($_ -match "^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$") {
        $envMap[$Matches[1]] = $Matches[2].Trim()
    }
}

$certsDir = Join-Path $InfraDir "config\wazuh_indexer_ssl_certs"
New-Item -ItemType Directory -Force -Path $certsDir | Out-Null
Get-ChildItem -Path $certsDir -Directory -Filter "*.pem" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Get-ChildItem -Path $certsDir -Directory -Filter "*.key" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

if (-not (Test-Path (Join-Path $certsDir "root-ca.pem") -PathType Leaf)) {
    Write-Host "[4/5] Generando certificados TLS internos (PKI propia del laboratorio)..." -ForegroundColor Cyan
    Push-Location $InfraDir
    try {
        docker compose -f generate-indexer-certs.yml run --rm generator
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[4/5] Certificados TLS internos verificados en config/wazuh_indexer_ssl_certs/." -ForegroundColor Yellow
}

$internalUsersPath = Join-Path $InfraDir "config\wazuh_indexer\internal_users.yml"
Remove-GhostDirectory -TargetPath $internalUsersPath

if ((-not (Test-Path $internalUsersPath -PathType Leaf)) -or $ForceRegenerateSecrets) {
    Write-Host "[5/5] Calculando hashes bcrypt para OpenSearch Security (vía env segura)..." -ForegroundColor Cyan
    $imageTag = "wazuh/wazuh-indexer:$($envMap['WAZUH_IMAGE_VERSION'])"

    $env:TARGET_HASH_PASS = $envMap["INDEXER_PASSWORD"]
    try {
        $adminHashRaw = docker run --rm -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk -e TARGET_HASH_PASS --entrypoint /bin/bash $imageTag -c '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$TARGET_HASH_PASS"'
    } finally {
        Remove-Item Env:\TARGET_HASH_PASS -ErrorAction SilentlyContinue
    }
    $adminHash = ($adminHashRaw | Where-Object { $_ -match '^\$2[ayb]\$' } | Select-Object -Last 1).Trim()

    $env:TARGET_HASH_PASS = $envMap["DASHBOARD_PASSWORD"]
    try {
        $dashHashRaw = docker run --rm -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk -e TARGET_HASH_PASS --entrypoint /bin/bash $imageTag -c '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$TARGET_HASH_PASS"'
    } finally {
        Remove-Item Env:\TARGET_HASH_PASS -ErrorAction SilentlyContinue
    }
    $dashHash = ($dashHashRaw | Where-Object { $_ -match '^\$2[ayb]\$' } | Select-Object -Last 1).Trim()

    if ([string]::IsNullOrWhiteSpace($adminHash) -or [string]::IsNullOrWhiteSpace($dashHash)) {
        throw "No se pudieron generar los hashes bcrypt mediante wazuh-indexer."
    }

    $usersTemplate = Get-Content (Join-Path $InfraDir "config\wazuh_indexer\internal_users.yml.template") -Raw
    $usersRendered = $usersTemplate.Replace("{{ADMIN_BCRYPT_HASH}}", $adminHash).Replace("{{DASHBOARD_BCRYPT_HASH}}", $dashHash)
    Write-Utf8LfFile -Path $internalUsersPath -Content $usersRendered
} else {
    Write-Host "[5/5] Archivo internal_users.yml ya sincronizado." -ForegroundColor Yellow
}

Write-Host "`nEntorno Wazuh preparado exitosamente. Ejecuta:" -ForegroundColor Green
Write-Host "  docker compose -f infrastructure/docker-compose.yml up -d" -ForegroundColor White
