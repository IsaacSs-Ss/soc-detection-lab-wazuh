# Evidencia Verificable — Fase 2: Instrumentación de Telemetría Endpoint (Windows Sysmon y Linux Auditd)

## 1. Estado de Salud de Contenedores (`docker ps`)

Verificación en vivo tras la integración del endpoint Linux reproducible (`soc-linux-endpoint`) dentro de la red interna `soc_internal_net`, sin publicar puertos de `openssh-server` hacia el sistema anfitrión:

```text
NAMES                 IMAGE                          STATUS                    PORTS
soc-linux-endpoint    soc-lab/linux-endpoint:4.9.2   Up 15 minutes (healthy)
soc-wazuh-dashboard   wazuh/wazuh-dashboard:4.9.2    Up 15 minutes (healthy)   127.0.0.1:443->5601/tcp
soc-wazuh-manager     wazuh/wazuh-manager:4.9.2      Up 15 minutes (healthy)   <HOST_ONLY_IP>:1514-1515->1514-1515/tcp, 127.0.0.1:55000->55000/tcp
soc-wazuh-indexer     wazuh/wazuh-indexer:4.9.2      Up 15 minutes (healthy)   127.0.0.1:9200->9200/tcp
```

---

## 2. Conectividad y Estado `Active` de Agentes (`agent_control -l`)

Salida obtenida desde `soc-wazuh-manager` confirmando el registro cifrado (`1515/TCP`) y la transmisión activa de eventos (`1514/TCP`) de ambos endpoints instrumentados:

```text
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local
   ID: 002, Name: soc-linux-endpoint, IP: any, Active
   ID: 003, Name: win-soc-endpoint, IP: any, Active
```

* **`soc-linux-endpoint` (`ID: 002`):** Contenedor Ubuntu 24.04 en `soc_internal_net` con `wazuh-agent` `4.9.2`, `rsyslog`, `openssh-server` (cuentas bloqueadas sin credenciales débiles activas) y captura de llamadas `execve`.
* **`win-soc-endpoint` (`ID: 003`):** Máquina virtual Windows 11 aprovisionada con `infrastructure/scripts/setup-windows-endpoint.ps1` para operar en el segmento *Host-Only* (`VMnet1`) ejecutando `Sysmon64` (`infrastructure/sysmon/sysmon-config.xml`) y `Wazuh Agent v4.9.2`, requiriendo desconectar cualquier adaptador NAT auxiliar previo al *Snapshot* limpio de la Fase 3.

---

## 3. Contraste Técnico en Windows: `Sysmon Event ID 1` frente a `Security 4688`

Ambos eventos corresponden exactamente a la misma ejecución elevada de `whoami.exe` (`PID 5072` / `0x13d0`) invocada desde `powershell.exe` (`PID 9012` / `0x2334`) a las `02:02:00Z` (identificadores del equipo sanitizados conforme a las normas OPSEC del repositorio; evento íntegro disponible en `detections/test-cases/phase2_sysmon_eid1_sample.json`):

### 3.1 `Microsoft-Windows-Sysmon/Operational` — Event ID 1 (`eventRecordID: 582`)

```json
{
  "timestamp": "2026-11-27T02:04:37.250+0000",
  "agent": {
    "id": "003",
    "name": "win-soc-endpoint",
    "ip": "192.168.56.101"
  },
  "decoder": {
    "name": "windows_eventchannel"
  },
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Sysmon",
        "eventID": "1",
        "systemTime": "2026-11-27T02:02:00.0950565Z",
        "eventRecordID": "582",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "WIN11-SOC-01"
      },
      "eventdata": {
        "utcTime": "2026-11-27 02:02:00.090",
        "processGuid": "{527729bb-e498-6b08-0602-000000000600}",
        "processId": "5072",
        "image": "C:\\\\Windows\\\\System32\\\\whoami.exe",
        "fileVersion": "10.0.26100.1882 (WinBuild.160101.0800)",
        "description": "whoami - displays logged on user information",
        "product": "Microsoft® Windows® Operating System",
        "company": "Microsoft Corporation",
        "originalFileName": "whoami.exe",
        "commandLine": "\\\"C:\\\\WINDOWS\\\\system32\\\\whoami.exe\\\"",
        "currentDirectory": "C:\\\\WINDOWS\\\\system32\\\\",
        "user": "WIN11-SOC-01\\\\corp_user",
        "logonGuid": "{527729bb-e300-6b08-c7fd-040000000000}",
        "logonId": "0x4fdc7",
        "terminalSessionId": "1",
        "integrityLevel": "High",
        "hashes": "SHA256=23240EF9F8B0A9A324110B1C2331DE31DC1B0E08F5359CB707E51A939AF56CD3",
        "parentProcessGuid": "{527729bb-e338-6b08-a800-000000000600}",
        "parentProcessId": "9012",
        "parentImage": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
        "parentCommandLine": "\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\"",
        "parentUser": "WIN11-SOC-01\\\\corp_user"
      }
    }
  },
  "location": "EventChannel"
}
```

### 3.2 `Security` — Event ID 4688 con `CommandLine` (`eventRecordID: 6286`)

```json
{
  "timestamp": "2026-11-27T02:04:35.473+0000",
  "rule": {
    "level": 3,
    "description": "A process was created.",
    "id": "67027",
    "firedtimes": 46,
    "mail": false,
    "groups": [
      "windows",
      " WEF"
    ]
  },
  "agent": {
    "id": "003",
    "name": "win-soc-endpoint",
    "ip": "192.168.56.101"
  },
  "decoder": {
    "name": "windows_eventchannel"
  },
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Security-Auditing",
        "eventID": "4688",
        "systemTime": "2026-11-27T02:02:00.0910016Z",
        "eventRecordID": "6286",
        "channel": "Security",
        "computer": "WIN11-SOC-01"
      },
      "eventdata": {
        "subjectUserName": "corp_user",
        "subjectDomainName": "WIN11-SOC-01",
        "newProcessId": "0x13d0",
        "newProcessName": "C:\\\\Windows\\\\System32\\\\whoami.exe",
        "tokenElevationType": "%%1937",
        "processId": "0x2334",
        "commandLine": "\\\"C:\\\\WINDOWS\\\\system32\\\\whoami.exe\\\"",
        "parentProcessName": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
        "mandatoryLabel": "S-1-16-12288"
      }
    }
  },
  "location": "EventChannel"
}
```

### Valor Diferencial para Detection Engineering

| Atributo Forense | `Security 4688` (con GPO `CommandLine`) | `Sysmon Event ID 1` (`windows_eventchannel`) | Impacto en Reglas Sigma / Wazuh (Fase 4) |
| :--- | :---: | :---: | :--- |
| Ruta del proceso e hijo/padre (`Image` / `ParentImage`) | ✓ | ✓ | Reconstrucción básica del árbol de ejecución (`PID` decimal frente a hexadecimal). |
| Línea de comandos del hijo (`CommandLine`) | ✓ | ✓ | Detección de banderas `-enc` / `-EncodedCommand` y `-ExecutionPolicy Bypass` (`T1059.001`). |
| Línea de comandos del padre (`ParentCommandLine`) | — | ✓ | Esencial para distinguir si el proceso padre fue iniciado por una tarea legítima o un *dropper* ofuscado. |
| Hash criptográfico del binario (`Hashes: SHA256`) | — | ✓ | Extracción directa de IoCs para enriquecimiento automatizado en VirusTotal (Fase 6). |
| Metadatos PE (`OriginalFileName`, `Company`) | — | ✓ | Resiliencia frente a evasión por renombrado de LOLBins (ej. copiar `powershell.exe` con otro nombre). |

---

## 4. Línea Base de Acceso a `lsass.exe` (`Sysmon Event ID 10`)

Extracto real capturado desde `win-soc-endpoint` (`RuleName: Sysmon_EID10_ProcessAccess_LSASS`). Conforme al diseño de `sysmon-config.xml`, no se aplican exclusiones masivas sobre binarios del sistema en el origen, permitiendo perfilar accesos legítimos (`svchost.exe` con máscara `0x1000` `PROCESS_QUERY_LIMITED_INFORMATION`) para documentar excepciones quirúrgicas en la Fase 5 frente a volcados reales de memoria (`T1003.001`):

```json
{
  "timestamp": "2026-11-27T02:18:43.039+0000",
  "agent": {
    "id": "003",
    "name": "win-soc-endpoint",
    "ip": "192.168.56.101"
  },
  "decoder": {
    "name": "windows_eventchannel"
  },
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Sysmon",
        "eventID": "10",
        "systemTime": "2026-11-27T02:18:41.9331615Z",
        "eventRecordID": "818",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "WIN11-SOC-01"
      },
      "eventdata": {
        "ruleName": "Sysmon_EID10_ProcessAccess_LSASS",
        "utcTime": "2026-11-27 02:18:41.928",
        "sourceProcessId": "512",
        "sourceImage": "C:\\\\WINDOWS\\\\system32\\\\svchost.exe",
        "targetProcessId": "820",
        "targetImage": "C:\\\\WINDOWS\\\\system32\\\\lsass.exe",
        "grantedAccess": "0x1000",
        "sourceUser": "NT AUTHORITY\\\\SYSTEM",
        "targetUser": "NT AUTHORITY\\\\SYSTEM"
      }
    }
  },
  "location": "EventChannel"
}
```

---

## 5. Telemetría Endpoint Linux en `archives.json` (`auditd` y `sshd`)

### 5.1 Ejecución de Procesos (`SYSCALL 59 / EXECVE`, clave `soc_execve`)

Evento real generado al ejecutar `/usr/bin/whoami` dentro de `soc-linux-endpoint`; el registro `SYSCALL 59 / EXECVE` proviene del relé de espacio de usuario compatible con `auditd` descrito en `ADR-05` (de ahí los valores sintéticos `a0–a3=0` y `ppid=0` del envoltorio `SYSCALL`), validando su decodificación nativa por el decodificador oficial `auditd` de Wazuh (`data.audit.*`):

```json
{
  "timestamp": "2026-11-27T02:22:35.072+0000",
  "agent": {
    "id": "002",
    "name": "soc-linux-endpoint",
    "ip": "172.19.0.2"
  },
  "manager": {
    "name": "wazuh.manager"
  },
  "id": "1795746155.5842889",
  "full_log": "type=SYSCALL msg=audit(1795746153.979:377): arch=c000003e syscall=59 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=1 ppid=0 pid=1302 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"whoami\" exe=\"/usr/bin/whoami\" key=\"soc_execve\" type=EXECVE msg=audit(1795746153.979:377): argc=1 a0=\"/usr/bin/whoami\" type=CWD msg=audit(1795746153.979:377): cwd=\"/\" type=PATH msg=audit(1795746153.979:377): item=0 name=\"/usr/bin/whoami\" nametype=NORMAL type=EOE msg=audit(1795746153.979:377): ",
  "decoder": {
    "parent": "auditd",
    "name": "auditd"
  },
  "data": {
    "audit": {
      "type": "SYSCALL",
      "id": "377",
      "arch": "c000003e",
      "syscall": "59",
      "success": "yes",
      "exit": "0",
      "ppid": "0",
      "pid": "1302",
      "auid": "4294967295",
      "uid": "0",
      "gid": "0",
      "euid": "0",
      "suid": "0",
      "fsuid": "0",
      "egid": "0",
      "sgid": "0",
      "fsgid": "0",
      "tty": "(none)",
      "session": "4294967295",
      "command": "whoami",
      "exe": "/usr/bin/whoami",
      "key": "soc_execve",
      "execve": {
        "a0": "/usr/bin/whoami"
      },
      "cwd": "/"
    }
  },
  "location": "/var/log/audit/audit.log"
}
```

### 5.2 Fallo de Autenticación SSH (`auth.log` -> Regla Nativa `5760` / `T1110.001`)

Intento controlado de autenticación fallida contra la cuenta bloqueada `soc_audit_target`, registrado por `rsyslog` en `/var/log/auth.log` y clasificado automáticamente con mapeo MITRE `T1110.001` (*Password Guessing*):

```json
{
  "timestamp": "2026-11-27T02:22:37.067+0000",
  "rule": {
    "level": 5,
    "description": "sshd: authentication failed.",
    "id": "5760",
    "mitre": {
      "id": [
        "T1110.001",
        "T1021.004"
      ],
      "tactic": [
        "Credential Access",
        "Lateral Movement"
      ],
      "technique": [
        "Password Guessing",
        "SSH"
      ]
    },
    "firedtimes": 1,
    "mail": false,
    "groups": [
      "syslog",
      "sshd",
      "authentication_failed"
    ],
    "gdpr": [
      "IV_35.7.d",
      "IV_32.2"
    ],
    "gpg13": [
      "7.1"
    ],
    "hipaa": [
      "164.312.b"
    ],
    "nist_800_53": [
      "AU.14",
      "AC.7"
    ],
    "pci_dss": [
      "10.2.4",
      "10.2.5"
    ],
    "tsc": [
      "CC6.1",
      "CC6.8",
      "CC7.2",
      "CC7.3"
    ]
  },
  "agent": {
    "id": "002",
    "name": "soc-linux-endpoint",
    "ip": "172.19.0.2"
  },
  "manager": {
    "name": "wazuh.manager"
  },
  "id": "1795746157.5842889",
  "full_log": "2026-11-27T02:22:36.417008+00:00 soc-linux-endpoint sshd[1315]: Failed password for soc_audit_target from 127.0.0.1 port 42154 ssh2",
  "predecoder": {
    "program_name": "sshd",
    "timestamp": "2026-11-27T02:22:36.417008+00:00"
  },
  "decoder": {
    "parent": "sshd",
    "name": "sshd"
  },
  "data": {
    "srcip": "127.0.0.1",
    "srcport": "42154",
    "dstuser": "soc_audit_target"
  },
  "location": "/var/log/auth.log"
}
```
