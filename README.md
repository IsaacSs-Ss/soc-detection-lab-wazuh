# Laboratorio SOC Empresarial, Detection Engineering y Triaje Automatizado (Wazuh + Sigma + Python SOAR)

> **Estado del Proyecto:** En construcción progresiva controlada — **Fase 1 (Infraestructura SIEM y Segmentación de Red)**.  
> Consulta el alcance ético y aislamiento del laboratorio en [DISCLAIMER.md](DISCLAIMER.md).

## 1. Problema Operativo que Resuelve

En un Centro de Operaciones de Seguridad (SOC) real, desplegar un SIEM con reglas por defecto genera dos fallos críticos: **puntos ciegos ante técnicas modernas** (por falta de telemetría granular a nivel de proceso/memoria) y **fatiga de alertas** (por ausencia de calibración documentada sobre línea base legítima).

Este proyecto implementa el ciclo completo de ingeniería defensiva (*Detection-as-Code* y *SOAR*):

1. **Ingesta e Instrumentación Avanzada:** Clúster **Wazuh (SIEM/XDR)** en Docker con aislamiento de interfaces, alimentado por **Sysmon** en Windows y **Auditd** en Linux dentro de una red *Host-Only*.
2. **Emulación Controlada de Adversarios:** Ejecución trazable de 5 técnicas **MITRE ATT&CK** (`T1059.001`, `T1003.001`, `T1547.001`, `T1053.005`, `T1110.001`) con **Atomic Red Team**.
3. **Ingeniería de Detección Portátil:** Reglas agnósticas en **Sigma (YAML)** traducidas a reglas personalizadas en **Wazuh XML** (`IDs 100001–100099`) y validadas con `wazuh-logtest`.
4. **Calibración Quirúrgica (*Tuning*):** Medición de línea base, matriz de confusión y excepciones de mínimo privilegio documentadas en `tuning/TUNING_LOG.md`.
5. **Automatización de Triaje L1 (Python SOAR):** Extracción de IoCs (filtrando RFC 1918), enriquecimiento con APIs CTI (**AbuseIPDB / VirusTotal**) con caché local y *rate limiting*, generación de reportes alineados a **NIST SP 800-61** e integración continua con **GitHub Actions** (`pytest` + validación YAML/XML).

---

## 2. Flujo de Datos de Extremo a Extremo

```text
[1. EMULACIÓN CONTROLADA]  Atomic Red Team (MITRE ATT&CK: T1059.001, T1003.001, T1547.001, T1053.005, T1110.001)
            |
            v
[2. TELEMETRÍA ENDPOINT]   Windows (Sysmon + Security Logs) / Linux (Auditd + auth.log)
            |              -- Canal cifrado TLS vía Agente Wazuh (1514/TCP en red Host-Only) --
            v
[3. MOTOR SIEM / XDR]      Wazuh Manager (Decoders + local_rules.xml derivadas de Sigma)
            |              -- Indexación OpenSearch (9200/TCP) y Dashboard (443/TCP en 127.0.0.1) --
            v
[4. CALIBRACIÓN (TUNING)]  Línea base legítima -> Excepciones quirúrgicas documentadas (TUNING_LOG.md)
            |
            v
[5. AUTOMATIZACIÓN PYTHON] Motor de Triaje (Extracción IoCs + AbuseIPDB/VirusTotal + Caché SQLite + .env)
            |
            v
[6. SALIDA OPERATIVA]      Reporte de Triaje (Markdown/JSON) + Playbook de Respuesta NIST SP 800-61
```

---

## 3. Estructura del Repositorio

```text
soc-detection-lab-wazuh/
├── README.md
├── DISCLAIMER.md
├── .env.example
├── .github/workflows/          # CI: linter Python, pytest y validación YAML/XML
├── infrastructure/             # Docker Compose Wazuh, Sysmon XML y ossec.conf snippets
├── detections/                 # Reglas Sigma (YAML), local_rules.xml y casos de prueba JSON
├── emulation/                  # Matriz de ejecución Atomic Red Team
├── tuning/                     # Registro formal de calibración de falsos positivos
├── automation/                 # Paquete modular Python de triaje CTI y suite pytest
├── playbooks/                  # Guías operativas L1 alineadas a NIST SP 800-61
└── docs/                       # Arquitectura detallada (ARCHITECTURE.md) y evidencias sanitizadas
```

---

## 4. Hoja de Progreso y Métricas Verificables

> *Nota de integridad: Todas las métricas de esta tabla se completan exclusivamente con mediciones reales obtenidas durante la ejecución de cada fase en el laboratorio.*

| Fase | Entregable Principal | Estado |
| :--- | :--- | :--- |
| **Fase 1** | Cimientos Git, segmentación de red *Host-Only* y clúster Wazuh en Docker | En progreso |
| **Fase 2** | Instrumentación avanzada de endpoints (Windows Sysmon + Linux Auditd) | Pendiente |
| **Fase 3** | Emulación controlada de 5 técnicas MITRE ATT&CK y casos de prueba | Pendiente |
| **Fase 4** | Reglas Sigma + traducción Wazuh XML + validación `wazuh-logtest` | Pendiente |
| **Fase 5** | Línea base, análisis de falsos positivos y `TUNING_LOG.md` | Pendiente |
| **Fase 6** | Motor Python de triaje CTI, Playbook NIST SP 800-61 y CI en GitHub Actions | Pendiente |
