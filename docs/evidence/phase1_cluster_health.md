# Evidencia Verificable — Fase 1: Salud del Clúster Wazuh Single-Node y Vinculación de Red

## 1. Estado de Salud de Contenedores (`docker ps`)

Verificación ejecutada tras el aprovisionamiento de certificados X.509 internos y hashes `bcrypt` mediante `infrastructure/scripts/setup-lab-env.ps1`:

```text
NAMES                 STATUS                   PORTS
soc-wazuh-dashboard   Up 2 minutes (healthy)   127.0.0.1:443->5601/tcp
soc-wazuh-manager     Up 2 minutes (healthy)   <HOST_ONLY_IP>:1514-1515->1514-1515/tcp, 127.0.0.1:55000->55000/tcp
soc-wazuh-indexer     Up 3 minutes (healthy)   127.0.0.1:9200->9200/tcp
```

### Controles Validados

* **Tres servicios principales en estado `(healthy)`:**
  * `soc-wazuh-indexer`: API OpenSearch `9200/TCP` autenticada con hashes `bcrypt` únicos y clúster en estado operativo.
  * `soc-wazuh-manager`: Demonios `wazuh-analysisd`, `wazuh-remoted`, `wazuh-authd` y `wazuh-apid` activos; regla centinela personalizada `ID 100099` propagada correctamente en `/var/ossec/etc/rules/local_rules.xml`.
  * `soc-wazuh-dashboard`: Consola web HTTPS respondiendo `HTTP/1.1 200 OK` (`osd-name: wazuh.dashboard`) exclusivamente en `127.0.0.1:443`.
* **Cero exposición en interfaz LAN/Wi-Fi:** Ningún puerto del SIEM escucha en `0.0.0.0`; la ingesta de agentes (`1514/1515 TCP`) permanece aislada en la interfaz virtual *Host-Only*.

---

## 2. Respuesta HTTPS del Wazuh Dashboard (`127.0.0.1:443`)

```http
HTTP/1.1 200 OK
content-security-policy: script-src 'unsafe-eval' 'self'; worker-src blob: 'self'; style-src 'unsafe-inline' 'self'
osd-name: wazuh.dashboard
```
