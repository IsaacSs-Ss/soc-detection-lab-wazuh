## Resumen Técnico del Cambio

Describe brevemente qué componente del laboratorio SOC o regla de detección introduce o ajusta este Pull Request:

- **Fase del Plan Maestro:** `Fase [1-6]`
- **Técnica(s) MITRE ATT&CK relacionadas (si aplica):** `Ej. T1059.001 / N/A`

---

## Checklist de Ingeniería y Seguridad (Obligatorio)

- [ ] **Higiene de Secretos:** Verifiqué con `git diff` que no se incluyen archivos `.env`, tokens de APIs (VirusTotal/AbuseIPDB), hashes reales ni llaves privadas TLS (`.pem`/`.key`).
- [ ] **Anonimización de Evidencias:** Cualquier log JSON o captura añadida en `detections/test-cases/` o `docs/evidence/` está libre de nombres de usuario reales del host e IPs públicas.
- [ ] **Validación Sintáctica y Operativa:** Las configuraciones YAML/XML, reglas Sigma/Wazuh (`wazuh-logtest`) o pruebas unitarias (`pytest`) pasan exitosamente en local y en GitHub Actions.
- [ ] **Conventional Commits:** Los mensajes de commit siguen el estándar semántico (`feat`, `fix`, `docs`, `test`, `chore`).
