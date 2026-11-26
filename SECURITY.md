# Política de Seguridad y Operación del Laboratorio

## Alcance del Repositorio

Este proyecto constituye un entorno controlado de **Ingeniería de Detección (*Detection Engineering*), Monitoreo SIEM/XDR y Automatización SOAR** diseñado exclusivamente para operación en redes virtuales aisladas (*Host-Only*).

## Controles de Seguridad Implementados en el Código

1. **Gestión Estricta de Secretos:** Ninguna contraseña operativa de Wazuh/OpenSearch ni claves de APIs de *Threat Intelligence* se almacena en el historial de Git. Toda credencial se inyecta mediante archivos `.env` locales ignorados por `.gitignore`.
2. **Superficie de Red Mínima:** Los servicios de administración (`443/TCP`, `9200/TCP`, `55000/TCP`) se vinculan por diseño a `127.0.0.1` y los puertos de ingesta de agentes (`1514/TCP`, `1515/TCP`) únicamente a la interfaz virtual aislada del laboratorio.
3. **Auditoría Continua en CI:** El flujo `.github/workflows/ci-validation.yml` inspecciona automáticamente cada *push* y *Pull Request* para bloquear certificados privados, archivos `.env` o contraseñas predeterminadas conocidas.

## Reporte de Hallazgos o Mejoras

Si identificas una posible mejora de endurecimiento (*hardening*), un caso de evasión en alguna regla Sigma/Wazuh o un problema en las dependencias de Python, por favor abre un *Issue* describiendo el escenario técnico y el impacto defensivo esperado.
