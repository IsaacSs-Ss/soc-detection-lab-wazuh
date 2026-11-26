# Aviso Legal, Ético y de Operación Segura (Disclaimer)

## 1. Propósito Educativo y Defensivo (Blue Team)

Este repositorio documenta el diseño, despliegue, instrumentación, ingeniería de detección, calibración de alertas (*tuning*) y automatización de triaje de un **Laboratorio de Centro de Operaciones de Seguridad (SOC)** con fines estrictamente educativos, de investigación defensiva y demostración profesional.

## 2. Aislamiento Estricto de Red

Todas las pruebas de emulación controlada de adversarios basadas en el marco **MITRE ATT&CK** y **Atomic Red Team** documentadas en este proyecto se ejecutan **exclusivamente dentro de una topología virtual aislada (*Host-Only*)** bajo control propio:

* **Sin exposición a Internet ni a redes de terceros:** Los endpoints de prueba operan en un segmento virtual privado sin puerta de enlace predeterminada (*Default Gateway*) durante la ejecución de pruebas atómicas.
* **Vinculación restringida de servicios:** Los puertos administrativos y de consulta (`443/TCP`, `9200/TCP`, `55000/TCP`) se vinculan exclusivamente a `127.0.0.1` en el equipo anfitrión, evitando exposición inadvertida en redes domésticas o corporativas.
* **Cero malware activo:** Ningún archivo de este repositorio contiene *malware* funcional, *exploits* armados ni herramientas ofensivas no autorizadas; únicamente se emplean comandos nativos de sistema operativo auditablemente benignos para validar telemetría defensiva.

## 3. Privacidad, Sanitización y Manejo de Secretos

* **Cero credenciales expuestas:** Todas las claves de API de inteligencia de amenazas (AbuseIPDB, VirusTotal) y contraseñas del clúster SIEM se gestionan mediante variables de entorno locales excluidas del control de versiones (`.gitignore`).
* **Anonimización de evidencias:** Todos los registros de prueba (`detections/test-cases/`) y capturas operativas (`docs/evidence/`) han sido revisados y sanitizados para eliminar nombres de usuario personales, identificadores de hardware del anfitrión y direcciones IP públicas.

## 4. Exención de Responsabilidad

El autor no se hace responsable del uso indebido de la información, configuraciones o scripts contenidos en este repositorio fuera de entornos de laboratorio debidamente autorizados. Cualquier prueba de seguridad debe contar siempre con autorización explícita y por escrito del propietario de los activos.
