# =============================================================================
# Proyecto: Laboratorio SOC, Detection Engineering y Triaje Automatizado
# Archivo:  infrastructure/linux-endpoint/Dockerfile
# Autor:    Isaac Sánchez Samaniego
# Objetivo: Endpoint Linux reproducible (Ubuntu 24.04) instrumentado con
#           Wazuh Agent v4.9.2, OpenSSH Server aislado, Rsyslog y telemetría
#           de ejecución de procesos (auditd / execve) en soc_internal_net.
# =============================================================================

FROM ubuntu:24.04 AS audit-sensor-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

COPY soc_execve_audit.c /tmp/soc_execve_audit.c
RUN gcc -O2 -Wall -Wextra -fPIC -shared -o /tmp/libsoc_execve_audit.so /tmp/soc_execve_audit.c

# -----------------------------------------------------------------------------
# Imagen final de operación del endpoint monitoreado
# -----------------------------------------------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        openssh-server \
        openssh-client \
        rsyslog \
        auditd \
        procps \
        python3 && \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 0644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update -qq && \
    WAZUH_MANAGER="wazuh.manager" apt-get install -y --no-install-recommends wazuh-agent=4.9.2-1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Endurecimiento de cuentas: bloqueo de root y cuenta señuelo bloqueada sin contraseña activa (Fase 3 T1110.001)
RUN passwd -l root && \
    useradd -r -M -d /nonexistent -s /usr/sbin/nologin soc_audit_target && \
    passwd -l soc_audit_target && \
    mkdir -p /run/sshd /var/log/audit && \
    chmod 0755 /run/sshd && \
    chmod 0700 /var/log/audit

# Configuración de Rsyslog para contenedor (formato tradicional BSD compatible con Wazuh y sin lectura /proc/kmsg)
RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf && \
    printf '\n$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat\n' >> /etc/rsyslog.d/00-traditional-format.cfg

# Endurecimiento de OpenSSH Server (solo escucha interna en soc_internal_net; sin credenciales débiles activas)
RUN printf '%s\n' \
    'Port 22' \
    'Protocol 2' \
    'PermitRootLogin no' \
    'PasswordAuthentication yes' \
    'PermitEmptyPasswords no' \
    'KbdInteractiveAuthentication no' \
    'UsePAM yes' \
    'SyslogFacility AUTH' \
    'LogLevel INFO' \
    'MaxAuthTries 6' \
    'X11Forwarding no' \
    'AllowTcpForwarding no' \
    > /etc/ssh/sshd_config.d/99-soc-lab.cfg

# Reglas de auditoría execve, colector dinámico de respaldo para sub-namespaces PID (WSL2) y configuración Wazuh
COPY --from=audit-sensor-builder /tmp/libsoc_execve_audit.so /usr/local/lib/libsoc_execve_audit.so
RUN chmod 0755 /usr/local/lib/libsoc_execve_audit.so

COPY soc-execve.rules /etc/audit/rules.d/soc-execve.rules
COPY soc_auditd_relay.py /usr/local/sbin/soc_auditd_relay.py
COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0640 /etc/audit/rules.d/soc-execve.rules && \
    chmod 0750 /usr/local/sbin/soc_auditd_relay.py && \
    chown root:wazuh /var/ossec/etc/ossec.conf && \
    chmod 0640 /var/ossec/etc/ossec.conf && \
    chmod 0755 /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
