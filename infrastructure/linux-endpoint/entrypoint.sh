#!/usr/bin/env bash
# =============================================================================
# Proyecto: Laboratorio SOC, Detection Engineering y Triaje Automatizado
# Archivo:  infrastructure/linux-endpoint/entrypoint.sh
# Autor:    Isaac Sánchez Samaniego
# Objetivo: Inicialización ordenada de Rsyslog, telemetría Auditd (execve),
#           OpenSSH Server interno y Wazuh Agent v4.9.2 en soc-linux-endpoint.
# =============================================================================
set -euo pipefail

echo "[soc-linux-endpoint] Inicializando archivos de registro..."
mkdir -p /var/log/audit /run/sshd
chmod 0700 /var/log/audit
touch /var/log/audit/audit.log /var/log/auth.log
chmod 0600 /var/log/audit/audit.log
chown syslog:adm /var/log/auth.log
chmod 0640 /var/log/auth.log

echo "[soc-linux-endpoint] Iniciando servicio rsyslogd..."
rm -f /run/rsyslogd.pid
rsyslogd

USE_USERLAND_RELAY=0
echo "[soc-linux-endpoint] Configurando telemetría de ejecución (execve)..."
if auditd 2>/dev/null && auditctl -R /etc/audit/rules.d/soc-execve.rules >/dev/null 2>&1; then
    echo "[soc-linux-endpoint] auditd nativo del kernel activo con regla soc_execve."
    rm -f /etc/ld.so.preload
else
    echo "[soc-linux-endpoint] Sub-namespace PID detectado en kernel anfitrión (NETLINK_AUDIT restringido); activando relé auditd de espacio de usuario..."
    USE_USERLAND_RELAY=1
    python3 /usr/local/sbin/soc_auditd_relay.py &
    for _ in $(seq 1 20); do
        [ -S /run/soc-audit.sock ] && break
        sleep 0.1
    done
    echo "/usr/local/lib/libsoc_execve_audit.so" > /etc/ld.so.preload
    chmod 0644 /etc/ld.so.preload
fi

echo "[soc-linux-endpoint] Generando claves de host SSH efímeras e iniciando sshd en soc_internal_net..."
ssh-keygen -A >/dev/null 2>&1
/usr/sbin/sshd

echo "[soc-linux-endpoint] Iniciando Wazuh Agent v4.9.2 hacia wazuh.manager..."
/var/ossec/bin/wazuh-control start

cleanup() {
    echo "[soc-linux-endpoint] Deteniendo servicios ordenadamente..."
    rm -f /etc/ld.so.preload
    /var/ossec/bin/wazuh-control stop || true
    pkill -TERM -x sshd || pkill -TERM -f '/usr/sbin/sshd' || true
    pkill -TERM -x rsyslogd || true
    pkill -TERM -f soc_auditd_relay.py || true
    exit 0
}
trap cleanup SIGTERM SIGINT

echo "[soc-linux-endpoint] Endpoint operativo y monitoreado."
while true; do
    if ! pgrep -x wazuh-agentd >/dev/null 2>&1; then
        echo "[soc-linux-endpoint] Error crítico: wazuh-agentd se detuvo." >&2
        exit 1
    fi
    if ! pgrep -x sshd >/dev/null 2>&1 && ! pgrep -f '/usr/sbin/sshd' >/dev/null 2>&1; then
        echo "[soc-linux-endpoint] Error crítico: sshd se detuvo." >&2
        exit 1
    fi
    if ! pgrep -x rsyslogd >/dev/null 2>&1; then
        echo "[soc-linux-endpoint] Error crítico: rsyslogd se detuvo." >&2
        exit 1
    fi
    if [ "$USE_USERLAND_RELAY" -eq 1 ] && ! pgrep -f soc_auditd_relay.py >/dev/null 2>&1; then
        echo "[soc-linux-endpoint] Error crítico: soc_auditd_relay.py se detuvo." >&2
        exit 1
    fi
    sleep 15 &
    wait $!
done
