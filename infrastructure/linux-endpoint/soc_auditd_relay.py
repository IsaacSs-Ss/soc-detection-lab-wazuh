#!/usr/bin/env python3
"""
Proyecto: Laboratorio SOC, Detection Engineering y Triaje Automatizado
Archivo:  infrastructure/linux-endpoint/soc_auditd_relay.py
Autor:    Isaac Sánchez Samaniego
Objetivo: Demonio receptor local de eventos execve cuando el kernel anfitrión
          opera en sub-namespace PID (ej. WSL2) e impide cargar reglas vía
          NETLINK_AUDIT. Escribe registros estructurados auditd en
          /var/log/audit/audit.log preservando permisos 0600 root:root.
"""

import os
import signal
import socket
import sys

SOCK_PATH = "/run/soc-audit.sock"
AUDIT_LOG = "/var/log/audit/audit.log"


def main() -> int:
    os.makedirs("/var/log/audit", mode=0o700, exist_ok=True)
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)

    log_fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.chmod(AUDIT_LOG, 0o600)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o666)

    running = True

    def handle_stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    seq = 100
    while running:
        try:
            raw, _ = srv.recvfrom(4096)
        except InterruptedError:
            continue
        except OSError:
            if not running:
                break
            continue

        try:
            line = raw.decode("utf-8", errors="replace")
            parts = line.split("|", 11)
            if len(parts) != 12:
                continue

            ts_str, ppid, pid, uid, euid, gid, egid, comm, exe, cwd, argc, args_str = parts
            if exe == "/usr/bin/pgrep" or (comm == "python3" and "soc_auditd_relay.py" in args_str):
                continue

            seq += 1
            audit_id = f"audit({ts_str}:{seq})"
            record = (
                f'type=SYSCALL msg={audit_id}: arch=c000003e syscall=59 success=yes exit=0 '
                f'a0=0 a1=0 a2=0 a3=0 items=1 ppid={ppid} pid={pid} auid=4294967295 '
                f'uid={uid} gid={gid} euid={euid} suid={euid} fsuid={euid} '
                f'egid={egid} sgid={egid} fsgid={egid} tty=(none) ses=4294967295 '
                f'comm="{comm}" exe="{exe}" key="soc_execve"\n'
                f'type=EXECVE msg={audit_id}: argc={argc} {args_str}\n'
                f'type=CWD msg={audit_id}: cwd="{cwd}"\n'
                f'type=PATH msg={audit_id}: item=0 name="{exe}" nametype=NORMAL\n'
                f'type=EOE msg={audit_id}: \n'
            )
            os.write(log_fd, record.encode("utf-8"))
        except Exception:
            continue

    srv.close()
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    os.close(log_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
