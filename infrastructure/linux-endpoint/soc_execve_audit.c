/*
 * Proyecto: Laboratorio SOC, Detection Engineering y Triaje Automatizado
 * Archivo:  infrastructure/linux-endpoint/soc_execve_audit.c
 * Autor:    Isaac Sánchez Samaniego
 * Objetivo: Colector dinámico de respaldo en espacio de usuario para
 *           contenedores aislados sin pid: "host" donde kauditd restringe
 *           NETLINK_AUDIT fuera de init_pid_ns. Emite registros
 *           reales de cada ejecución de proceso (execve) hacia un socket UNIX
 *           local que escribe /var/log/audit/audit.log en formato auditd.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SOC_AUDIT_SOCK "/run/soc-audit.sock"
#define MAX_PAYLOAD 3584

static void sanitize_val(const char *src, char *dst, size_t dst_sz) {
    size_t j = 0;
    if (!src || dst_sz == 0) {
        if (dst_sz > 0) dst[0] = '\0';
        return;
    }
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\' || c == '|' || c < 0x20 || c > 0x7e) {
            dst[j++] = '_';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

__attribute__((constructor))
static void soc_capture_execve(int argc, char **argv) {
    char exe_path[PATH_MAX];
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exe_len <= 0) {
        return;
    }
    exe_path[exe_len] = '\0';

    /* Evitar bucles internos con los demonios propios del agente Wazuh y el relé */
    if (strncmp(exe_path, "/var/ossec/", 11) == 0) {
        return;
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOC_AUDIT_SOCK, sizeof(addr.sun_path) - 1);

    char cwd_buf[PATH_MAX];
    if (!getcwd(cwd_buf, sizeof(cwd_buf))) {
        strcpy(cwd_buf, "/");
    }

    char comm_raw[64] = "unknown";
    int cfd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
    if (cfd >= 0) {
        ssize_t n = read(cfd, comm_raw, sizeof(comm_raw) - 1);
        close(cfd);
        if (n > 0) {
            comm_raw[n] = '\0';
            char *nl = strchr(comm_raw, '\n');
            if (nl) *nl = '\0';
        }
    }

    char exe_clean[512];
    char cwd_clean[512];
    char comm_clean[64];
    sanitize_val(exe_path, exe_clean, sizeof(exe_clean));
    sanitize_val(cwd_buf, cwd_clean, sizeof(cwd_clean));
    sanitize_val(comm_raw, comm_clean, sizeof(comm_clean));

    char args_buf[1536];
    size_t pos = 0;
    int max_args = argc > 16 ? 16 : argc;
    if (max_args < 0) max_args = 0;
    args_buf[0] = '\0';

    for (int i = 0; i < max_args; i++) {
        char a_clean[192];
        sanitize_val(argv && argv[i] ? argv[i] : "", a_clean, sizeof(a_clean));
        int written = snprintf(
            args_buf + pos,
            sizeof(args_buf) - pos,
            "%sa%d=\"%s\"",
            (i == 0 ? "" : " "),
            i,
            a_clean
        );
        if (written < 0 || (size_t)written >= sizeof(args_buf) - pos) {
            break;
        }
        pos += (size_t)written;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char payload[MAX_PAYLOAD];
    int plen = snprintf(
        payload,
        sizeof(payload),
        "%ld.%03ld|%d|%d|%u|%u|%u|%u|%s|%s|%s|%d|%s",
        (long)ts.tv_sec,
        ts.tv_nsec / 1000000L,
        (int)getppid(),
        (int)getpid(),
        (unsigned)getuid(),
        (unsigned)geteuid(),
        (unsigned)getgid(),
        (unsigned)getegid(),
        comm_clean,
        exe_clean,
        cwd_clean,
        max_args,
        args_buf
    );

    if (plen > 0 && (size_t)plen < sizeof(payload)) {
        (void)sendto(fd, payload, (size_t)plen, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
    }
    close(fd);
}
