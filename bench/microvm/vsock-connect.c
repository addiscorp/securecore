/* libsc-vsock-connect.so: php-fpm's connect() to 127.0.0.1:<port> becomes a vsock connect to the
 * host (CID 2) on the same port, in the microVM guest (addiscorp/securecore#70). Loaded with
 * LD_PRELOAD into php-fpm only, with SC_VSOCK_PORTS="3306" (a comma-separated list): mysqlnd's
 * own socket then carries the MySQL protocol straight over vsock, with no forwarder process in
 * the guest. Any other connect() is untouched, and the guest still has no network device.
 *
 * How: the AF_INET socket mysqlnd made is replaced in place (dup3 onto the same fd number, same
 * O_NONBLOCK and FD_CLOEXEC) by an AF_VSOCK one, then connected; a non-blocking connect returns
 * EINPROGRESS and completes through poll + SO_ERROR as TCP's does. setsockopt(IPPROTO_TCP, ...)
 * (TCP_NODELAY) on such a socket is accepted and ignored: vsock has no Nagle to turn off.
 *   cc -O2 -shared -fPIC -o libsc-vsock-connect.so vsock-connect.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

#define MAX_PORTS 8
static int nports = -1;
static unsigned short ports[MAX_PORTS];

static void load_ports(void) {
    const char *s = getenv("SC_VSOCK_PORTS");
    nports = 0;
    while (s && *s && nports < MAX_PORTS) {
        char *end;
        long p = strtol(s, &end, 10);
        if (end == s) break;
        if (p > 0 && p < 65536) ports[nports++] = (unsigned short)p;
        s = *end == ',' ? end + 1 : end;
    }
}

/* Read once, in php-fpm's master at load time: its workers are forks with clear_env, so the
 * variable is gone by the time a worker connects. */
__attribute__((constructor)) static void init(void) { load_ports(); }

static int listed(unsigned short p) {
    if (nports < 0) load_ports();
    for (int i = 0; i < nports; i++)
        if (ports[i] == p) return 1;
    return 0;
}

int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real) real = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    if (sa && sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        unsigned short port = ntohs(in->sin_port);
        if (in->sin_addr.s_addr == htonl(INADDR_LOOPBACK) && listed(port)) {
            int fl = fcntl(fd, F_GETFL), fdfl = fcntl(fd, F_GETFD);
            if (fl < 0 || fdfl < 0) return -1;
            int v = socket(AF_VSOCK, SOCK_STREAM | ((fl & O_NONBLOCK) ? SOCK_NONBLOCK : 0), 0);
            if (v < 0) return -1;
            if (dup3(v, fd, (fdfl & FD_CLOEXEC) ? O_CLOEXEC : 0) < 0) {
                int e = errno;
                close(v);
                errno = e;
                return -1;
            }
            close(v);
            struct sockaddr_vm vm;
            memset(&vm, 0, sizeof vm);
            vm.svm_family = AF_VSOCK;
            vm.svm_cid = VMADDR_CID_HOST;
            vm.svm_port = port;
            return real(fd, (const struct sockaddr *)&vm, sizeof vm);
        }
    }
    return real(fd, sa, len);
}

int setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    static int (*real)(int, int, int, const void *, socklen_t);
    if (!real) real = (int (*)(int, int, int, const void *, socklen_t))dlsym(RTLD_NEXT, "setsockopt");
    if (level == IPPROTO_TCP) {
        int dom;
        socklen_t l = sizeof dom;
        if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &l) == 0 && dom == AF_VSOCK) return 0;
    }
    return real(fd, level, name, val, len);
}
