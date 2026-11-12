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
 *
 * Egress by name (addiscorp/securecore#72), with SC_EGRESS_PORTS="443" and SC_EGRESS_HOST_PORT:
 * the guest has no DNS, so getaddrinfo() of a name (not an IP literal, not localhost) answers
 * one address of its own, 127.77.x.y, and remembers the name. A connect() to such an address on
 * an egress port becomes a vsock connect to the host's egress port, then one line, "<name>
 * <port>\n", and the host's answer: "OK\n" and then the bytes (TLS stays end to end; the name is
 * the one the program asked for), or "ERR <why>\n", which is ECONNREFUSED here. That handshake
 * is blocking, inside connect(), and the socket's O_NONBLOCK is put back after: a non-blocking
 * connect() then simply returns 0. getpeername() on it answers the 127.77.x.y address.
 *   cc -O2 -shared -fPIC -o libsc-vsock-connect.so vsock-connect.c -ldl -lpthread
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

#define MAX_PORTS 8
static int nports = -1, negress = 0;
static unsigned short ports[MAX_PORTS], egress[MAX_PORTS];
static unsigned int egress_host_port = 0;

static int parse_ports(const char *s, unsigned short *out) {
    int n = 0;
    while (s && *s && n < MAX_PORTS) {
        char *end;
        long p = strtol(s, &end, 10);
        if (end == s) break;
        if (p > 0 && p < 65536) out[n++] = (unsigned short)p;
        s = *end == ',' ? end + 1 : end;
    }
    return n;
}

static void load_ports(void) {
    nports = parse_ports(getenv("SC_VSOCK_PORTS"), ports);
    negress = parse_ports(getenv("SC_EGRESS_PORTS"), egress);
    const char *h = getenv("SC_EGRESS_HOST_PORT");
    egress_host_port = h ? (unsigned int)strtoul(h, NULL, 10) : 0;
    if (!egress_host_port) negress = 0;
}

/* Read once, in php-fpm's master at load time, then taken out of the environment: the workers are
 * forks of the master (the library and what it read stay mapped), and the image's pool has
 * clear_env = no, so without this every program a PHP script starts would inherit the preload
 * and the list of ports it forwards (#86 review). */
__attribute__((constructor)) static void init(void) {
    load_ports();
    unsetenv("LD_PRELOAD");
    unsetenv("SC_VSOCK_PORTS");
    unsetenv("SC_EGRESS_PORTS");
    unsetenv("SC_EGRESS_HOST_PORT");
}

static int listed(unsigned short p) {
    if (nports < 0) load_ports();
    for (int i = 0; i < nports; i++)
        if (ports[i] == p) return 1;
    return 0;
}

static int egress_port(unsigned short p) {
    if (nports < 0) load_ports();
    for (int i = 0; i < negress; i++)
        if (egress[i] == p) return 1;
    return 0;
}

/* The names getaddrinfo() answered, by the address it gave each: 127.77.0.0 + index + 1. */
#define MAX_NAMES 4096
#define NAME_NET 0x7f4d0000u /* 127.77.0.0/16 */
static char *names[MAX_NAMES];
static int nnames = 0;
static pthread_mutex_t names_lock = PTHREAD_MUTEX_INITIALIZER;

/* The address for `name`, 0 when the table is full. */
static unsigned int name_addr(const char *name) {
    unsigned int a = 0;
    pthread_mutex_lock(&names_lock);
    for (int i = 0; i < nnames; i++)
        if (strcasecmp(names[i], name) == 0) { a = NAME_NET + (unsigned int)i + 1; break; }
    if (!a && nnames < MAX_NAMES) {
        char *copy = strdup(name);
        if (copy) { names[nnames] = copy; a = NAME_NET + (unsigned int)nnames + 1; nnames++; }
    }
    pthread_mutex_unlock(&names_lock);
    return a;
}

/* The name behind a 127.77.x.y address (host order), or NULL. Copied into `out`. */
static int addr_name(unsigned int a, char *out, size_t len) {
    int ok = 0;
    pthread_mutex_lock(&names_lock);
    unsigned int i = a - NAME_NET - 1;
    if ((a & 0xffff0000u) == NAME_NET && i < (unsigned int)nnames) {
        snprintf(out, len, "%s", names[i]);
        ok = 1;
    }
    pthread_mutex_unlock(&names_lock);
    return ok;
}

/* Whether getaddrinfo() should answer `node` itself: a name that isn't an IP literal or a
 * loopback name, when there are egress ports. */
static int ours(const char *node) {
    if (nports < 0) load_ports();
    if (!negress || !node || !*node || strlen(node) > 253) return 0;
    struct in6_addr a6;
    struct in_addr a4;
    if (inet_pton(AF_INET, node, &a4) == 1 || inet_pton(AF_INET6, node, &a6) == 1) return 0;
    if (strcasecmp(node, "localhost") == 0 || strcasecmp(node, "localhost.") == 0) return 0;
    for (const char *p = node; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_'))
            return 0;
    return 1;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    static int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
    if (!real) real = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
    if (!ours(node) || (hints && hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET) || (hints && (hints->ai_flags & AI_NUMERICHOST)))
        return real(node, service, hints, res);
    long port = 0;
    if (service && *service) {
        char *end;
        port = strtol(service, &end, 10);
        if (*end || port < 0 || port > 65535) return real(node, service, hints, res);
    }
    unsigned int a = name_addr(node);
    if (!a) return EAI_FAIL;
    /* One block, as glibc's own results are, so its freeaddrinfo() frees it. */
    struct addrinfo *ai = calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
    if (!ai) return EAI_MEMORY;
    struct sockaddr_in *in = (struct sockaddr_in *)(ai + 1);
    in->sin_family = AF_INET;
    in->sin_port = htons((unsigned short)port);
    in->sin_addr.s_addr = htonl(a);
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = hints && hints->ai_protocol ? hints->ai_protocol : IPPROTO_TCP;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)in;
    if (hints && (hints->ai_flags & AI_CANONNAME)) ai->ai_canonname = strdup(node);
    *res = ai;
    return 0;
}

/* The egress handshake on `fd` (a fresh blocking vsock socket in its place): 0 or -1/errno. */
static int egress_connect(int fd, const char *name, unsigned short port,
                          int (*real)(int, const struct sockaddr *, socklen_t)) {
    struct sockaddr_vm vm;
    memset(&vm, 0, sizeof vm);
    vm.svm_family = AF_VSOCK;
    vm.svm_cid = VMADDR_CID_HOST;
    vm.svm_port = egress_host_port;
    if (real(fd, (const struct sockaddr *)&vm, sizeof vm) < 0) return -1;
    struct timeval tv = {15, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char line[300];
    int n = snprintf(line, sizeof line, "%s %u\n", name, (unsigned)port);
    if (n <= 0 || n >= (int)sizeof line || write(fd, line, (size_t)n) != n) { errno = ECONNREFUSED; return -1; }
    /* The answer, byte by byte: nothing after it is consumed. */
    char ans[300];
    size_t got = 0;
    while (got < sizeof ans - 1) {
        ssize_t r = read(fd, ans + got, 1);
        if (r <= 0) { errno = ECONNREFUSED; return -1; }
        if (ans[got++] == '\n') break;
    }
    ans[got] = 0;
    struct timeval none = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none);
    if (strcmp(ans, "OK\n") != 0) { errno = ECONNREFUSED; return -1; }
    return 0;
}

/* Whether `fd` is an egress socket: vsock, connected to the host's egress port. */
static int is_egress(int fd) {
    static int (*peer)(int, struct sockaddr *, socklen_t *);
    if (!peer) peer = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getpeername");
    if (!negress) return 0;
    int dom;
    socklen_t dl = sizeof dom;
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &dl) != 0 || dom != AF_VSOCK) return 0;
    struct sockaddr_vm vm;
    socklen_t l = sizeof vm;
    return peer(fd, (struct sockaddr *)&vm, &l) == 0 && vm.svm_port == egress_host_port;
}

/* An AF_INET address for an egress socket's ends: its program made an AF_INET socket. */
static int fake_inet(struct sockaddr *sa, socklen_t *len, unsigned int addr) {
    struct sockaddr_in in;
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(addr);
    socklen_t n = *len < sizeof in ? *len : sizeof in;
    memcpy(sa, &in, n);
    *len = sizeof in;
    return 0;
}

int getpeername(int fd, struct sockaddr *sa, socklen_t *len) {
    static int (*real)(int, struct sockaddr *, socklen_t *);
    if (!real) real = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getpeername");
    if (sa && len && is_egress(fd)) return fake_inet(sa, len, NAME_NET);
    return real(fd, sa, len);
}

int getsockname(int fd, struct sockaddr *sa, socklen_t *len) {
    static int (*real)(int, struct sockaddr *, socklen_t *);
    if (!real) real = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getsockname");
    if (sa && len && is_egress(fd)) return fake_inet(sa, len, INADDR_LOOPBACK);
    return real(fd, sa, len);
}

int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    static int (*real)(int, const struct sockaddr *, socklen_t);
    if (!real) real = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    if (sa && sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        unsigned short port = ntohs(in->sin_port);
        char name[256];
        if (egress_port(port) && addr_name(ntohl(in->sin_addr.s_addr), name, sizeof name)) {
            int fl = fcntl(fd, F_GETFL), fdfl = fcntl(fd, F_GETFD);
            if (fl < 0 || fdfl < 0) return -1;
            int v = socket(AF_VSOCK, SOCK_STREAM, 0);
            if (v < 0) return -1;
            if (dup3(v, fd, (fdfl & FD_CLOEXEC) ? O_CLOEXEC : 0) < 0) {
                int e = errno;
                close(v);
                errno = e;
                return -1;
            }
            close(v);
            int r = egress_connect(fd, name, port, real);
            int e = errno;
            if (fl & O_NONBLOCK) fcntl(fd, F_SETFL, fl);
            errno = e;
            return r;
        }
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

/* A program PHP runs that the guest doesn't have (addiscorp/securecore#101): the guest is the
 * host's own PHP, and the programs PHP runs (the shell, sendmail, ImageMagick, ghostscript) are
 * captured only when the host has them. An exec that fails with ENOENT for a name found in no
 * PATH folder says so on stderr, once per name in a process: php-fpm's workers' stderr goes to
 * the launcher's log (catch_workers_output), and a shell PHP started inherits it. An exec of a
 * name some later PATH folder has (a shell trying each folder) says nothing. */
static void say_missing(const char *path) {
    static char last[256];
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (!*name || strcmp(last, name) == 0) return;
    const char *p = getenv("PATH");
    if (!p) p = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    char buf[512];
    while (*p) {
        const char *end = strchr(p, ':');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n && n + strlen(name) + 2 < sizeof buf) {
            memcpy(buf, p, n);
            buf[n] = '/';
            strcpy(buf + n + 1, name);
            if (access(buf, X_OK) == 0) return;
        }
        p += n + (end ? 1 : 0);
        if (!end) break;
    }
    if (path[0] == '/' && access(path, F_OK) == 0) return;
    snprintf(last, sizeof last, "%s", name);
    dprintf(2, "securecore-guest: %s isn't in the guest: the host had no such program to capture (PHP tried to run %s)\n", name, path);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real)(const char *, char *const[], char *const[]);
    if (!real) real = (int (*)(const char *, char *const[], char *const[]))dlsym(RTLD_NEXT, "execve");
    int r = real(path, argv, envp);
    int e = errno;
    if (e == ENOENT && path) say_missing(path);
    errno = e;
    return r;
}

int execv(const char *path, char *const argv[]) {
    static int (*real)(const char *, char *const[]);
    if (!real) real = (int (*)(const char *, char *const[]))dlsym(RTLD_NEXT, "execv");
    int r = real(path, argv);
    int e = errno;
    if (e == ENOENT && path) say_missing(path);
    errno = e;
    return r;
}

int execvp(const char *file, char *const argv[]) {
    static int (*real)(const char *, char *const[]);
    if (!real) real = (int (*)(const char *, char *const[]))dlsym(RTLD_NEXT, "execvp");
    int r = real(file, argv);
    int e = errno;
    if (e == ENOENT && file) say_missing(file);
    errno = e;
    return r;
}
