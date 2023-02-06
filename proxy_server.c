#define _GNU_SOURCE /* POLLRDHUP */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_util.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

struct sock_key {
    uint32_t local_ip;
    uint32_t local_port;
    uint32_t remote_ip;
    uint32_t remote_port;
};

struct header {
    uint32_t target_ip;
    uint16_t target_port;
} __attribute__((packed));

int redirect(int from_fd, int to_fd)
{
    char buf[BUFFER_SIZE];
    int n = recv(from_fd, buf, sizeof(buf), 0);
    // printf("recv from_fd = %d, to_fd = %d, n = %d\n", from_fd, to_fd, n);
    if (n < 0) {
        if (errno == ECONNRESET) {
            fprintf(stderr, "[!] ECONNRESET\n");
            return -1;
        }

        fprintf(stderr, "[?] recv failed, from_fd = %d, to_fd = %d, %s \n",
                from_fd, to_fd, strerror(errno));

        PFATAL("read()");
    }

    if (n == 0) {
        /* On TCP socket zero means EOF */
        fprintf(stderr, "[-] edge side EOF\n");
        return -1;
    }

    int m = send(to_fd, buf, n, MSG_NOSIGNAL);
    if (m < 0) {
        if (errno == ECONNRESET) {
            fprintf(stderr, "[!] ECONNRESET on origin\n");
            return -1;
        }
        if (errno == EPIPE) {
            fprintf(stderr, "[!] EPIPE on origin\n");
            return -1;
        }

        perror("send failed");
        return -1;
    }
    if (m == 0) {
        perror("send 0 bytes");
        return -1;
    }
    if (m != n) {
        int err;
        socklen_t err_len = sizeof(err);
        int r = getsockopt(to_fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
        if (r < 0) {
            PFATAL("getsockopt()");
        }
        errno = err;
        if (errno == EPIPE || errno == ECONNRESET) {
            return -1;
        }
        PFATAL("send()");
    }

    return 0;
}

void init_sock_key(int fd, struct sock_key *key)
{
    struct sockaddr_storage local, remote;
    net_getsockname(fd, &local);
    net_getpeername(fd, &remote);

    struct sockaddr_in *local_addr = (struct sockaddr_in *)&local;
    struct sockaddr_in *remote_addr = (struct sockaddr_in *)&remote;
    key->local_ip = local_addr->sin_addr.s_addr;
    key->local_port = ntohs(local_addr->sin_port);
    key->remote_ip = remote_addr->sin_addr.s_addr;
    key->remote_port = ((uint32_t)(remote_addr->sin_port)) << 16;
}

int sockmap_insert(int sockmap_fd, const struct sock_key *key, int *fd)
{
    if (bpf_map_update_elem(sockmap_fd, key, fd, BPF_NOEXIST)) {
        if (errno == EOPNOTSUPP) {
            perror("pushing closed socket to sockmap?");
            return -1;
        }
        PFATAL("bpf(MAP_UPDATE_ELEM)");
    }

    return 0;
}

int sockmap_delete(int sockmap_fd, const struct sock_key *key)
{
    if (bpf_map_delete_elem(sockmap_fd, key)) {
        if (errno == EINVAL) {
            fprintf(stderr, "[-] Removing closed sock from sockmap\n");
            return -1;
        } else {
            PFATAL("bpf(MAP_DELETE_ELEM, sock_map)");
        }
    }

    return 0;
}

void check_sockerr(int fd)
{
    int err;
    socklen_t err_len = sizeof(err);
    int r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
    if (r < 0) {
        PFATAL("getsockopt()");
    }
    errno = err;
    if (errno) {
        perror("sockmap fd");
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        FATAL("Usage: %s <listen:port>", argv[0]);
    }

#ifdef USE_SOCKMAP
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_kern.o", "sockmap");

    struct bpf_object *obj;
    struct bpf_program *prog;
    int bpf_prog_fd, sockmap_fd, prog_verdict_fd;
    if (bpf_prog_load(filename, BPF_PROG_TYPE_SK_SKB, &obj, &bpf_prog_fd)) {
        PFATAL("bpf_prog_load, failed");
    }

    sockmap_fd = bpf_object__find_map_fd_by_name(obj, "sock_map");
    if (sockmap_fd < 0) {
        PFATAL("bpf_object__find_map_fd_by_name, get sockmap_fd failed");
    }

    prog = bpf_object__find_program_by_title(obj, "prog_verdict");
    if (!prog) {
        PFATAL("bpf_object__find_program_by_title, get prog_verdict failed");
    }

    prog_verdict_fd = bpf_program__fd(prog);
    if (prog_verdict_fd < 0) {
        PFATAL("bpf_program__fd, get prog_verdict_fd failed");
    }

    if (bpf_prog_attach(prog_verdict_fd, sockmap_fd, BPF_SK_SKB_STREAM_VERDICT,
                        0)) {
        PFATAL("bpf_prog_attach, attach sockmap to prog_verdict failed");
    }
#endif

    struct sockaddr_storage listen;
    net_parse_sockaddr(&listen, argv[1]);
    fprintf(stderr, "[+] proxy server listen on %s\n", argv[1]);

    int listen_fd = net_bind_tcp(&listen);
    if (listen_fd < 0) {
        PFATAL("connect()");
    }

    for (;;) {
        struct sockaddr_storage frontend_peer;
        int frontend_fd = net_accept(listen_fd, &frontend_peer);

        struct header h;
        int n = recv(frontend_fd, &h, sizeof(h), 0);
        if (n <= 0) {
            close(frontend_fd);
            perror("parse header failed");
            continue;
        }

        struct sockaddr_storage backend_peer;
        memset(&backend_peer, 0, sizeof(backend_peer));

        struct sockaddr_in *backend_peer_in =
            (struct sockaddr_in *)&backend_peer;
        backend_peer_in->sin_addr.s_addr = h.target_ip;
        backend_peer_in->sin_port = h.target_port;
        backend_peer_in->sin_family = AF_INET;

        const char *tmp;
        char frontend_peer_addr[64] = {0}, backend_local_addr[64] = {0},
             front_local_addr[64] = {0};
        tmp = net_ntop(&frontend_peer);
        memcpy(frontend_peer_addr, tmp, strlen(tmp));

        int backend_fd = net_connect_tcp_blocking(
            (struct sockaddr_storage *)&backend_peer, 0);
        if (backend_fd < 0) {
            close(frontend_fd);
            continue;
        }

        struct sockaddr_storage frontend_local, backend_local;
        net_getsockname(frontend_fd, &frontend_local);
        net_getsockname(backend_fd, &backend_local);
        tmp = net_ntop(&frontend_local);
        memcpy(front_local_addr, tmp, strlen(tmp));
        tmp = net_ntop(&backend_local);
        memcpy(backend_local_addr, tmp, strlen(tmp));

        printf("[+] session start <%s,%s> --- <%s,%s> \n", frontend_peer_addr,
               front_local_addr, backend_local_addr, net_ntop(&backend_peer));

#ifdef USE_SOCKMAP
        struct sock_key frontend_key, backend_key;
        init_sock_key(frontend_fd, &frontend_key);
        init_sock_key(backend_fd, &backend_key);

        if (sockmap_insert(sockmap_fd, &frontend_key, &backend_fd)) {
            continue;
        }

        if (sockmap_insert(sockmap_fd, &backend_key, &frontend_fd)) {
            continue;
        }

        /* [*] Wait for the sockets to close. Let sockmap do the magic. */
        struct pollfd fds[2] = {
            {.fd = frontend_fd, .events = POLLRDHUP},
            {.fd = backend_fd, .events = POLLRDHUP},
        };
        poll(fds, 2, -1);

        check_sockerr(frontend_fd);
        check_sockerr(backend_fd);

#else
        struct pollfd fds[2] = {
            {.fd = frontend_fd, .events = POLLIN},
            {.fd = backend_fd, .events = POLLIN},
        };

        for (;;) {
            int nfds = poll(fds, 2, -1);
            if (nfds < 0) {
                break;
            }

            if (fds[0].revents == POLLIN) {
                if (redirect(frontend_fd, backend_fd)) {
                    break;
                }
            }

            if (fds[1].revents == POLLIN) {
                if (redirect(backend_fd, frontend_fd)) {
                    break;
                }
            }
        }
#endif

#ifdef USE_SOCKMAP
        sockmap_delete(sockmap_fd, &frontend_key);
        sockmap_delete(sockmap_fd, &backend_key);
#endif

        close(frontend_fd);
        close(backend_fd);

        printf("[+] session finish \n");
    }

    return 0;
}
