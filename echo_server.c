#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        FATAL("Usage: %s <listen:port>", argv[0]);
    }

    struct sockaddr_storage listen;
    net_parse_sockaddr(&listen, argv[1]);

    fprintf(stderr, "[+] echo server listen on %s \n", net_ntop(&listen));

    int sd = net_bind_tcp(&listen);
    if (sd < 0) {
        PFATAL("bind()");
    }

    for (;;) {
        struct sockaddr_storage client;
        int cd = net_accept(sd, &client);

        char buf[BUFFER_SIZE];
        uint64_t sum = 0;
        uint64_t t0 = realtime_now();
        while (1) {
            int n = recv(cd, buf, sizeof(buf), 0);
            // printf("recv n = %d\n", n);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == ECONNRESET) {
                    fprintf(stderr, "[!] ECONNRESET\n");
                    break;
                }
                PFATAL("read()");
            }

            if (n == 0) {
                /* On TCP socket zero means EOF */
                fprintf(stderr, "[-] edge side EOF\n");
                break;
            }

            sum += n;

            int m = send(cd, buf, n, MSG_NOSIGNAL);
            // printf("send m = %d\n", m);
            if (m < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == ECONNRESET) {
                    fprintf(stderr, "[!] ECONNRESET on origin\n");
                    break;
                }
                if (errno == EPIPE) {
                    fprintf(stderr, "[!] EPIPE on origin\n");
                    break;
                }
                PFATAL("send()");
            }
            if (m == 0) {
                break;
            }
            if (m != n) {
                int err;
                socklen_t err_len = sizeof(err);
                int r = getsockopt(cd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (r < 0) {
                    PFATAL("getsockopt()");
                }
                errno = err;
                if (errno == EPIPE || errno == ECONNRESET) {
                    break;
                }
                PFATAL("send()");
            }
        }

        close(cd);
        uint64_t t1 = realtime_now();

        fprintf(stderr, "[+] Read %lu Bytes in %.1fms\n", sum , (t1 - t0) / 1000000.);
    }

    return 0;
}
