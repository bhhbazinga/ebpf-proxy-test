#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

struct header {
    uint32_t target_ip;
    uint16_t target_port;
} __attribute__((packed));

int main(int argc, char **argv)
{
    if (argc < 3) {
        FATAL(
            "Usage: %s <proxy:port> <target:port> <amount in KiB> <number of "
            "bursts>",
            argv[0]);
    }

    struct sockaddr_storage proxy;
    net_parse_sockaddr(&proxy, argv[1]);

    struct sockaddr_storage target;
    net_parse_sockaddr(&target, argv[2]);

    uint64_t burst_sz = 1 * 1024 * 1024;  // 1MiB
    if (argc > 3) {
        char *endptr;
        double ts = strtod(argv[3], &endptr);
        if (ts < 0 || *endptr != '\0') {
            FATAL("Can't parse number %s", argv[3]);
        }

        burst_sz = ts;  // In KiB
    }

    long burst_count = 1;
    if (argc > 3) {
        char *endptr;
        burst_count = strtol(argv[4], &endptr, 10);
        if (burst_count < 0 || *endptr != '\0') {
            FATAL("Can't parse number %s", argv[4]);
        }
    }

    fprintf(stderr, "[+] Sending %ld blocks of %lu Bytes to %s\n", burst_count,
            burst_sz, net_ntop(&proxy));

    int fd = net_connect_tcp_blocking(&proxy, 0);
    if (fd < 0) {
        PFATAL("connect()");
    }

    struct sockaddr_in *target_in = (struct sockaddr_in *)&target;
    struct header h = {
        .target_ip = target_in->sin_addr.s_addr,
        .target_port = target_in->sin_port,
    };

    int n = send(fd, &h, sizeof(h), MSG_NOSIGNAL);
    if (n < 0) {
        PFATAL("send header failed");
    }
    sleep(1);

    char tx_buf[BUFFER_SIZE];
    char rx_buf[BUFFER_SIZE];
    memset(tx_buf, 'a', sizeof(tx_buf));

    uint64_t total_t0 = realtime_now();
    for (int i = 0; i < burst_count; i++) {
        uint64_t t0 = realtime_now();
        int n = send(fd, &tx_buf, burst_sz, MSG_NOSIGNAL);
        // printf("burst_sz = %lu, n = %d \n", burst_sz, n);
        if (n < 0) {
            if (errno == ECONNRESET) {
                fprintf(stderr, "[!] ECONNRESET\n");
                break;
            }
            if (errno == EPIPE) {
                fprintf(stderr, "[!] EPIPE\n");
                break;
            }

            PFATAL("send()");
        }

        if (n == 0) {
            // perror("send 0 bytes");
            PFATAL("send 0 bytes");
        }

        n = recv(fd, &rx_buf, sizeof(rx_buf), 0);
        if (n < 0) {
            PFATAL("recvmsg()");
        }

        if (n == 0) {
            PFATAL("?");
        }
        uint64_t t1 = realtime_now();
        printf("%lu\n", (t1 - t0) / 1000);
    }

    uint64_t total_t1 = realtime_now();

    close(fd);
    fprintf(stderr,
            "[+] Wrote %ld bursts of %lu Btyes in %lums\n, rtt_avg = %luus \n",
            burst_count, burst_sz, (total_t1 - total_t0) / 1000 / 1000,
            (total_t1 - total_t0) / 1000 / burst_count);
    return 0;
}
