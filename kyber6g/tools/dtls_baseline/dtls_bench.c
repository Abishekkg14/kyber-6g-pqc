/* dtls_bench: DTLS 1.3 handshakes with a hybrid post-quantum key exchange and ML-DSA-87 mutual authentication
 * (wolfSSL), as the baseline that the manuscript review of 14 October 2026 asked for: what a standard secure transport
 * costs on the same test bed as the Kyber-6G link.
 *
 *   server:  dtls_bench server PORT COOKIE(0|1) OWN_CERT OWN_KEY PEER_CERT
 *   client:  dtls_bench client HOST PORT_COOKIE PORT_NOCOOKIE OWN_CERT OWN_KEY PEER_CERT
 *
 * Key exchange: the hybrid group SecP384r1MLKEM1024 (ML-KEM-1024 with ECDH on P-384, security category 5). The client
 * asks for its key share in the first ClientHello (wolfSSL_UseKeyShare), but wolfSSL 5.9.4 sends a first ClientHello of
 * 139 bytes without it and sends the share (two fragments) only after the server's HelloRetryRequest, with or without
 * a cookie: the recorded flows of 14 October 2026 show it, and it costs every full handshake one round trip.
 * Authentication: each end has a self-signed ML-DSA-87 certificate and
 * trusts exactly the other's (the counterpart of the link's pinned keys). Cipher: TLS_AES_256_GCM_SHA384.
 * Timers: wolfSSL's own DTLS 1.3 timers (1 s initial, doubled after each timeout, a quarter of it while a flight is
 * partly acknowledged), driven through the I/O callbacks below exactly as wolfSSL's built-in socket I/O drives them.
 *
 * The client reads commands from standard input and writes one JSON line per handshake, so a measurement program can
 * interleave these handshakes with others:
 *   "full"        full handshake on PORT_COOKIE (the server sends a HelloRetryRequest with a cookie first)
 *   "full_nc"     full handshake on PORT_NOCOOKIE (no cookie round trip)
 *   "psk_ke"      resumption with the ticket of the last full handshake, PSK only (no new key exchange)
 *   "psk_dhe_ke"  resumption with that ticket and a new hybrid key exchange
 *   "quit"
 * Durations are wolfSSL_connect() from start to end on CLOCK_MONOTONIC of the client (the UAV). Datagrams and bytes are
 * counted in the I/O callbacks on the client: everything it sent, and everything that reached it. */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#define GROUP WOLFSSL_SECP384R1MLKEM1024
#define SUITE "TLS13-AES256-GCM-SHA384"

typedef struct {
    int fd;
    struct sockaddr_in peer;      /* server: the client of the connection in progress */
    int server;                   /* 1: unconnected socket, datagrams from other addresses end the connection */
    double deadline;              /* monotonic seconds; 0 = none */
    long sent_dg, sent_b, recv_dg, recv_b, timeouts;
    char flow[512];               /* sizes of the datagrams in order: >sent <received */
} io_t;

static void note(io_t *io, char dir, long n) {
    size_t l = strlen(io->flow);
    if (l < sizeof io->flow - 12)
        snprintf(io->flow + l, sizeof io->flow - l, "%s%c%ld", l ? " " : "", dir, n);
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int cb_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    io_t *io = ctx;
    ssize_t n = io->server ? sendto(io->fd, buf, sz, 0, (struct sockaddr *)&io->peer, sizeof io->peer) : send(io->fd, buf, sz, 0);
    if (n < 0) {
        /* EPERM: the loss rule of the measurement (nftables, output hook) dropped the datagram; ENOBUFS/EAGAIN: a full
           queue; ECONNREFUSED: an ICMP error of an earlier datagram. On the air each of these is a lost datagram, so it
           counts as sent and lost, as the Kyber-6G link treats it, never as the end of the connection. */
        if (errno == EPERM || errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED) {
            io->sent_dg++;
            io->sent_b += sz;
            note(io, '>', (long)sz);
            return sz;
        }
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    io->sent_dg++;
    io->sent_b += n;
    note(io, '>', (long)n);
    return (int)n;
}

static int cb_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    io_t *io = ctx;
    for (;;) {
        long ms = 1000L * wolfSSL_dtls_get_current_timeout(ssl);
#ifdef WOLFSSL_DTLS13
        if (wolfSSL_dtls13_use_quick_timeout(ssl))
            ms /= 4;
#endif
        if (io->deadline > 0) {
            double left = io->deadline - now();
            if (left <= 0)
                return WOLFSSL_CBIO_ERR_GENERAL;          /* the measurement gives up on this handshake */
            if (left * 1000 < ms)
                ms = (long)(left * 1000) + 1;
        }
        struct pollfd p = {io->fd, POLLIN, 0};
        int r = poll(&p, 1, (int)ms);
        if (r == 0) {
            if (io->deadline > 0 && now() >= io->deadline)
                return WOLFSSL_CBIO_ERR_GENERAL;
            io->timeouts++;
            return WOLFSSL_CBIO_ERR_TIMEOUT;             /* wolfSSL retransmits and asks again */
        }
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        if (io->server) {
            struct sockaddr_in src;
            socklen_t sl = sizeof src;
            ssize_t n = recvfrom(io->fd, buf, sz, MSG_PEEK, (struct sockaddr *)&src, &sl);
            if (n < 0)
                return WOLFSSL_CBIO_ERR_GENERAL;
            if (src.sin_addr.s_addr != io->peer.sin_addr.s_addr || src.sin_port != io->peer.sin_port)
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;      /* a new client: this connection is over, the datagram stays */
        }
        ssize_t n = recv(io->fd, buf, sz, 0);
        if (n < 0) {
            if (errno == ECONNREFUSED || errno == EINTR)
                continue;
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        io->recv_dg++;
        io->recv_b += n;
        note(io, '<', (long)n);
        return (int)n;
    }
}

static WOLFSSL_CTX *make_ctx(int server, const char *cert, const char *key, const char *peer) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(server ? wolfDTLSv1_3_server_method() : wolfDTLSv1_3_client_method());
    int groups[] = {GROUP};
    if (!ctx || wolfSSL_CTX_use_certificate_file(ctx, cert, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, key, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_locations(ctx, peer, NULL) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_set_cipher_list(ctx, SUITE) != WOLFSSL_SUCCESS || wolfSSL_CTX_set_groups(ctx, groups, 1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "context setup failed (certificate, key, peer certificate, suite or group)\n");
        exit(2);
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    wolfSSL_CTX_SetIORecv(ctx, cb_recv);
    wolfSSL_CTX_SetIOSend(ctx, cb_send);
    return ctx;
}

/* ------------------------------------------------------------------------------------------------------- server */
static int server(int port, int cookie, const char *cert, const char *key, const char *peer) {
    WOLFSSL_CTX *ctx = make_ctx(1, cert, key, peer);
    int fd = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rb = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        perror("bind");
        return 2;
    }
    fprintf(stderr, "dtls_bench server on UDP %d, cookie %s, group SecP384r1MLKEM1024, ML-DSA-87 both ways\n", port, cookie ? "on" : "off");
    for (;;) {
        io_t io = {.fd = fd, .server = 1};
        char b[64];
        socklen_t sl = sizeof io.peer;
        if (recvfrom(fd, b, sizeof b, MSG_PEEK, (struct sockaddr *)&io.peer, &sl) < 0)
            continue;
        WOLFSSL *ssl = wolfSSL_new(ctx);
        wolfSSL_SetIOReadCtx(ssl, &io);
        wolfSSL_SetIOWriteCtx(ssl, &io);
        if (!cookie)
            wolfSSL_disable_hrr_cookie(ssl);
        io.deadline = now() + 30;
        int ret = wolfSSL_accept(ssl);
        if (ret == WOLFSSL_SUCCESS) {
            /* stay for the client's acknowledgements and close_notify, until the next client arrives or 2 s pass */
            io.deadline = now() + 2;
            while (wolfSSL_read(ssl, b, sizeof b) > 0)
                ;
        } else {
            /* a stale datagram of an earlier connection, or a failed handshake: drop the datagram that started it */
            int err = wolfSSL_get_error(ssl, ret);
            if (err != WOLFSSL_ERROR_WANT_READ)
                fprintf(stderr, "accept: %d %s\n", err, wolfSSL_ERR_reason_error_string(err));
        }
        wolfSSL_free(ssl);
        /* a datagram from the address just served that is still queued (a late retransmission) belongs to the old
           connection: discard it so that it does not start a new one */
        struct pollfd p = {fd, POLLIN, 0};
        while (poll(&p, 1, 0) > 0) {
            struct sockaddr_in src;
            sl = sizeof src;
            if (recvfrom(fd, b, sizeof b, MSG_PEEK, (struct sockaddr *)&src, &sl) < 0)
                break;
            if (src.sin_addr.s_addr == io.peer.sin_addr.s_addr && src.sin_port == io.peer.sin_port)
                recv(fd, b, sizeof b, 0);
            else
                break;
        }
    }
}

/* ------------------------------------------------------------------------------------------------------- client */
static WOLFSSL_SESSION *ticket;

static void handshake(WOLFSSL_CTX *ctx, const char *kind, struct sockaddr_in *srv, int resume, int psk_only) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    connect(fd, (struct sockaddr *)srv, sizeof *srv);
    io_t io = {.fd = fd};
    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_SetIOReadCtx(ssl, &io);
    wolfSSL_SetIOWriteCtx(ssl, &io);
    int have_ticket = ticket != NULL;
    /* With ClientHello fragmentation, wolfSSL's DTLS 1.3 client sends its first hello without the large hybrid key
       share; the server asks for it with a HelloRetryRequest (with or without a cookie). A PSK-only resumption needs
       no key share and completes after the first hello. (Without any key-share extension the server asks for one and
       the PSK-only client cannot answer: measured, so not done.) */
    wolfSSL_UseKeyShare(ssl, GROUP);
    if (resume && ticket) {
        wolfSSL_set_session(ssl, ticket);
        if (psk_only)
            wolfSSL_no_dhe_psk(ssl);
    }
    io.deadline = now() + 10;                    /* given up after 10 s (the link's full handshake waits about 6 s) */
    double t0 = now();
    int ret = wolfSSL_connect(ssl);
    double t1 = now();
    int err = ret == WOLFSSL_SUCCESS ? 0 : wolfSSL_get_error(ssl, ret);
    int reused = ret == WOLFSSL_SUCCESS ? wolfSSL_session_reused(ssl) : 0;
    long sdg = io.sent_dg, sb = io.sent_b, rdg = io.recv_dg, rb = io.recv_b, to = io.timeouts;
    char flow[sizeof io.flow];
    memcpy(flow, io.flow, sizeof flow);
    if (ret == WOLFSSL_SUCCESS && !resume) {
        /* the server's NewSessionTicket follows the handshake: read until it is there (not timed, at most 1.5 s) */
        char b[64];
        unsigned char tb[4096];
        word32 tl = 0;
        double give_up = now() + 1.5;
        while (now() < give_up) {
            io.deadline = now() + 0.15;
            wolfSSL_read(ssl, b, sizeof b);
            tl = sizeof tb;
            if (wolfSSL_get_SessionTicket(ssl, tb, &tl) == WOLFSSL_SUCCESS && tl > 0)
                break;
            tl = 0;
        }
        if (tl > 0) {
            WOLFSSL_SESSION *s = wolfSSL_get1_session(ssl);
            if (s) {
                if (ticket)
                    wolfSSL_SESSION_free(ticket);
                ticket = s;
            }
        }                                         /* no ticket this time: the resumptions use the previous one */
    }
    io.deadline = now() + 0.05;
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(fd);
    printf("{\"kind\": \"%s\", \"ok\": %s, \"ms\": %.3f, \"resumed\": %s, \"had_ticket\": %s, \"sent_datagrams\": %ld, \"sent_bytes\": %ld, "
           "\"received_datagrams\": %ld, \"received_bytes\": %ld, \"timeouts\": %ld, \"error\": %d, \"flow\": \"%s\"}\n",
           kind, ret == WOLFSSL_SUCCESS ? "true" : "false", (t1 - t0) * 1000, reused ? "true" : "false", have_ticket ? "true" : "false",
           sdg, sb, rdg, rb, to, err, flow);
    fflush(stdout);
}

static int client(const char *host, int port_cookie, int port_nocookie, const char *cert, const char *key, const char *peer) {
    WOLFSSL_CTX *ctx = make_ctx(0, cert, key, peer);
    struct sockaddr_in c = {.sin_family = AF_INET, .sin_port = htons(port_cookie)}, n;
    if (inet_pton(AF_INET, host, &c.sin_addr) != 1) {
        fprintf(stderr, "HOST must be an IPv4 address\n");
        return 2;
    }
    n = c;
    n.sin_port = htons(port_nocookie);
    char line[64];
    printf("{\"ready\": true, \"wolfssl\": \"%s\"}\n", wolfSSL_lib_version());
    fflush(stdout);
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strcmp(line, "full"))
            handshake(ctx, "full", &c, 0, 0);
        else if (!strcmp(line, "full_nc"))
            handshake(ctx, "full_nc", &n, 0, 0);
        else if (!strcmp(line, "psk_ke"))
            handshake(ctx, "psk_ke", &n, 1, 1);
        else if (!strcmp(line, "psk_dhe_ke"))
            handshake(ctx, "psk_dhe_ke", &n, 1, 0);
        else if (!strcmp(line, "quit"))
            break;
        else {
            printf("{\"error\": \"unknown command\"}\n");
            fflush(stdout);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    wolfSSL_Init();
    if (argc == 7 && !strcmp(argv[1], "server"))
        return server(atoi(argv[2]), atoi(argv[3]), argv[4], argv[5], argv[6]);
    if (argc == 8 && !strcmp(argv[1], "client"))
        return client(argv[2], atoi(argv[3]), atoi(argv[4]), argv[5], argv[6], argv[7]);
    fprintf(stderr, "usage: dtls_bench server PORT COOKIE(0|1) CERT KEY PEER_CERT\n"
                    "       dtls_bench client HOST PORT_COOKIE PORT_NOCOOKIE CERT KEY PEER_CERT  (commands on stdin)\n");
    return 2;
}
