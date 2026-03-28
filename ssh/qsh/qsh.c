/*
 * qsh — QUIC Shell Client (with PTY support)
 *
 * Connects to qshd via QUIC, puts the local terminal in raw mode,
 * and provides a fully interactive shell session.
 *
 * Usage: ./qsh --host=user:ip [--port=2222]
 *
 * Stream protocol:
 *   0x01  Shell data — first 4 bytes: rows(u16 BE) + cols(u16 BE),
 *         then raw bidirectional I/O.
 *   0x02  Window resize — 4 bytes: rows(u16 BE) + cols(u16 BE), FIN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#define STREAM_TYPE_DATA    0x01
#define STREAM_TYPE_RESIZE  0x02

#define DEFAULT_PORT  2222
#define BUF_SZ        65536

static char ca_file[512];
static char client_cert[512];
static char client_key[512];

static void init_cert_paths(void)
{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(ca_file,      sizeof(ca_file),      "%s/ssh/certs/ca-cert.pem", home);
    snprintf(client_cert,  sizeof(client_cert),   "%s/ssh/certs/client-cert.pem", home);
    snprintf(client_key,   sizeof(client_key),    "%s/ssh/certs/client-key.pem", home);
}

#define CA_FILE       ca_file
#define CLIENT_CERT   client_cert
#define CLIENT_KEY    client_key

static const unsigned char alpn[] = {3, 'q', 's', 'h'};

/* ------------------------------------------------------------------ */
/*  Terminal handling                                                   */
/* ------------------------------------------------------------------ */

static struct termios orig_termios;
static int raw_mode_set;
static volatile int got_winch;
static volatile int running = 1;

static void restore_terminal(void)
{
    if (raw_mode_set) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_mode_set = 0;
    }
}

static void set_raw_mode(void)
{
    struct termios raw;
    if (!isatty(STDIN_FILENO)) return;
    tcgetattr(STDIN_FILENO, &orig_termios);
    raw = orig_termios;
    cfmakeraw(&raw);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_mode_set = 1;
}

static void get_winsize(uint16_t *rows, uint16_t *cols)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    } else {
        *rows = 24;
        *cols = 80;
    }
}

static void sigwinch_handler(int sig) { (void)sig; got_winch = 1; }
static void sig_handler(int sig)      { (void)sig; running = 0; }

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static uint64_t get_timestamp(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
    WC_RNG rng;
    (void)rand_ctx;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, dest, (word32)destlen);
    wc_FreeRng(&rng);
}

static int get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                          ngtcp2_stateless_reset_token *token,
                          size_t cidlen, void *user_data)
{
    WC_RNG rng;
    (void)conn; (void)user_data;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, cid->data, (word32)cidlen);
    cid->datalen = cidlen;
    wc_RNG_GenerateBlock(&rng, token->data, sizeof(token->data));
    wc_FreeRng(&rng);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Client state                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn           *conn;
    WOLFSSL_CTX           *ssl_ctx;
    WOLFSSL               *ssl;
    int                    fd;
    struct sockaddr_storage local_addr;
    socklen_t              local_addrlen;
    struct sockaddr_in     remote_addr;

    int64_t  data_stream_id;
    int      handshake_done;
    int      streams_available;
    int      stream_fin;          /* server sent FIN — shell exited */

    /* stdin → QUIC output buffer */
    uint8_t  out_buf[BUF_SZ];
    size_t   out_len;
    size_t   out_sent;
} Client;

static ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    Client *c = ref->user_data;
    return c->conn;
}

/* ------------------------------------------------------------------ */
/*  ngtcp2 callbacks                                                   */
/* ------------------------------------------------------------------ */

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data)
{
    Client *c = user_data;
    (void)conn; (void)stream_id; (void)offset; (void)stream_user_data;

    /* Write shell output straight to the terminal */
    if (datalen > 0)
        (void)!write(STDOUT_FILENO, data, datalen);

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
        c->stream_fin = 1;

    return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    Client *c = user_data;
    (void)conn;
    c->handshake_done = 1;
    return 0;
}

static int extend_max_streams_cb(ngtcp2_conn *conn, uint64_t max_streams,
                                 void *user_data)
{
    Client *c = user_data;
    (void)conn; (void)max_streams;
    c->streams_available = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Packet I/O                                                         */
/* ------------------------------------------------------------------ */

static int send_packets(Client *c)
{
    uint8_t buf[1400];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    uint64_t ts = get_timestamp();

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        if (c->data_stream_id >= 0 && c->out_sent < c->out_len) {
            nwrite = ngtcp2_conn_write_stream(
                c->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen,
                0, c->data_stream_id,
                c->out_buf + c->out_sent,
                c->out_len  - c->out_sent, ts);

            if (nwrite > 0 && wdatalen > 0)
                c->out_sent += (size_t)wdatalen;
        }
        else {
            nwrite = ngtcp2_conn_write_pkt(c->conn, &ps.path, &pi,
                                           buf, sizeof(buf), ts);
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) break;
            return -1;
        }
        if (nwrite == 0) break;

        sendto(c->fd, buf, (size_t)nwrite, 0,
               (struct sockaddr *)&c->remote_addr, sizeof(c->remote_addr));
    }
    return 0;
}

static int recv_packets(Client *c)
{
    uint8_t buf[BUF_SZ];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t nread;
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {0};

    for (;;) {
        addrlen = sizeof(addr);
        nread = recvfrom(c->fd, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&addr, &addrlen);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return -1;
        }

        path.local.addr     = (struct sockaddr *)&c->local_addr;
        path.local.addrlen  = c->local_addrlen;
        path.remote.addr    = (struct sockaddr *)&addr;
        path.remote.addrlen = addrlen;

        if (ngtcp2_conn_read_pkt(c->conn, &path, &pi,
                                 buf, (size_t)nread, get_timestamp()) != 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Send a window-resize control stream                                */
/* ------------------------------------------------------------------ */

static int send_resize(Client *c, uint16_t rows, uint16_t cols)
{
    int64_t sid;
    uint8_t hdr[5];
    uint8_t buf[1400];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;

    if (ngtcp2_conn_open_bidi_stream(c->conn, &sid, NULL) != 0)
        return -1;

    hdr[0] = STREAM_TYPE_RESIZE;
    hdr[1] = (rows >> 8) & 0xff;
    hdr[2] =  rows       & 0xff;
    hdr[3] = (cols >> 8) & 0xff;
    hdr[4] =  cols       & 0xff;

    ngtcp2_path_storage_zero(&ps);

    nwrite = ngtcp2_conn_write_stream(
        c->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen,
        NGTCP2_WRITE_STREAM_FLAG_FIN, sid,
        hdr, sizeof(hdr), get_timestamp());

    if (nwrite > 0)
        sendto(c->fd, buf, (size_t)nwrite, 0,
               (struct sockaddr *)&c->remote_addr, sizeof(c->remote_addr));

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Client setup                                                       */
/* ------------------------------------------------------------------ */

static int client_init(Client *c, const char *host, int port)
{
    ngtcp2_callbacks cb = {0};
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid dcid, scid;
    ngtcp2_path path;
    int rv;

    memset(c, 0, sizeof(*c));
    c->data_stream_id = -1;

    /* UDP socket */
    c->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (c->fd < 0) return -1;

    memset(&c->remote_addr, 0, sizeof(c->remote_addr));
    c->remote_addr.sin_family = AF_INET;
    c->remote_addr.sin_port   = htons((unsigned short)port);

    if (inet_pton(AF_INET, host, &c->remote_addr.sin_addr) != 1) {
        struct addrinfo hints = {0}, *res;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
            fprintf(stderr, "Cannot resolve host: %s\n", host);
            return -1;
        }
        c->remote_addr.sin_addr =
            ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }

    if (connect(c->fd, (struct sockaddr *)&c->remote_addr,
                sizeof(c->remote_addr)) < 0)
        return -1;

    c->local_addrlen = sizeof(c->local_addr);
    getsockname(c->fd, (struct sockaddr *)&c->local_addr, &c->local_addrlen);

    /* wolfSSL */
    c->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!c->ssl_ctx) return -1;

    ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx);

    if (wolfSSL_CTX_load_verify_locations(c->ssl_ctx, CA_FILE, NULL)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "qsh: failed to load CA: %s\n", CA_FILE);
        return -1;
    }
    if (wolfSSL_CTX_use_certificate_file(c->ssl_ctx, CLIENT_CERT,
                                         WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "qsh: failed to load client cert: %s\n", CLIENT_CERT);
        return -1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(c->ssl_ctx, CLIENT_KEY,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "qsh: failed to load client key: %s\n", CLIENT_KEY);
        return -1;
    }

    wolfSSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_NONE, NULL);

    c->ssl = wolfSSL_new(c->ssl_ctx);
    if (!c->ssl) return -1;

    wolfSSL_set_connect_state(c->ssl);
    wolfSSL_set_alpn_protos(c->ssl, alpn, sizeof(alpn));

    c->conn_ref.get_conn  = get_conn_cb;
    c->conn_ref.user_data = c;
    wolfSSL_set_app_data(c->ssl, &c->conn_ref);

    /* ngtcp2 */
    cb.client_initial       = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data     = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt              = ngtcp2_crypto_encrypt_cb;
    cb.decrypt              = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask              = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry           = ngtcp2_crypto_recv_retry_cb;
    cb.update_key           = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation  = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.get_new_connection_id2   = get_new_cid_cb;
    cb.rand                 = rand_cb;
    cb.recv_stream_data     = recv_stream_data_cb;
    cb.handshake_completed  = handshake_completed_cb;
    cb.extend_max_local_streams_bidi = extend_max_streams_cb;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = get_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi            = 100;
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data                    = 1024 * 1024;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    rand_cb(dcid.data, dcid.datalen, NULL);
    scid.datalen = 8;
    rand_cb(scid.data, scid.datalen, NULL);

    path.local.addr     = (struct sockaddr *)&c->local_addr;
    path.local.addrlen  = c->local_addrlen;
    path.remote.addr    = (struct sockaddr *)&c->remote_addr;
    path.remote.addrlen = sizeof(c->remote_addr);

    rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1, &cb, &settings,
                                &params, NULL, c);
    if (rv != 0) return -1;

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Handshake                                                          */
/* ------------------------------------------------------------------ */

static int do_handshake(Client *c)
{
    int loops;
    struct pollfd pfd = { .fd = c->fd, .events = POLLIN };

    send_packets(c);

    for (loops = 0; loops < 50; loops++) {
        if (poll(&pfd, 1, 200) > 0 && (pfd.revents & POLLIN))
            recv_packets(c);
        send_packets(c);
        ngtcp2_conn_handle_expiry(c->conn, get_timestamp());

        if (c->handshake_done) return 0;
    }

    fprintf(stderr, "Handshake timeout\n");
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Extract username from our own client certificate CN                */
/* ------------------------------------------------------------------ */

static void get_cert_user(const char *cert_path, char *user, size_t usersz)
{
    WOLFSSL_CTX *ctx;
    WOLFSSL_X509 *x509;
    char *cn;

    user[0] = '\0';

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return;

    if (wolfSSL_CTX_use_certificate_file(ctx, cert_path,
                                         WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS) {
        x509 = wolfSSL_CTX_get0_certificate(ctx);
        if (x509) {
            cn = wolfSSL_X509_get_subjectCN(x509);
            if (cn && cn[0]) {
                snprintf(user, usersz, "%s", cn);
            }
        }
    }

    wolfSSL_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/*  Argument parsing                                                   */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --host=<hostname> [options]\n"
        "\n"
        "Options:\n"
        "  --host=<hostname>        Server to connect to\n"
        "  --host=<user>:<hostname> Override username from cert CN\n"
        "  --port=N                 UDP port (default: 2222)\n"
        "  --user=<name>            Use ~/ssh/certs/<name>-{cert,key}.pem\n"
        "  --cert=<path>            Client certificate file\n"
        "  --key=<path>             Client private key file\n"
        "  --ca=<path>              CA certificate file\n"
        "\n"
        "Defaults: ~/ssh/certs/{client-cert,client-key,ca-cert}.pem\n",
        prog);
    exit(1);
}

static void parse_host(const char *arg, char *user, size_t usersz,
                       char *host, size_t hostsz)
{
    const char *colon = strchr(arg, ':');
    if (!colon) {
        /* No user prefix — host only, username comes from cert */
        user[0] = '\0';
        strncpy(host, arg, hostsz - 1);
    }
    else {
        size_t ulen = (size_t)(colon - arg);
        if (ulen >= usersz) ulen = usersz - 1;
        memcpy(user, arg, ulen);
        user[ulen] = '\0';
        strncpy(host, colon + 1, hostsz - 1);
    }
    host[hostsz - 1] = '\0';
    user[usersz - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    char user[64] = {0}, host[256] = {0};
    int port = DEFAULT_PORT;
    int i, got_host = 0;
    Client client;
    int64_t sid;
    uint16_t rows, cols;
    uint8_t hdr[5];

    /* Set defaults before parsing args */
    init_cert_paths();

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--host=", 7) == 0) {
            parse_host(argv[i] + 7, user, sizeof(user),
                       host, sizeof(host));
            got_host = 1;
        }
        else if (strncmp(argv[i], "--port=", 7) == 0) {
            port = atoi(argv[i] + 7);
        }
        else if (strncmp(argv[i], "--user=", 7) == 0) {
            const char *home = getenv("HOME");
            if (!home) home = ".";
            snprintf(client_cert, sizeof(client_cert),
                     "%s/ssh/certs/%s-cert.pem", home, argv[i] + 7);
            snprintf(client_key, sizeof(client_key),
                     "%s/ssh/certs/%s-key.pem", home, argv[i] + 7);
        }
        else if (strncmp(argv[i], "--cert=", 7) == 0) {
            snprintf(client_cert, sizeof(client_cert), "%s", argv[i] + 7);
        }
        else if (strncmp(argv[i], "--key=", 6) == 0) {
            snprintf(client_key, sizeof(client_key), "%s", argv[i] + 6);
        }
        else if (strncmp(argv[i], "--ca=", 5) == 0) {
            snprintf(ca_file, sizeof(ca_file), "%s", argv[i] + 5);
        }
        else {
            usage(argv[0]);
        }
    }

    if (!got_host) usage(argv[0]);
    wolfSSL_Init();

    /* If no user given on command line, read it from the cert CN */
    if (!user[0])
        get_cert_user(CLIENT_CERT, user, sizeof(user));
    if (!user[0])
        snprintf(user, sizeof(user), "%s", getenv("USER") ? getenv("USER") : "unknown");

    fprintf(stderr, "qsh: connecting to %s@%s:%d via QUIC...\n",
            user, host, port);

    if (client_init(&client, host, port) != 0) {
        fprintf(stderr, "qsh: connection init failed\n");
        return 1;
    }
    if (do_handshake(&client) != 0) {
        fprintf(stderr, "qsh: handshake failed\n");
        return 1;
    }

    fprintf(stderr, "qsh: connected (TLS 1.3 / QUIC)\n");

    /* Open the data stream and send the header */
    if (ngtcp2_conn_open_bidi_stream(client.conn, &sid, NULL) != 0) {
        fprintf(stderr, "qsh: cannot open stream\n");
        return 1;
    }
    client.data_stream_id = sid;

    get_winsize(&rows, &cols);
    hdr[0] = STREAM_TYPE_DATA;
    hdr[1] = (rows >> 8) & 0xff;
    hdr[2] =  rows       & 0xff;
    hdr[3] = (cols >> 8) & 0xff;
    hdr[4] =  cols       & 0xff;

    memcpy(client.out_buf, hdr, 5);
    client.out_len  = 5;
    client.out_sent = 0;
    send_packets(&client);

    /* Switch terminal to raw mode */
    set_raw_mode();
    atexit(restore_terminal);

    signal(SIGWINCH, sigwinch_handler);
    signal(SIGINT,   sig_handler);
    signal(SIGTERM,  sig_handler);

    /* ---- Interactive loop ---- */
    while (running && !client.stream_fin &&
           !ngtcp2_conn_in_draining_period(client.conn) &&
           !ngtcp2_conn_in_closing_period(client.conn)) {
        struct pollfd pfds[2];
        int nfds = 2;

        pfds[0].fd     = client.fd;
        pfds[0].events = POLLIN;
        pfds[1].fd     = STDIN_FILENO;
        pfds[1].events = (client.out_sent >= client.out_len) ? POLLIN : 0;

        if (poll(pfds, (nfds_t)nfds, 50) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* stdin → QUIC */
        if ((pfds[1].revents & POLLIN) && client.out_sent >= client.out_len) {
            ssize_t n = read(STDIN_FILENO, client.out_buf,
                             sizeof(client.out_buf));
            if (n > 0) {
                client.out_len  = (size_t)n;
                client.out_sent = 0;
            }
            else if (n == 0) {
                break;   /* EOF on stdin */
            }
        }

        /* QUIC → stdout */
        if (pfds[0].revents & POLLIN) {
            if (recv_packets(&client) != 0)
                break;
        }

        /* Window resize */
        if (got_winch) {
            got_winch = 0;
            get_winsize(&rows, &cols);
            send_resize(&client, rows, cols);
        }

        send_packets(&client);
        ngtcp2_conn_handle_expiry(client.conn, get_timestamp());
    }

    /* Report reason if server closed the connection */
    if (ngtcp2_conn_in_draining_period(client.conn) ||
        ngtcp2_conn_in_closing_period(client.conn)) {
        const ngtcp2_ccerr *ccerr = ngtcp2_conn_get_ccerr(client.conn);
        if (ccerr->reasonlen > 0)
            fprintf(stderr, "\r\nqsh: server closed connection: %.*s\r\n",
                    (int)ccerr->reasonlen, ccerr->reason);
        else
            fprintf(stderr, "\r\nqsh: server closed connection\r\n");
    }

    /* Cleanup */
    restore_terminal();
    ngtcp2_conn_del(client.conn);
    wolfSSL_free(client.ssl);
    wolfSSL_CTX_free(client.ssl_ctx);
    close(client.fd);
    wolfSSL_Cleanup();

    fprintf(stderr, "qsh: disconnected\n");
    return 0;
}
