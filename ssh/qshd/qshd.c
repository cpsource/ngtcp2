/*
 * qshd — QUIC Shell Daemon (with PTY support)
 *
 * Listens on UDP for QUIC connections using ngtcp2 + wolfSSL.
 * Allocates a PTY and spawns a shell for interactive use.
 *
 * Usage: ./qshd [port]   (default: 2222)
 *
 * Stream protocol:
 *   First byte of each client-opened stream indicates type:
 *     0x01  Shell data stream
 *           Next 4 bytes: rows(u16 BE) + cols(u16 BE)
 *           Remaining: raw shell I/O, bidirectional, no FIN until exit
 *     0x02  Window resize
 *           Next 4 bytes: rows(u16 BE) + cols(u16 BE), then FIN
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <pty.h>
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

static char cert_file[512];
static char key_file[512];
static char ca_file[512];

static void init_cert_paths(void)
{
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(cert_file, sizeof(cert_file), "%s/ssh/certs/server-cert.pem", home);
    snprintf(key_file,  sizeof(key_file),  "%s/ssh/certs/server-key.pem", home);
    snprintf(ca_file,   sizeof(ca_file),   "%s/ssh/certs/ca-cert.pem", home);
}

#define CERT_FILE  cert_file
#define KEY_FILE   key_file
#define CA_FILE    ca_file

static const unsigned char alpn[] = {3, 'q', 's', 'h'};
static volatile int running = 1;

static void sig_handler(int sig) { (void)sig; running = 0; }

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
/*  Server state                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn           *conn;
    WOLFSSL_CTX           *ssl_ctx;
    WOLFSSL               *ssl;
    int                    fd;
    struct sockaddr_in     local_addr;
    struct sockaddr_storage remote_addr;
    socklen_t              remote_addrlen;
    int                    handshake_done;
    char                   cert_user[64]; /* CN from client cert */

    /* PTY state */
    int       pty_master;
    pid_t     child_pid;
    int64_t   data_stream_id;
    int       shell_running;

    /* Stream header parsing buffer */
    uint8_t   ctrl_buf[16];
    size_t    ctrl_len;

    /* PTY → QUIC output buffer */
    uint8_t   out_buf[BUF_SZ];
    size_t    out_len;
    size_t    out_sent;
    int       out_fin;      /* shell exited, send FIN after draining */
    int       fin_sent;
} Server;

static ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    Server *s = ref->user_data;
    return s->conn;
}

/* ------------------------------------------------------------------ */
/*  Start shell with PTY                                               */
/* ------------------------------------------------------------------ */

static int start_shell(Server *s, uint16_t rows, uint16_t cols)
{
    struct winsize ws;
    int flags;

    memset(&ws, 0, sizeof(ws));
    ws.ws_row = rows;
    ws.ws_col = cols;

    s->child_pid = forkpty(&s->pty_master, NULL, NULL, &ws);
    if (s->child_pid < 0) {
        perror("[qshd] forkpty");
        return -1;
    }

    if (s->child_pid == 0) {
        /* Child — set up environment from cert identity, exec shell */
        setenv("TERM", "xterm-256color", 1);
        if (s->cert_user[0]) {
            setenv("USER",    s->cert_user, 1);
            setenv("LOGNAME", s->cert_user, 1);
            /* Try to set HOME to the user's home directory */
            char home[256];
            snprintf(home, sizeof(home), "/home/%s", s->cert_user);
            if (access(home, F_OK) == 0) {
                setenv("HOME", home, 1);
                if (chdir(home) != 0)
                    perror("chdir");
            }
        }
        execl("/bin/bash", "bash", "--login", (char *)NULL);
        _exit(1);
    }

    /* Parent — set PTY master non-blocking */
    flags = fcntl(s->pty_master, F_GETFL, 0);
    fcntl(s->pty_master, F_SETFL, flags | O_NONBLOCK);

    s->shell_running = 1;
    fprintf(stderr, "[qshd] shell started (pid %d, %ux%u)\n",
            s->child_pid, cols, rows);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  ngtcp2 callbacks                                                   */
/* ------------------------------------------------------------------ */

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data)
{
    Server *s = user_data;
    (void)conn; (void)offset; (void)stream_user_data;

    /* Fast path: data on established shell stream → write to PTY */
    if (s->shell_running && stream_id == s->data_stream_id) {
        if (datalen > 0 && s->pty_master >= 0) {
            if (write(s->pty_master, data, datalen) < 0)
                fprintf(stderr, "[qshd] pty write: %s\n", strerror(errno));
        }
        if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
            /* Client disconnected — tear down shell */
            if (s->pty_master >= 0) {
                close(s->pty_master);
                s->pty_master = -1;
            }
            if (s->child_pid > 0)
                kill(s->child_pid, SIGHUP);
        }
        return 0;
    }

    /* Accumulate header bytes for a new stream */
    if (datalen > 0) {
        size_t room = sizeof(s->ctrl_buf) - s->ctrl_len;
        size_t cp   = datalen < room ? datalen : room;
        memcpy(s->ctrl_buf + s->ctrl_len, data, cp);
        s->ctrl_len += cp;
    }

    /* Need at least 5 bytes: type(1) + rows(2) + cols(2) */
    if (s->ctrl_len >= 5) {
        uint8_t  type = s->ctrl_buf[0];
        uint16_t rows = ((uint16_t)s->ctrl_buf[1] << 8) | s->ctrl_buf[2];
        uint16_t cols = ((uint16_t)s->ctrl_buf[3] << 8) | s->ctrl_buf[4];

        if (type == STREAM_TYPE_DATA && !s->shell_running) {
            s->data_stream_id = stream_id;
            if (start_shell(s, rows, cols) == 0) {
                /* Forward any bytes that arrived after the 5-byte header */
                if (s->ctrl_len > 5) {
                    if (write(s->pty_master, s->ctrl_buf + 5,
                              s->ctrl_len - 5) < 0)
                        fprintf(stderr, "[qshd] pty write: %s\n",
                                strerror(errno));
                }
            }
            s->ctrl_len = 0;
        }
        else if (type == STREAM_TYPE_RESIZE) {
            struct winsize ws = {0};
            ws.ws_row = rows;
            ws.ws_col = cols;
            if (s->pty_master >= 0) {
                ioctl(s->pty_master, TIOCSWINSZ, &ws);
                fprintf(stderr, "[qshd] resize %ux%u\n", cols, rows);
            }
            s->ctrl_len = 0;
        }
    }

    return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    Server *s = user_data;
    (void)conn;
    s->handshake_done = 1;

    /* Extract username from client certificate CN */
    {
        WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(s->ssl);
        if (peer) {
            char *cn = wolfSSL_X509_get_subjectCN(peer);
            if (cn && cn[0]) {
                snprintf(s->cert_user, sizeof(s->cert_user), "%s", cn);
            }
            fprintf(stderr, "[qshd] handshake complete (user: %s)\n",
                    s->cert_user[0] ? s->cert_user : "unknown");
            wolfSSL_X509_free(peer);
        }
        else {
            fprintf(stderr, "[qshd] handshake complete (no client cert)\n");
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Packet I/O                                                         */
/* ------------------------------------------------------------------ */

static int send_packets(Server *s)
{
    uint8_t buf[1400];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    uint64_t ts = get_timestamp();

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        if (s->data_stream_id >= 0 && s->out_sent < s->out_len) {
            /* Send PTY output on the data stream */
            nwrite = ngtcp2_conn_write_stream(
                s->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen,
                0, s->data_stream_id,
                s->out_buf + s->out_sent,
                s->out_len  - s->out_sent, ts);

            if (nwrite > 0 && wdatalen > 0)
                s->out_sent += (size_t)wdatalen;
        }
        else if (s->data_stream_id >= 0 && s->out_fin && !s->fin_sent) {
            /* Buffer drained and shell exited — send FIN */
            nwrite = ngtcp2_conn_write_stream(
                s->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen,
                NGTCP2_WRITE_STREAM_FLAG_FIN, s->data_stream_id,
                NULL, 0, ts);

            if (nwrite > 0)
                s->fin_sent = 1;
        }
        else {
            /* ACKs, handshake, keepalive */
            nwrite = ngtcp2_conn_write_pkt(s->conn, &ps.path, &pi,
                                           buf, sizeof(buf), ts);
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                nwrite == NGTCP2_ERR_STREAM_SHUT_WR)
                break;
            return -1;
        }
        if (nwrite == 0) break;

        sendto(s->fd, buf, (size_t)nwrite, 0,
               (struct sockaddr *)&s->remote_addr, s->remote_addrlen);
    }
    return 0;
}

static int recv_packets(Server *s)
{
    uint8_t buf[BUF_SZ];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t nread;
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {0};
    int rv;

    for (;;) {
        addrlen = sizeof(addr);
        nread = recvfrom(s->fd, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&addr, &addrlen);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return -1;
        }

        path.local.addr  = (struct sockaddr *)&s->local_addr;
        path.local.addrlen = sizeof(s->local_addr);
        path.remote.addr = (struct sockaddr *)&addr;
        path.remote.addrlen = addrlen;

        rv = ngtcp2_conn_read_pkt(s->conn, &path, &pi,
                                  buf, (size_t)nread, get_timestamp());
        if (rv != 0) {
            fprintf(stderr, "[qshd] read_pkt: %s\n", ngtcp2_strerror(rv));
            if (rv == NGTCP2_ERR_CRYPTO)
                fprintf(stderr, "[qshd] TLS alert: %d\n",
                        ngtcp2_conn_get_tls_alert(s->conn));
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Connection setup                                                   */
/* ------------------------------------------------------------------ */

static int server_setup(Server *s, int fd, struct sockaddr_in *bind_addr,
                        const uint8_t *initial_pkt, size_t pktlen,
                        struct sockaddr *client_addr, socklen_t client_addrlen)
{
    ngtcp2_pkt_hd hd;
    ngtcp2_callbacks cb = {0};
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid scid;
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {0};
    int rv;

    memset(s, 0, sizeof(*s));
    s->data_stream_id = -1;
    s->pty_master     = -1;
    s->child_pid      = -1;
    s->fd = fd;
    memcpy(&s->local_addr, bind_addr, sizeof(*bind_addr));
    memcpy(&s->remote_addr, client_addr, client_addrlen);
    s->remote_addrlen = client_addrlen;

    rv = ngtcp2_accept(&hd, initial_pkt, pktlen);
    if (rv < 0) {
        fprintf(stderr, "[qshd] ngtcp2_accept: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    /* wolfSSL */
    s->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!s->ssl_ctx) return -1;

    if (ngtcp2_crypto_wolfssl_configure_server_context(s->ssl_ctx) != 0)
        return -1;
    if (wolfSSL_CTX_use_certificate_file(s->ssl_ctx, CERT_FILE,
                                         WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_use_PrivateKey_file(s->ssl_ctx, KEY_FILE,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        return -1;
    if (wolfSSL_CTX_load_verify_locations(s->ssl_ctx, CA_FILE, NULL)
            != WOLFSSL_SUCCESS)
        return -1;

    s->ssl = wolfSSL_new(s->ssl_ctx);
    if (!s->ssl) return -1;

    wolfSSL_set_verify(s->ssl, SSL_VERIFY_NONE, NULL);
    wolfSSL_set_accept_state(s->ssl);
    wolfSSL_set_alpn_protos(s->ssl, alpn, sizeof(alpn));

    s->conn_ref.get_conn  = get_conn_cb;
    s->conn_ref.user_data = s;
    wolfSSL_set_app_data(s->ssl, &s->conn_ref);

    /* ngtcp2 callbacks */
    cb.recv_client_initial    = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data       = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt                = ngtcp2_crypto_encrypt_cb;
    cb.decrypt                = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask                = ngtcp2_crypto_hp_mask_cb;
    cb.update_key             = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation    = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.get_new_connection_id2 = get_new_cid_cb;
    cb.rand                   = rand_cb;
    cb.recv_stream_data       = recv_stream_data_cb;
    cb.handshake_completed    = handshake_completed_cb;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = get_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi            = 100;
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data                    = 1024 * 1024;
    params.original_dcid         = hd.dcid;
    params.original_dcid_present = 1;

    scid.datalen = 8;
    rand_cb(scid.data, scid.datalen, NULL);

    path.local.addr     = (struct sockaddr *)&s->local_addr;
    path.local.addrlen  = sizeof(s->local_addr);
    path.remote.addr    = client_addr;
    path.remote.addrlen = client_addrlen;

    rv = ngtcp2_conn_server_new(&s->conn, &hd.scid, &scid, &path,
                                hd.version, &cb, &settings, &params,
                                NULL, s);
    if (rv != 0) return -1;

    ngtcp2_conn_set_tls_native_handle(s->conn, s->ssl);

    rv = ngtcp2_conn_read_pkt(s->conn, &path, &pi,
                              initial_pkt, pktlen, get_timestamp());
    if (rv != 0) return -1;

    return 0;
}

static void server_cleanup(Server *s)
{
    if (s->pty_master >= 0) close(s->pty_master);
    if (s->child_pid > 0) {
        kill(s->child_pid, SIGHUP);
        waitpid(s->child_pid, NULL, WNOHANG);
    }
    if (s->conn)    ngtcp2_conn_del(s->conn);
    if (s->ssl)     wolfSSL_free(s->ssl);
    if (s->ssl_ctx) wolfSSL_CTX_free(s->ssl_ctx);
    s->conn     = NULL;
    s->ssl      = NULL;
    s->ssl_ctx  = NULL;
    s->pty_master = -1;
    s->child_pid  = -1;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    int fd, opt = 1;
    int port = DEFAULT_PORT;
    struct sockaddr_in bind_addr;
    uint8_t buf[BUF_SZ];
    ssize_t nread;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    Server srv;
    int have_conn = 0;

    if (argc > 1) port = atoi(argv[1]);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    init_cert_paths();
    wolfSSL_Init();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_port        = htons((unsigned short)port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); return 1;
    }

    fprintf(stderr, "[qshd] listening on UDP port %d\n", port);

    while (running) {
        struct pollfd pfds[2];
        int nfds = 1;

        pfds[0].fd     = fd;
        pfds[0].events = POLLIN;

        /* Also poll PTY when output buffer has been drained */
        if (have_conn && srv.shell_running && srv.pty_master >= 0 &&
            srv.out_sent >= srv.out_len) {
            pfds[1].fd     = srv.pty_master;
            pfds[1].events = POLLIN;
            nfds = 2;
        }

        if (poll(pfds, (nfds_t)nfds, 50) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ---- Read PTY output ---- */
        if (nfds > 1 && (pfds[1].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(srv.pty_master, srv.out_buf, sizeof(srv.out_buf));
            if (n > 0) {
                srv.out_len  = (size_t)n;
                srv.out_sent = 0;
            }
            else if (n == 0 ||
                     (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                /* PTY closed — shell exited */
                fprintf(stderr, "[qshd] shell exited\n");
                srv.out_fin      = 1;
                srv.shell_running = 0;
                close(srv.pty_master);
                srv.pty_master = -1;
                waitpid(srv.child_pid, NULL, WNOHANG);
                srv.child_pid = -1;
            }
        }

        /* ---- Handle UDP ---- */
        if (pfds[0].revents & POLLIN) {
            if (!have_conn) {
                client_addrlen = sizeof(client_addr);
                nread = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&client_addr,
                                 &client_addrlen);
                if (nread <= 0) continue;

                fprintf(stderr, "[qshd] new connection\n");

                if (server_setup(&srv, fd, &bind_addr, buf, (size_t)nread,
                                 (struct sockaddr *)&client_addr,
                                 client_addrlen) != 0) {
                    fprintf(stderr, "[qshd] setup failed\n");
                    continue;
                }
                have_conn = 1;
                send_packets(&srv);
            }
            else {
                if (recv_packets(&srv) != 0) {
                    fprintf(stderr, "[qshd] connection error, resetting\n");
                    server_cleanup(&srv);
                    have_conn = 0;
                    continue;
                }
            }
        }

        if (have_conn) {
            send_packets(&srv);
            ngtcp2_conn_handle_expiry(srv.conn, get_timestamp());

            if (ngtcp2_conn_in_draining_period(srv.conn) ||
                ngtcp2_conn_in_closing_period(srv.conn)) {
                fprintf(stderr, "[qshd] connection closed\n");
                server_cleanup(&srv);
                have_conn = 0;
            }
        }
    }

    if (have_conn) server_cleanup(&srv);
    close(fd);
    wolfSSL_Cleanup();

    fprintf(stderr, "[qshd] shutdown\n");
    return 0;
}
