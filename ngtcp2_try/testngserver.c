/*
 * testngserver.c - ngtcp2 QUIC + nghttp3 server using OpenSSL directly
 *                  (no libngtcp2_crypto_ossl)
 *
 * Uses ngopenssl.h/ngopenssl.c for the TLS-to-ngtcp2 glue via
 * OpenSSL 3.5's SSL_set_quic_tls_cbs / OSSL_DISPATCH API.
 *
 * Compare with testserver.c which uses ngtcp2_crypto_ossl for the
 * same role — the server logic is identical, only the crypto setup
 * and callback wiring differs.
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include "ngopenssl.h"

#define MAX_PKT_SIZE   1280
#define BODY "Hello from ngtcp2 H3 server (direct OpenSSL crypto)\n"

static volatile sig_atomic_t running = 1;
static const uint8_t alpn[] = "\x02h3";

/* ------------------------------------------------------------------ */
/*  Server connection state                                           */
/*  ngopenssl_ctx MUST be the first member so that ngtcp2's           */
/*  user_data pointer works for both crypto and app callbacks.        */
/*                                                                    */
/*  Compare with testserver.c's ServerConn which has:                 */
/*    ngtcp2_crypto_conn_ref conn_ref;                                */
/*    ngtcp2_crypto_ossl_ctx *ossl_ctx;                               */
/*  in place of ngopenssl_ctx.                                        */
/* ------------------------------------------------------------------ */
typedef struct {
  ngopenssl_ctx ng;   /* crypto state — MUST be first */
  nghttp3_conn *h3conn;
  SSL_CTX *ssl_ctx;
  int fd;
  struct sockaddr_storage local_addr, remote_addr;
  socklen_t local_addrlen, remote_addrlen;
  int h3_ctrl_stream_bound;
} ServerConn;

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */
static void sigint_handler(int sig) { (void)sig; running = 0; }

static ngtcp2_tstamp timestamp(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS +
         (ngtcp2_tstamp)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/*  ngtcp2 non-crypto callbacks (same as testserver)                  */
/* ------------------------------------------------------------------ */
static void server_rand(uint8_t *dest, size_t destlen,
                        const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  RAND_bytes(dest, (int)destlen);
}

static int server_get_new_cid(ngtcp2_conn *conn, ngtcp2_cid *cid,
                              uint8_t *token, size_t cidlen,
                              void *user_data) {
  (void)conn; (void)user_data;
  RAND_bytes(cid->data, (int)cidlen);
  cid->datalen = cidlen;
  RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  nghttp3 callbacks (same as testserver)                            */
/* ------------------------------------------------------------------ */
static int h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                          int32_t token, nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value, uint8_t flags,
                          void *conn_user_data, void *stream_user_data) {
  nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);
  (void)conn; (void)stream_id; (void)token; (void)flags;
  (void)conn_user_data; (void)stream_user_data;
  printf("  %.*s: %.*s\n", (int)nv.len, nv.base, (int)vv.len, vv.base);
  return 0;
}

static nghttp3_ssize h3_read_data(nghttp3_conn *conn, int64_t stream_id,
                                  nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data) {
  (void)conn; (void)stream_id; (void)veccnt;
  (void)conn_user_data; (void)stream_user_data;
  vec[0].base = (uint8_t *)BODY;
  vec[0].len = sizeof(BODY) - 1;
  *pflags = NGHTTP3_DATA_FLAG_EOF;
  return 1;
}

static int h3_end_stream(nghttp3_conn *conn, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data) {
  nghttp3_nv nva[] = {
    {(uint8_t *)":status", (uint8_t *)"200", 7, 3,
     NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10,
     NGHTTP3_NV_FLAG_NONE},
  };
  nghttp3_data_reader dr;
  (void)conn_user_data; (void)stream_user_data;
  memset(&dr, 0, sizeof(dr));
  dr.read_data = h3_read_data;
  printf("Request complete on stream %ld, sending 200\n", (long)stream_id);
  nghttp3_conn_submit_response(conn, stream_id, nva, 2, &dr);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  ngtcp2 stream callbacks (same as testserver)                      */
/* ------------------------------------------------------------------ */
static int q_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                              int64_t stream_id, uint64_t offset,
                              const uint8_t *data, size_t datalen,
                              void *user_data, void *stream_user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  (void)conn; (void)offset; (void)stream_user_data;
  if (sc->h3conn)
    nghttp3_conn_read_stream(sc->h3conn, stream_id, data, datalen, fin);
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(conn, datalen);
  return 0;
}

static int q_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                      uint64_t offset, uint64_t datalen,
                                      void *user_data,
                                      void *stream_user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  (void)conn; (void)offset; (void)stream_user_data;
  if (sc->h3conn)
    nghttp3_conn_add_ack_offset(sc->h3conn, stream_id, datalen);
  return 0;
}

static int q_stream_open(ngtcp2_conn *conn, int64_t stream_id,
                         void *user_data) {
  (void)conn; (void)stream_id; (void)user_data;
  return 0;
}

static int q_stream_close(ngtcp2_conn *conn, uint32_t flags,
                          int64_t stream_id, uint64_t app_error_code,
                          void *user_data, void *stream_user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  (void)conn; (void)flags; (void)stream_user_data;
  if (sc->h3conn)
    nghttp3_conn_close_stream(sc->h3conn, stream_id, app_error_code);
  return 0;
}

static int q_extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                           uint64_t max_streams,
                                           void *user_data) {
  (void)conn; (void)max_streams; (void)user_data;
  return 0;
}

static int q_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t max_data, void *user_data,
                                    void *stream_user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  (void)conn; (void)max_data; (void)stream_user_data;
  if (sc->h3conn)
    nghttp3_conn_unblock_stream(sc->h3conn, stream_id);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  H3 setup (same as testserver)                                     */
/* ------------------------------------------------------------------ */
static int setup_h3(ServerConn *sc) {
  nghttp3_callbacks h3_cb;
  nghttp3_settings h3_settings;
  int64_t ctrl, qenc, qdec;
  int rv;

  memset(&h3_cb, 0, sizeof(h3_cb));
  h3_cb.recv_header = h3_recv_header;
  h3_cb.end_stream = h3_end_stream;
  nghttp3_settings_default(&h3_settings);

  rv = nghttp3_conn_server_new(&sc->h3conn, &h3_cb, &h3_settings,
                               NULL, sc);
  if (rv != 0) {
    fprintf(stderr, "nghttp3_conn_server_new: %s\n",
            nghttp3_strerror(rv));
    return -1;
  }
  ngtcp2_conn_open_uni_stream(sc->ng.qconn, &ctrl, NULL);
  ngtcp2_conn_open_uni_stream(sc->ng.qconn, &qenc, NULL);
  ngtcp2_conn_open_uni_stream(sc->ng.qconn, &qdec, NULL);
  nghttp3_conn_bind_control_stream(sc->h3conn, ctrl);
  nghttp3_conn_bind_qpack_streams(sc->h3conn, qenc, qdec);
  sc->h3_ctrl_stream_bound = 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/*  Write pending QUIC packets (same as testserver)                   */
/* ------------------------------------------------------------------ */
static int write_to_wire(ServerConn *sc) {
  uint8_t buf[MAX_PKT_SIZE];
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_tstamp ts = timestamp();

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    nghttp3_vec vec[16];
    nghttp3_ssize sveccnt = 0;
    int64_t stream_id = -1;
    int fin = 0;
    ngtcp2_ssize nwrite;
    ngtcp2_ssize ndatalen = 0;

    if (sc->h3conn && sc->h3_ctrl_stream_bound) {
      sveccnt = nghttp3_conn_writev_stream(sc->h3conn, &stream_id,
                                           &fin, vec, 16);
      if (sveccnt < 0) {
        fprintf(stderr, "nghttp3_conn_writev_stream: %s\n",
                nghttp3_strerror((int)sveccnt));
        return -1;
      }
    }

    uint32_t wflags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin)
      wflags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

    if (sveccnt > 0) {
      nwrite = ngtcp2_conn_writev_stream(sc->ng.qconn, &ps.path, &pi,
                                         buf, sizeof(buf), &ndatalen,
                                         wflags, stream_id,
                                         (ngtcp2_vec *)vec,
                                         (size_t)sveccnt, ts);
    } else {
      nwrite = ngtcp2_conn_write_pkt(sc->ng.qconn, &ps.path, &pi,
                                     buf, sizeof(buf), ts);
    }
    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        if (sc->h3conn && ndatalen >= 0)
          nghttp3_conn_add_write_offset(sc->h3conn, stream_id, ndatalen);
        continue;
      }
      fprintf(stderr, "ngtcp2_conn_write: %s\n",
              ngtcp2_strerror((int)nwrite));
      return -1;
    }
    if (nwrite == 0)
      break;
    if (sc->h3conn && ndatalen >= 0 && stream_id >= 0)
      nghttp3_conn_add_write_offset(sc->h3conn, stream_id, ndatalen);
    sendto(sc->fd, buf, (size_t)nwrite, 0,
           (struct sockaddr *)&sc->remote_addr, sc->remote_addrlen);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/*  ALPN selection callback                                           */
/* ------------------------------------------------------------------ */
static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg) {
  (void)ssl; (void)arg;
  if (SSL_select_next_proto((unsigned char **)out, outlen, alpn,
                            sizeof(alpn) - 1, in, inlen) !=
      OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  return SSL_TLSEXT_ERR_OK;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/*                                                                    */
/*  Compare with testserver.c's main():                               */
/*    - Crypto callbacks: ngopenssl_* instead of ngtcp2_crypto_*_cb   */
/*    - SSL setup: ngopenssl_configure_server() instead of            */
/*        ngtcp2_crypto_ossl_configure_server_session()               */
/*        + ngtcp2_crypto_ossl_ctx_new()                              */
/*        + ngtcp2_conn_set_tls_native_handle()                       */
/*        + SSL_set_app_data()                                        */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[]) {
  SSL_CTX *ssl_ctx;
  ServerConn sc;
  int fd;
  uint16_t port = 4433;
  const char *cert_file = "server.crt";
  const char *key_file = "server.key";
  struct sockaddr_in sin;
  ngtcp2_callbacks q_cb;
  ngtcp2_settings q_settings;
  ngtcp2_transport_params q_params;
  ngtcp2_cid scid, dcid;
  ngtcp2_path path;
  int i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
      port = (uint16_t)atoi(argv[++i]);
    else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
      cert_file = argv[++i];
    else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
      key_file = argv[++i];
    else {
      fprintf(stderr, "Usage: %s [-p port] [-c cert] [-k key]\n", argv[0]);
      return 1;
    }
  }

  signal(SIGINT, sigint_handler);

  /* SSL_CTX — plain TLS 1.3, no QUIC method on the context */
  ssl_ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    fprintf(stderr, "Cannot load %s\n", cert_file);
    return 1;
  }
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file,
                                  SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "Cannot load %s\n", key_file);
    return 1;
  }
  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, NULL);

  /* UDP socket */
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = INADDR_ANY;
  if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("bind");
    return 1;
  }
  printf("Listening on UDP port %u\n", (unsigned)port);

  /*
   * ngtcp2 callbacks — crypto callbacks from ngopenssl, not ngtcp2_crypto_ossl.
   *
   * testserver.c has:
   *   q_cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
   *   q_cb.encrypt             = ngtcp2_crypto_encrypt_cb;
   *   ...etc
   */
  memset(&q_cb, 0, sizeof(q_cb));
  q_cb.recv_client_initial   = ngopenssl_recv_client_initial;
  q_cb.recv_crypto_data      = ngopenssl_recv_crypto_data;
  q_cb.encrypt               = ngopenssl_encrypt;
  q_cb.decrypt               = ngopenssl_decrypt;
  q_cb.hp_mask               = ngopenssl_hp_mask;
  q_cb.update_key            = ngopenssl_update_key;
  q_cb.delete_crypto_aead_ctx   = ngopenssl_delete_crypto_aead_ctx;
  q_cb.delete_crypto_cipher_ctx = ngopenssl_delete_crypto_cipher_ctx;
  q_cb.get_path_challenge_data  = ngopenssl_get_path_challenge_data;
  q_cb.version_negotiation      = ngopenssl_version_negotiation;
  q_cb.recv_stream_data         = q_recv_stream_data;
  q_cb.acked_stream_data_offset = q_acked_stream_data_offset;
  q_cb.stream_open              = q_stream_open;
  q_cb.stream_close             = q_stream_close;
  q_cb.extend_max_local_streams_bidi = q_extend_max_local_streams_bidi;
  q_cb.extend_max_stream_data   = q_extend_max_stream_data;
  q_cb.rand                     = server_rand;
  q_cb.get_new_connection_id    = server_get_new_cid;

  memset(&sc, 0, sizeof(sc));
  sc.ssl_ctx = ssl_ctx;
  sc.fd = fd;
  sc.local_addrlen = sizeof(sc.local_addr);
  getsockname(fd, (struct sockaddr *)&sc.local_addr, &sc.local_addrlen);

  /* Wait for Initial packet */
  while (running) {
    uint8_t buf[65536];
    ssize_t nread;
    ngtcp2_pkt_hd hd;
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    int rv;

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    rv = poll(&pfd, 1, 1000);
    if (rv <= 0) continue;

    sc.remote_addrlen = sizeof(sc.remote_addr);
    nread = recvfrom(fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&sc.remote_addr,
                     &sc.remote_addrlen);
    if (nread < 0) continue;

    rv = ngtcp2_accept(&hd, buf, (size_t)nread);
    if (rv != 0) continue;

    dcid = hd.scid;
    scid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    RAND_bytes(scid.data, (int)scid.datalen);

    ngtcp2_path_storage_zero(&ps);
    ps.path.local.addr = (struct sockaddr *)&sc.local_addr;
    ps.path.local.addrlen = sc.local_addrlen;
    ps.path.remote.addr = (struct sockaddr *)&sc.remote_addr;
    ps.path.remote.addrlen = sc.remote_addrlen;

    ngtcp2_settings_default(&q_settings);
    q_settings.initial_ts = timestamp();

    ngtcp2_transport_params_default(&q_params);
    q_params.initial_max_streams_uni = 3;
    q_params.initial_max_streams_bidi = 100;
    q_params.initial_max_stream_data_bidi_local = 256 * 1024;
    q_params.initial_max_stream_data_bidi_remote = 256 * 1024;
    q_params.initial_max_stream_data_uni = 256 * 1024;
    q_params.initial_max_data = 1024 * 1024;
    q_params.original_dcid = hd.dcid;
    q_params.original_dcid_present = 1;

    rv = ngtcp2_conn_server_new(&sc.ng.qconn, &dcid, &scid, &ps.path,
                                hd.version, &q_cb, &q_settings,
                                &q_params, NULL, &sc);
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_server_new: %s\n",
              ngtcp2_strerror(rv));
      return 1;
    }

    /*
     * Create SSL and configure for QUIC TLS.
     *
     * testserver.c has:
     *   sc.conn_ref.get_conn = get_conn;
     *   sc.conn_ref.user_data = &sc;
     *   ngtcp2_crypto_ossl_configure_server_session(sc.ssl);
     *   SSL_set_app_data(sc.ssl, &sc.conn_ref);
     *   ngtcp2_crypto_ossl_ctx_new(&sc.ossl_ctx, sc.ssl);
     *   ngtcp2_conn_set_tls_native_handle(sc.qconn, sc.ossl_ctx);
     */
    sc.ng.ssl = SSL_new(ssl_ctx);
    if (!sc.ng.ssl) {
      fprintf(stderr, "SSL_new failed\n");
      return 1;
    }
    if (ngopenssl_configure_server(&sc.ng, sc.ng.ssl, sc.ng.qconn) != 0) {
      fprintf(stderr, "ngopenssl_configure_server failed\n");
      return 1;
    }

    /* Feed the Initial packet */
    memset(&pi, 0, sizeof(pi));
    path = ps.path;
    rv = ngtcp2_conn_read_pkt(sc.ng.qconn, &path, &pi, buf,
                              (size_t)nread, timestamp());
    if (rv != 0) {
      fprintf(stderr, "read_pkt(Initial): %s\n", ngtcp2_strerror(rv));
      ngtcp2_conn_del(sc.ng.qconn);
      SSL_free(sc.ng.ssl);
      sc.ng.qconn = NULL;
      sc.ng.ssl = NULL;
      continue;
    }

    write_to_wire(&sc);
    break;
  }

  if (!sc.ng.qconn) {
    close(fd);
    SSL_CTX_free(ssl_ctx);
    return 1;
  }

  /* Main event loop */
  while (running) {
    struct pollfd pfd;
    int timeout_ms = 50;
    ngtcp2_tstamp expiry, now;
    int rv;

    expiry = ngtcp2_conn_get_expiry(sc.ng.qconn);
    now = timestamp();
    if (expiry <= now) {
      timeout_ms = 0;
    } else {
      int ms = (int)((expiry - now) / NGTCP2_MILLISECONDS);
      if (ms < timeout_ms)
        timeout_ms = ms > 0 ? ms : 1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    rv = poll(&pfd, 1, timeout_ms);
    now = timestamp();

    if (rv > 0 && (pfd.revents & POLLIN)) {
      uint8_t buf[65536];
      ssize_t nread;
      ngtcp2_path_storage ps;
      ngtcp2_pkt_info pi;

      sc.remote_addrlen = sizeof(sc.remote_addr);
      nread = recvfrom(fd, buf, sizeof(buf), 0,
                       (struct sockaddr *)&sc.remote_addr,
                       &sc.remote_addrlen);
      if (nread > 0) {
        ngtcp2_path_storage_zero(&ps);
        ps.path.local.addr = (struct sockaddr *)&sc.local_addr;
        ps.path.local.addrlen = sc.local_addrlen;
        ps.path.remote.addr = (struct sockaddr *)&sc.remote_addr;
        ps.path.remote.addrlen = sc.remote_addrlen;
        memset(&pi, 0, sizeof(pi));

        rv = ngtcp2_conn_read_pkt(sc.ng.qconn, &ps.path, &pi, buf,
                                  (size_t)nread, now);
        if (rv != 0) {
          if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING)
            break;
          fprintf(stderr, "read_pkt: %s\n", ngtcp2_strerror(rv));
        }
      }
    }

    rv = ngtcp2_conn_handle_expiry(sc.ng.qconn, now);
    if (rv != 0) {
      fprintf(stderr, "handle_expiry: %s\n", ngtcp2_strerror(rv));
      break;
    }

    if (!sc.h3conn &&
        ngtcp2_conn_get_handshake_completed(sc.ng.qconn)) {
      if (setup_h3(&sc) < 0)
        break;
      printf("Handshake complete, H3 ready\n");
    }

    if (write_to_wire(&sc) < 0)
      break;
  }

  printf("Shutting down\n");
  if (sc.h3conn) nghttp3_conn_del(sc.h3conn);
  if (sc.ng.qconn)  ngtcp2_conn_del(sc.ng.qconn);
  if (sc.ng.ssl)    SSL_free(sc.ng.ssl);
  close(fd);
  SSL_CTX_free(ssl_ctx);
  return 0;
}
