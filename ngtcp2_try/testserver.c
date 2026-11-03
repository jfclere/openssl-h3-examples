#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

/* Application state per connection */
typedef struct {
  ngtcp2_conn *qconn;
  nghttp3_conn *h3conn;
  SSL *ssl;
  int fd;
} AppConnection;

/* -------------------------------------------------------------
 * 1. HTTP/3 Callbacks (nghttp3)
 * ------------------------------------------------------------- */
static int h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                          int32_t token, nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value, uint8_t flags,
                          void *conn_user_data, void *stream_user_data) {
  nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);
  (void)conn; (void)token; (void)flags;
  (void)conn_user_data; (void)stream_user_data;
  printf("H3 Header [%ld]: %.*s: %.*s\n", (long)stream_id,
         (int)nv.len, nv.base, (int)vv.len, vv.base);
  return 0;
}

static int h3_end_stream(nghttp3_conn *conn, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data) {
  /* Client finished request: queue a 200 OK response */
  nghttp3_nv nva[] = {
    {(uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP3_NV_FLAG_NONE},
    {(uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10, NGHTTP3_NV_FLAG_NONE}
  };
  nghttp3_data_reader dr;
  (void)conn_user_data; (void)stream_user_data;
  memset(&dr, 0, sizeof(dr));

  nghttp3_conn_submit_response(conn, stream_id, nva, 2, &dr);
  return 0;
}

/* -------------------------------------------------------------
 * 2. QUIC Callbacks (ngtcp2)
 * ------------------------------------------------------------- */
static int q_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                             int64_t stream_id, uint64_t offset,
                             const uint8_t *data, size_t datalen,
                             void *user_data, void *stream_user_data) {
  AppConnection *app = (AppConnection *)user_data;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  (void)conn; (void)offset; (void)stream_user_data;

  nghttp3_conn_read_stream(app->h3conn, stream_id, data, datalen, fin);
  return 0;
}

/* -------------------------------------------------------------
 * 3. Server Initialization Setup
 * ------------------------------------------------------------- */
int main(void) {
  /* A. Initialize OpenSSL SSL_CTX with TLS 1.3 and ALPN "h3" */
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
  SSL *ssl;
  nghttp3_callbacks h3_cb;
  ngtcp2_callbacks q_cb;
  int fd;
  struct sockaddr_in sin;

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_use_certificate_chain_file(ssl_ctx, "server.crt");
  SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM);

  /* Configure ngtcp2 crypto for OpenSSL on the SSL session */
  ssl = SSL_new(ssl_ctx);
  ngtcp2_crypto_ossl_configure_server_session(ssl);

  /* B. Initialize nghttp3 callbacks */
  memset(&h3_cb, 0, sizeof(h3_cb));
  h3_cb.recv_header = h3_recv_header;
  h3_cb.end_stream = h3_end_stream;

  /* C. Initialize ngtcp2 callbacks */
  memset(&q_cb, 0, sizeof(q_cb));
  q_cb.recv_stream_data = q_recv_stream_data;
  q_cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  q_cb.encrypt = ngtcp2_crypto_encrypt_cb;
  q_cb.decrypt = ngtcp2_crypto_decrypt_cb;
  q_cb.hp_mask = ngtcp2_crypto_hp_mask_cb;

  /* D. Open UDP Socket */
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(4433);
  sin.sin_addr.s_addr = INADDR_ANY;
  bind(fd, (struct sockaddr *)&sin, sizeof(sin));
  printf("Listening for HTTP/3 over UDP port 4433...\n");

  /* In a real event loop (e.g., epoll, libev, or select):
   * 1. recvfrom() datagram from UDP socket
   * 2. Call ngtcp2_conn_read_pkt()
   * 3. Let ngtcp2 feed crypto to OpenSSL and stream bytes to nghttp3
   * 4. Call ngtcp2_conn_write_pkt() and sendto() outgoing UDP packets
   */

  close(fd);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  return 0;
}
