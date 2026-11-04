/*
 * ngopenssl.h - Direct OpenSSL 3.5 crypto glue for ngtcp2
 *
 * Drop-in replacement for ngtcp2_crypto_ossl: implements the same
 * ngtcp2 crypto callbacks using raw OpenSSL EVP APIs and
 * SSL_set_quic_tls_cbs (OSSL_DISPATCH).
 *
 * Usage: embed ngopenssl_ctx as the FIRST member of your connection
 * struct so that ngtcp2's user_data pointer can be cast to both
 * ngopenssl_ctx* (by the crypto callbacks) and your struct (by the
 * application callbacks).
 */
#ifndef NGOPENSSL_H
#define NGOPENSSL_H

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>

#define NGOPENSSL_CRYPTO_BUF_CAP 65536

typedef struct {
  uint8_t buf[NGOPENSSL_CRYPTO_BUF_CAP];
  size_t len;
  size_t consumed;
} ngopenssl_crypto_buf;

/*
 * Crypto context — embed as FIRST member of your connection struct.
 * Replaces ngtcp2_crypto_conn_ref + ngtcp2_crypto_ossl_ctx.
 */
typedef struct {
  SSL *ssl;
  ngtcp2_conn *qconn;
  ngtcp2_encryption_level write_level;
  int handshake_completed;
  ngopenssl_crypto_buf crypto[4]; /* indexed by ngtcp2_encryption_level */
  uint8_t tp_buf[512];
  size_t tp_len;
} ngopenssl_ctx;

/*
 * Configure SSL for QUIC TLS via OSSL_DISPATCH callbacks.
 * Call after ngtcp2_conn_server_new() and SSL_new().
 * Replaces: ngtcp2_crypto_ossl_configure_server_session()
 *         + ngtcp2_crypto_ossl_ctx_new()
 *         + ngtcp2_conn_set_tls_native_handle()
 *         + SSL_set_app_data()
 */
int ngopenssl_configure_server(ngopenssl_ctx *ctx, SSL *ssl,
                                ngtcp2_conn *qconn);

/*
 * ngtcp2 crypto callbacks.
 * Replace: ngtcp2_crypto_recv_client_initial_cb, etc.
 */
int ngopenssl_recv_client_initial(ngtcp2_conn *conn,
                                   const ngtcp2_cid *dcid,
                                   void *user_data);

int ngopenssl_recv_crypto_data(ngtcp2_conn *conn,
                                ngtcp2_encryption_level level,
                                uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data);

int ngopenssl_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                       const ngtcp2_crypto_aead_ctx *aead_ctx,
                       const uint8_t *plaintext, size_t plaintextlen,
                       const uint8_t *nonce, size_t noncelen,
                       const uint8_t *aad, size_t aadlen);

int ngopenssl_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                       const ngtcp2_crypto_aead_ctx *aead_ctx,
                       const uint8_t *ciphertext, size_t ciphertextlen,
                       const uint8_t *nonce, size_t noncelen,
                       const uint8_t *aad, size_t aadlen);

int ngopenssl_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                       const ngtcp2_crypto_cipher_ctx *hp_ctx,
                       const uint8_t *sample);

int ngopenssl_update_key(ngtcp2_conn *conn,
                          uint8_t *rx_secret, uint8_t *tx_secret,
                          ngtcp2_crypto_aead_ctx *rx_aead_ctx,
                          uint8_t *rx_iv,
                          ngtcp2_crypto_aead_ctx *tx_aead_ctx,
                          uint8_t *tx_iv,
                          const uint8_t *current_rx_secret,
                          const uint8_t *current_tx_secret,
                          size_t secretlen, void *user_data);

void ngopenssl_delete_crypto_aead_ctx(ngtcp2_conn *conn,
                                       ngtcp2_crypto_aead_ctx *aead_ctx,
                                       void *user_data);

void ngopenssl_delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                                         ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                         void *user_data);

int ngopenssl_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                       void *user_data);

int ngopenssl_version_negotiation(ngtcp2_conn *conn, uint32_t version,
                                   const ngtcp2_cid *client_dcid,
                                   void *user_data);

#endif /* NGOPENSSL_H */
