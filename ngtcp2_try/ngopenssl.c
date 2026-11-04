/*
 * ngopenssl.c - Direct OpenSSL 3.5 crypto glue for ngtcp2
 *
 * Implements the ngtcp2 crypto callbacks and OpenSSL QUIC TLS
 * dispatch table using raw EVP APIs — no libngtcp2_crypto_ossl.
 *
 * See ngopenssl.h for API documentation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>

#include "ngopenssl.h"

/* QUIC v1 initial salt (RFC 9001 Section 5.2) */
static const uint8_t quic_v1_salt[] = {
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
  0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
  0xcc, 0xbb, 0x7f, 0x0a,
};

/* ------------------------------------------------------------------ */
/*  AEAD / HP key storage                                             */
/* ------------------------------------------------------------------ */
typedef struct {
  const EVP_CIPHER *cipher;
  uint8_t key[32];
  size_t keylen;
  int enc;
} AeadKey;

typedef struct {
  const EVP_CIPHER *cipher;
  uint8_t key[32];
  size_t keylen;
} HpKey;

/* ------------------------------------------------------------------ */
/*  HKDF via EVP_MAC("HMAC")                                         */
/* ------------------------------------------------------------------ */
static int do_hmac(const EVP_MD *md, const uint8_t *key, size_t keylen,
                   const uint8_t *msg, size_t msglen,
                   uint8_t *out, size_t *outlen) {
  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  EVP_MAC_CTX *ctx;
  OSSL_PARAM params[2];
  int ok;
  if (!mac) return -1;
  ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  if (!ctx) return -1;
  params[0] = OSSL_PARAM_construct_utf8_string(
                  "digest", (char *)EVP_MD_get0_name(md), 0);
  params[1] = OSSL_PARAM_construct_end();
  ok = EVP_MAC_init(ctx, key, keylen, params)
    && EVP_MAC_update(ctx, msg, msglen)
    && EVP_MAC_final(ctx, out, outlen, EVP_MAX_MD_SIZE);
  EVP_MAC_CTX_free(ctx);
  return ok ? 0 : -1;
}

static int hkdf_extract(uint8_t *dest, size_t *destlen, const EVP_MD *md,
                         const uint8_t *salt, size_t saltlen,
                         const uint8_t *ikm, size_t ikmlen) {
  return do_hmac(md, salt, saltlen, ikm, ikmlen, dest, destlen);
}

static int hkdf_expand(uint8_t *dest, size_t destlen, const EVP_MD *md,
                        const uint8_t *prk, size_t prklen,
                        const uint8_t *info, size_t infolen) {
  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  OSSL_PARAM params[2];
  uint8_t t[EVP_MAX_MD_SIZE];
  size_t tlen = 0, done = 0;
  uint8_t counter = 0;
  int ok = 1;
  if (!mac) return -1;
  params[0] = OSSL_PARAM_construct_utf8_string(
                  "digest", (char *)EVP_MD_get0_name(md), 0);
  params[1] = OSSL_PARAM_construct_end();
  while (done < destlen && ok) {
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    size_t outlen, tocopy;
    if (!ctx) { ok = 0; break; }
    counter++;
    ok = EVP_MAC_init(ctx, prk, prklen, params);
    if (ok && tlen > 0)   ok = EVP_MAC_update(ctx, t, tlen);
    if (ok)               ok = EVP_MAC_update(ctx, info, infolen);
    if (ok)               ok = EVP_MAC_update(ctx, &counter, 1);
    if (ok)               ok = EVP_MAC_final(ctx, t, &outlen, sizeof(t));
    EVP_MAC_CTX_free(ctx);
    if (!ok) break;
    tlen = outlen;
    tocopy = destlen - done;
    if (tocopy > tlen) tocopy = tlen;
    memcpy(dest + done, t, tocopy);
    done += tocopy;
  }
  EVP_MAC_free(mac);
  return ok ? 0 : -1;
}

static int qhkdf_expand(uint8_t *dest, size_t destlen, const EVP_MD *md,
                          const uint8_t *secret, size_t secretlen,
                          const uint8_t *label, size_t labellen) {
  uint8_t info[256];
  size_t pos = 0;
  info[pos++] = (uint8_t)(destlen >> 8);
  info[pos++] = (uint8_t)(destlen);
  info[pos++] = (uint8_t)(6 + labellen);
  memcpy(info + pos, "tls13 ", 6); pos += 6;
  memcpy(info + pos, label, labellen); pos += labellen;
  info[pos++] = 0;
  return hkdf_expand(dest, destlen, md, secret, secretlen, info, pos);
}

/* ------------------------------------------------------------------ */
/*  Cipher helpers                                                    */
/* ------------------------------------------------------------------ */
static void cipher_suite_from_ssl(SSL *ssl,
                                   const EVP_CIPHER **aead,
                                   const EVP_CIPHER **hp,
                                   const EVP_MD **md) {
  const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
  uint16_t id = c ? SSL_CIPHER_get_protocol_id(c) : 0x1301;
  switch (id) {
  case 0x1302:
    *aead = EVP_aes_256_gcm(); *hp = EVP_aes_256_ecb(); *md = EVP_sha384();
    break;
  case 0x1303:
    *aead = EVP_chacha20_poly1305(); *hp = EVP_chacha20(); *md = EVP_sha256();
    break;
  default:
    *aead = EVP_aes_128_gcm(); *hp = EVP_aes_128_ecb(); *md = EVP_sha256();
    break;
  }
}

static int derive_pkt_keys(const EVP_CIPHER *aead, const EVP_MD *md,
                            uint8_t *key, uint8_t *iv, uint8_t *hp_key,
                            const uint8_t *secret, size_t secretlen) {
  size_t klen = (size_t)EVP_CIPHER_get_key_length(aead);
  if (qhkdf_expand(key, klen, md, secret, secretlen,
                    (const uint8_t *)"quic key", 8) < 0) return -1;
  if (qhkdf_expand(iv, 12, md, secret, secretlen,
                    (const uint8_t *)"quic iv", 7) < 0) return -1;
  if (qhkdf_expand(hp_key, klen, md, secret, secretlen,
                    (const uint8_t *)"quic hp", 7) < 0) return -1;
  return 0;
}

static ngtcp2_encryption_level prot_to_level(uint32_t p) {
  switch (p) {
  case OSSL_RECORD_PROTECTION_LEVEL_NONE:        return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  case OSSL_RECORD_PROTECTION_LEVEL_EARLY:       return NGTCP2_ENCRYPTION_LEVEL_0RTT;
  case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE:   return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
  case OSSL_RECORD_PROTECTION_LEVEL_APPLICATION: return NGTCP2_ENCRYPTION_LEVEL_1RTT;
  }
  return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
}

/* ------------------------------------------------------------------ */
/*  AEAD / HP context helpers                                         */
/* ------------------------------------------------------------------ */
static int aead_ctx_init(ngtcp2_crypto_aead_ctx *ctx,
                          const EVP_CIPHER *cipher,
                          const uint8_t *key, int enc) {
  AeadKey *ak = calloc(1, sizeof(*ak));
  if (!ak) return -1;
  ak->cipher = cipher;
  ak->keylen = (size_t)EVP_CIPHER_get_key_length(cipher);
  memcpy(ak->key, key, ak->keylen);
  ak->enc = enc;
  ctx->native_handle = ak;
  return 0;
}

static int hp_ctx_init(ngtcp2_crypto_cipher_ctx *ctx,
                        const EVP_CIPHER *cipher,
                        const uint8_t *key) {
  HpKey *hk = calloc(1, sizeof(*hk));
  if (!hk) return -1;
  hk->cipher = cipher;
  hk->keylen = (size_t)EVP_CIPHER_get_key_length(cipher);
  memcpy(hk->key, key, hk->keylen);
  ctx->native_handle = hk;
  return 0;
}

/* ------------------------------------------------------------------ */
/*  Install initial keys from DCID (RFC 9001 Section 5.2)             */
/* ------------------------------------------------------------------ */
static int install_initial_keys(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                                 const uint8_t *salt, size_t saltlen) {
  const EVP_CIPHER *aead = EVP_aes_128_gcm();
  const EVP_CIPHER *hp_cipher = EVP_aes_128_ecb();
  const EVP_MD *md = EVP_sha256();
  uint8_t initial_secret[32], client_secret[32], server_secret[32];
  uint8_t rx_key[16], rx_iv[12], rx_hp[16];
  uint8_t tx_key[16], tx_iv[12], tx_hp[16];
  size_t secretlen;
  ngtcp2_crypto_aead_ctx rx_aead = {0}, tx_aead = {0};
  ngtcp2_crypto_cipher_ctx rx_hp_ctx = {0}, tx_hp_ctx = {0};
  ngtcp2_crypto_ctx crypto_ctx;

  if (hkdf_extract(initial_secret, &secretlen, md,
                    salt, saltlen, dcid->data, dcid->datalen) < 0)
    return -1;

  if (qhkdf_expand(client_secret, 32, md, initial_secret, 32,
                    (const uint8_t *)"client in", 9) < 0) return -1;
  if (qhkdf_expand(server_secret, 32, md, initial_secret, 32,
                    (const uint8_t *)"server in", 9) < 0) return -1;

  if (derive_pkt_keys(aead, md, rx_key, rx_iv, rx_hp,
                       client_secret, 32) < 0) return -1;
  if (derive_pkt_keys(aead, md, tx_key, tx_iv, tx_hp,
                       server_secret, 32) < 0) return -1;

  if (aead_ctx_init(&rx_aead, aead, rx_key, 0) < 0) return -1;
  if (aead_ctx_init(&tx_aead, aead, tx_key, 1) < 0) return -1;
  if (hp_ctx_init(&rx_hp_ctx, hp_cipher, rx_hp) < 0) return -1;
  if (hp_ctx_init(&tx_hp_ctx, hp_cipher, tx_hp) < 0) return -1;

  memset(&crypto_ctx, 0, sizeof(crypto_ctx));
  crypto_ctx.aead.native_handle = (void *)aead;
  crypto_ctx.aead.max_overhead = 16;
  crypto_ctx.hp.native_handle = (void *)hp_cipher;
  crypto_ctx.md.native_handle = (void *)md;
  crypto_ctx.max_encryption = UINT64_MAX;
  crypto_ctx.max_decryption_failure = UINT64_MAX;
  ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);

  return ngtcp2_conn_install_initial_key(conn,
    &rx_aead, rx_iv, &rx_hp_ctx,
    &tx_aead, tx_iv, &tx_hp_ctx, 12);
}

/* ------------------------------------------------------------------ */
/*  Install handshake / 1-RTT keys from a TLS traffic secret          */
/* ------------------------------------------------------------------ */
static int install_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                        int direction, const EVP_CIPHER *aead,
                        const EVP_CIPHER *hp_cipher, const EVP_MD *md,
                        const uint8_t *secret, size_t secretlen) {
  uint8_t key[32], iv[12], hp_key[32];
  ngtcp2_crypto_aead_ctx aead_ctx = {0};
  ngtcp2_crypto_cipher_ctx hp_ctx = {0};
  int enc = (direction == 1);

  if (derive_pkt_keys(aead, md, key, iv, hp_key, secret, secretlen) < 0)
    return -1;
  if (aead_ctx_init(&aead_ctx, aead, key, enc) < 0) return -1;
  if (hp_ctx_init(&hp_ctx, hp_cipher, hp_key) < 0) return -1;

  switch (level) {
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    if (direction == 0)
      return ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, iv, 12, &hp_ctx);
    else
      return ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, iv, 12, &hp_ctx);
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    if (direction == 0)
      return ngtcp2_conn_install_rx_key(conn, secret, secretlen,
                                         &aead_ctx, iv, 12, &hp_ctx);
    else
      return ngtcp2_conn_install_tx_key(conn, secret, secretlen,
                                         &aead_ctx, iv, 12, &hp_ctx);
  case NGTCP2_ENCRYPTION_LEVEL_0RTT:
    return ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, iv, 12, &hp_ctx);
  default:
    return -1;
  }
}

/* ------------------------------------------------------------------ */
/*  ngtcp2 crypto callbacks                                           */
/* ------------------------------------------------------------------ */
int ngopenssl_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                       const ngtcp2_crypto_aead_ctx *aead_ctx,
                       const uint8_t *plaintext, size_t plaintextlen,
                       const uint8_t *nonce, size_t noncelen,
                       const uint8_t *aad, size_t aadlen) {
  AeadKey *ak = aead_ctx->native_handle;
  EVP_CIPHER_CTX *ctx;
  int len, rv = -1;
  (void)noncelen;
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  if (!EVP_EncryptInit_ex(ctx, ak->cipher, NULL, ak->key, nonce)) goto out;
  if (aadlen > 0 && !EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen))
    goto out;
  if (!EVP_EncryptUpdate(ctx, dest, &len, plaintext, (int)plaintextlen))
    goto out;
  if (!EVP_EncryptFinal_ex(ctx, dest + len, &len)) goto out;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            (int)aead->max_overhead,
                            dest + plaintextlen))
    goto out;
  rv = 0;
out:
  EVP_CIPHER_CTX_free(ctx);
  return rv;
}

int ngopenssl_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                       const ngtcp2_crypto_aead_ctx *aead_ctx,
                       const uint8_t *ciphertext, size_t ciphertextlen,
                       const uint8_t *nonce, size_t noncelen,
                       const uint8_t *aad, size_t aadlen) {
  AeadKey *ak = aead_ctx->native_handle;
  EVP_CIPHER_CTX *ctx;
  int len, ret, rv = -1;
  size_t taglen = aead->max_overhead;
  size_t datalen = ciphertextlen - taglen;
  (void)noncelen;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  if (!EVP_DecryptInit_ex(ctx, ak->cipher, NULL, ak->key, nonce))
    goto out;
  if (aadlen > 0 && !EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen))
    goto out;
  if (!EVP_DecryptUpdate(ctx, dest, &len, ciphertext, (int)datalen))
    goto out;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                            (void *)(ciphertext + datalen)))
    goto out;
  ret = EVP_DecryptFinal_ex(ctx, dest + len, &len);
  if (!ret) {
    rv = NGTCP2_ERR_DECRYPT;
    goto out;
  }
  rv = 0;
out:
  EVP_CIPHER_CTX_free(ctx);
  return rv;
}

int ngopenssl_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                       const ngtcp2_crypto_cipher_ctx *hp_ctx,
                       const uint8_t *sample) {
  HpKey *hk = hp_ctx->native_handle;
  EVP_CIPHER_CTX *ctx;
  int len, rv = -1;
  int mode = EVP_CIPHER_get_mode((const EVP_CIPHER *)hp->native_handle);

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  if (mode == EVP_CIPH_ECB_MODE) {
    uint8_t mask_buf[16];
    if (!EVP_EncryptInit_ex(ctx, hk->cipher, NULL, hk->key, NULL)) goto out;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!EVP_EncryptUpdate(ctx, mask_buf, &len, sample, 16)) goto out;
    memcpy(dest, mask_buf, 5);
  } else {
    static const uint8_t zeros[5] = {0};
    if (!EVP_EncryptInit_ex(ctx, hk->cipher, NULL, hk->key, sample)) goto out;
    if (!EVP_EncryptUpdate(ctx, dest, &len, zeros, 5)) goto out;
  }
  rv = 0;
out:
  EVP_CIPHER_CTX_free(ctx);
  return rv;
}

void ngopenssl_delete_crypto_aead_ctx(ngtcp2_conn *conn,
                                       ngtcp2_crypto_aead_ctx *aead_ctx,
                                       void *user_data) {
  (void)conn; (void)user_data;
  free(aead_ctx->native_handle);
  aead_ctx->native_handle = NULL;
}

void ngopenssl_delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                                         ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                         void *user_data) {
  (void)conn; (void)user_data;
  free(cipher_ctx->native_handle);
  cipher_ctx->native_handle = NULL;
}

int ngopenssl_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                       void *user_data) {
  (void)conn; (void)user_data;
  RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
  return 0;
}

int ngopenssl_recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                                   void *user_data) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)user_data;
  ngtcp2_ssize tp_len;

  if (install_initial_keys(conn, dcid, quic_v1_salt,
                            sizeof(quic_v1_salt)) != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  {
    const ngtcp2_transport_params *ltp = ngtcp2_conn_get_local_transport_params(conn);
    ngtcp2_transport_params tp_copy = *ltp;
    ngtcp2_cid scids[1];
    ngtcp2_conn_get_scid(conn, scids);
    tp_copy.initial_scid = scids[0];
    tp_copy.initial_scid_present = 1;
    if (tp_copy.version_info.chosen_version == 0)
      tp_copy.version_info.chosen_version = 1;
    tp_len = ngtcp2_transport_params_encode(ctx->tp_buf, sizeof(ctx->tp_buf), &tp_copy);
  }
  if (tp_len < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
  ctx->tp_len = (size_t)tp_len;
  if (!SSL_set_quic_tls_transport_params(ctx->ssl, ctx->tp_buf, ctx->tp_len))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

int ngopenssl_recv_crypto_data(ngtcp2_conn *conn,
                                ngtcp2_encryption_level level,
                                uint64_t offset, const uint8_t *data,
                                size_t datalen, void *user_data) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)user_data;
  ngopenssl_crypto_buf *cb = &ctx->crypto[level];
  int rv;
  (void)offset;

  if (cb->len + datalen > NGOPENSSL_CRYPTO_BUF_CAP)
    return NGTCP2_ERR_CRYPTO;
  memcpy(cb->buf + cb->len, data, datalen);
  cb->len += datalen;

  if (!ctx->handshake_completed) {
    rv = SSL_do_handshake(ctx->ssl);
    if (rv <= 0) {
      int err = SSL_get_error(ctx->ssl, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        ERR_print_errors_fp(stderr);
        ngtcp2_conn_set_tls_alert(conn, SSL_AD_HANDSHAKE_FAILURE);
        return NGTCP2_ERR_CRYPTO;
      }
    }
    if (SSL_is_init_finished(ctx->ssl)) {
      ctx->handshake_completed = 1;
      ngtcp2_conn_tls_handshake_completed(conn);
    }
  } else {
    rv = SSL_do_handshake(ctx->ssl);
    if (rv <= 0) {
      int err = SSL_get_error(ctx->ssl, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        ngtcp2_conn_set_tls_alert(conn, SSL_AD_INTERNAL_ERROR);
        return NGTCP2_ERR_CRYPTO;
      }
    }
  }
  return 0;
}

int ngopenssl_update_key(ngtcp2_conn *conn,
                          uint8_t *rx_secret, uint8_t *tx_secret,
                          ngtcp2_crypto_aead_ctx *rx_aead_ctx,
                          uint8_t *rx_iv,
                          ngtcp2_crypto_aead_ctx *tx_aead_ctx,
                          uint8_t *tx_iv,
                          const uint8_t *current_rx_secret,
                          const uint8_t *current_tx_secret,
                          size_t secretlen, void *user_data) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)user_data;
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *md;
  uint8_t key[32], hp_key[32];
  (void)conn;

  cipher_suite_from_ssl(ctx->ssl, &aead, &hp, &md);

  if (qhkdf_expand(rx_secret, secretlen, md, current_rx_secret,
                    secretlen, (const uint8_t *)"quic ku", 7) < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  if (qhkdf_expand(tx_secret, secretlen, md, current_tx_secret,
                    secretlen, (const uint8_t *)"quic ku", 7) < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if (derive_pkt_keys(aead, md, key, rx_iv, hp_key,
                       rx_secret, secretlen) < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  if (aead_ctx_init(rx_aead_ctx, aead, key, 0) < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if (derive_pkt_keys(aead, md, key, tx_iv, hp_key,
                       tx_secret, secretlen) < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  if (aead_ctx_init(tx_aead_ctx, aead, key, 1) < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

int ngopenssl_version_negotiation(ngtcp2_conn *conn, uint32_t version,
                                   const ngtcp2_cid *client_dcid,
                                   void *user_data) {
  (void)user_data;
  (void)version;
  return install_initial_keys(conn, client_dcid,
                               quic_v1_salt, sizeof(quic_v1_salt));
}

/* ------------------------------------------------------------------ */
/*  OpenSSL 3.5 QUIC TLS dispatch callbacks                           */
/* ------------------------------------------------------------------ */
static int quic_crypto_send(SSL *ssl, const unsigned char *buf,
                             size_t buf_len, size_t *consumed, void *arg) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)arg;
  (void)ssl;
  if (ngtcp2_conn_submit_crypto_data(ctx->qconn, ctx->write_level,
                                      buf, buf_len) != 0)
    return 0;
  *consumed = buf_len;
  return 1;
}

static int quic_crypto_recv_rcd(SSL *ssl, const unsigned char **buf,
                                 size_t *bytes_read, void *arg) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)arg;
  int i;
  (void)ssl;
  for (i = 0; i < 4; i++) {
    ngopenssl_crypto_buf *cb = &ctx->crypto[i];
    if (cb->consumed < cb->len) {
      *buf = cb->buf + cb->consumed;
      *bytes_read = cb->len - cb->consumed;
      return 1;
    }
  }
  *buf = NULL;
  *bytes_read = 0;
  return 1;
}

static int quic_crypto_release_rcd(SSL *ssl, size_t bytes_read, void *arg) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)arg;
  int i;
  (void)ssl;
  for (i = 0; i < 4; i++) {
    ngopenssl_crypto_buf *cb = &ctx->crypto[i];
    size_t avail = cb->len - cb->consumed;
    if (avail > 0) {
      if (bytes_read <= avail) {
        cb->consumed += bytes_read;
        if (cb->consumed == cb->len) {
          cb->len = 0;
          cb->consumed = 0;
        }
        return 1;
      }
      bytes_read -= avail;
      cb->len = 0;
      cb->consumed = 0;
    }
  }
  return 1;
}

static int quic_yield_secret(SSL *ssl, uint32_t prot_level, int direction,
                              const unsigned char *secret, size_t secret_len,
                              void *arg) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)arg;
  ngtcp2_encryption_level level = prot_to_level(prot_level);
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *md;
  (void)ssl;

  cipher_suite_from_ssl(ctx->ssl, &aead, &hp, &md);

  if (direction == 1)
    ctx->write_level = level;

  if (level == NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE && direction == 1) {
    ngtcp2_crypto_ctx crypto_ctx;
    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    crypto_ctx.aead.native_handle = (void *)aead;
    crypto_ctx.aead.max_overhead = 16;
    crypto_ctx.hp.native_handle = (void *)hp;
    crypto_ctx.md.native_handle = (void *)md;
    if (EVP_CIPHER_get_nid(aead) == NID_chacha20_poly1305) {
      crypto_ctx.max_encryption = (uint64_t)1 << 62;
      crypto_ctx.max_decryption_failure = (uint64_t)1 << 36;
    } else {
      crypto_ctx.max_encryption = (uint64_t)1 << 23;
      crypto_ctx.max_decryption_failure = (uint64_t)1 << 52;
    }
    ngtcp2_conn_set_crypto_ctx(ctx->qconn, &crypto_ctx);
  }

  return install_key(ctx->qconn, level, direction, aead, hp, md,
                      secret, secret_len) == 0 ? 1 : 0;
}

static int quic_got_transport_params(SSL *ssl, const unsigned char *params,
                                      size_t params_len, void *arg) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)arg;
  (void)ssl;
  return ngtcp2_conn_decode_and_set_remote_transport_params(
           ctx->qconn, params, params_len) == 0 ? 1 : 0;
}

static int quic_alert(SSL *ssl, unsigned char alert_code, void *arg) {
  ngopenssl_ctx *ctx = (ngopenssl_ctx *)arg;
  (void)ssl;
  ngtcp2_conn_set_tls_alert(ctx->qconn, alert_code);
  return 1;
}

static const OSSL_DISPATCH quic_tls_dispatch[] = {
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
    (void (*)(void))quic_crypto_send },
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
    (void (*)(void))quic_crypto_recv_rcd },
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
    (void (*)(void))quic_crypto_release_rcd },
  { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
    (void (*)(void))quic_yield_secret },
  { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
    (void (*)(void))quic_got_transport_params },
  { OSSL_FUNC_SSL_QUIC_TLS_ALERT,
    (void (*)(void))quic_alert },
  OSSL_DISPATCH_END
};

/* ------------------------------------------------------------------ */
/*  Public: configure SSL for QUIC TLS                                */
/* ------------------------------------------------------------------ */
int ngopenssl_configure_server(ngopenssl_ctx *ctx, SSL *ssl,
                                ngtcp2_conn *qconn) {
  ctx->ssl = ssl;
  ctx->qconn = qconn;
  ctx->write_level = NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  ctx->handshake_completed = 0;

  SSL_set_accept_state(ssl);
  if (!SSL_set_quic_tls_cbs(ssl, quic_tls_dispatch, ctx))
    return -1;

  return 0;
}
