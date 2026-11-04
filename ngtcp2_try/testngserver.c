/*
 * testngserver.c - ngtcp2 QUIC + nghttp3 server using OpenSSL directly
 *                  (no libngtcp2_crypto_ossl)
 *
 * Implements the TLS-to-ngtcp2 glue via OpenSSL 3.5's
 * SSL_set_quic_tls_cbs / OSSL_DISPATCH API, plus raw EVP crypto
 * for AEAD encrypt/decrypt and header protection.
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

#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#define MAX_PKT_SIZE   1280
#define CRYPTO_BUF_CAP 65536
#define BODY "Hello from ngtcp2 H3 server (direct OpenSSL crypto)\n"

static volatile sig_atomic_t running = 1;
static const uint8_t alpn[] = "\x02h3";

/* QUIC v1 initial salt (RFC 9001 Section 5.2) */
static const uint8_t quic_v1_salt[] = {
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
  0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
  0xcc, 0xbb, 0x7f, 0x0a,
};

/* ------------------------------------------------------------------ */
/*  Per-encryption-level crypto data buffer (for the pull-model API)  */
/* ------------------------------------------------------------------ */
typedef struct {
  uint8_t buf[CRYPTO_BUF_CAP];
  size_t len;
  size_t consumed;
} CryptoBuf;

/* ------------------------------------------------------------------ */
/*  Server connection state                                           */
/* ------------------------------------------------------------------ */
typedef struct {
  ngtcp2_conn *qconn;
  nghttp3_conn *h3conn;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int fd;
  struct sockaddr_storage local_addr, remote_addr;
  socklen_t local_addrlen, remote_addrlen;
  int h3_ctrl_stream_bound;
  int handshake_completed;
  ngtcp2_encryption_level write_level;
  CryptoBuf crypto[4]; /* indexed by ngtcp2_encryption_level */
  uint8_t tp_buf[512];
  size_t tp_len;
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

/* HKDF-Expand-Label (TLS 1.3 / QUIC, empty context) */
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
  info[pos++] = 0; /* context length */
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
  case 0x1302: /* TLS_AES_256_GCM_SHA384 */
    *aead = EVP_aes_256_gcm(); *hp = EVP_aes_256_ecb(); *md = EVP_sha384();
    break;
  case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
    *aead = EVP_chacha20_poly1305(); *hp = EVP_chacha20(); *md = EVP_sha256();
    break;
  default: /* 0x1301  TLS_AES_128_GCM_SHA256 */
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

/* ------------------------------------------------------------------ */
/*  AEAD / HP context helpers                                         */
/* ------------------------------------------------------------------ */
typedef struct {
  const EVP_CIPHER *cipher;
  uint8_t key[32];
  size_t keylen;
  int enc;
} AeadKey;

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

typedef struct {
  const EVP_CIPHER *cipher;
  uint8_t key[32];
  size_t keylen;
} HpKey;

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
  int enc = (direction == 1); /* 1 = tx */

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
static int my_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
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

static int my_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
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

static int my_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
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

static void my_delete_aead_ctx(ngtcp2_conn *conn,
                                ngtcp2_crypto_aead_ctx *aead_ctx,
                                void *user_data) {
  (void)conn; (void)user_data;
  free(aead_ctx->native_handle);
  aead_ctx->native_handle = NULL;
}

static void my_delete_cipher_ctx(ngtcp2_conn *conn,
                                  ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                  void *user_data) {
  (void)conn; (void)user_data;
  free(cipher_ctx->native_handle);
  cipher_ctx->native_handle = NULL;
}

static int my_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                       void *user_data) {
  (void)conn; (void)user_data;
  RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
  return 0;
}

static int my_recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                                   void *user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  ngtcp2_ssize tp_len;

  if (install_initial_keys(conn, dcid, quic_v1_salt,
                            sizeof(quic_v1_salt)) != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  /* Encode local transport params into sc->tp_buf (must outlive the
     callback — OpenSSL keeps a pointer, not a copy).  Add initial_scid
     and fix version_info which ngtcp2 hasn't populated yet. */
  {
    const ngtcp2_transport_params *ltp = ngtcp2_conn_get_local_transport_params(conn);
    ngtcp2_transport_params tp_copy = *ltp;
    ngtcp2_cid scids[1];
    ngtcp2_conn_get_scid(conn, scids);
    tp_copy.initial_scid = scids[0];
    tp_copy.initial_scid_present = 1;
    if (tp_copy.version_info.chosen_version == 0)
      tp_copy.version_info.chosen_version = 1;
    tp_len = ngtcp2_transport_params_encode(sc->tp_buf, sizeof(sc->tp_buf), &tp_copy);
  }
  if (tp_len < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
  sc->tp_len = (size_t)tp_len;
  if (!SSL_set_quic_tls_transport_params(sc->ssl, sc->tp_buf, sc->tp_len))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

static int my_recv_crypto_data(ngtcp2_conn *conn,
                                ngtcp2_encryption_level level,
                                uint64_t offset, const uint8_t *data,
                                size_t datalen, void *user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  CryptoBuf *cb = &sc->crypto[level];
  int rv;
  (void)offset;

  /* Buffer incoming crypto data for the pull-model recv_rcd callback */
  if (cb->len + datalen > CRYPTO_BUF_CAP)
    return NGTCP2_ERR_CRYPTO;
  memcpy(cb->buf + cb->len, data, datalen);
  cb->len += datalen;

  /* Drive the TLS state machine */
  if (!sc->handshake_completed) {
    rv = SSL_do_handshake(sc->ssl);
    if (rv <= 0) {
      int err = SSL_get_error(sc->ssl, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        ERR_print_errors_fp(stderr);
        ngtcp2_conn_set_tls_alert(conn, SSL_AD_HANDSHAKE_FAILURE);
        return NGTCP2_ERR_CRYPTO;
      }
    }
    if (SSL_is_init_finished(sc->ssl)) {
      sc->handshake_completed = 1;
      ngtcp2_conn_tls_handshake_completed(conn);
    }
  } else {
    /* Post-handshake: just drive the TLS state machine again */
    rv = SSL_do_handshake(sc->ssl);
    if (rv <= 0) {
      int err = SSL_get_error(sc->ssl, rv);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        ngtcp2_conn_set_tls_alert(conn, SSL_AD_INTERNAL_ERROR);
        return NGTCP2_ERR_CRYPTO;
      }
    }
  }
  return 0;
}

static int my_update_key(ngtcp2_conn *conn,
                          uint8_t *rx_secret, uint8_t *tx_secret,
                          ngtcp2_crypto_aead_ctx *rx_aead_ctx,
                          uint8_t *rx_iv,
                          ngtcp2_crypto_aead_ctx *tx_aead_ctx,
                          uint8_t *tx_iv,
                          const uint8_t *current_rx_secret,
                          const uint8_t *current_tx_secret,
                          size_t secretlen, void *user_data) {
  ServerConn *sc = (ServerConn *)user_data;
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *md;
  uint8_t key[32], hp_key[32];
  (void)conn;

  cipher_suite_from_ssl(sc->ssl, &aead, &hp, &md);

  /* new_secret = HKDF-Expand-Label(current, "quic ku", "", len) */
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

static int my_version_negotiation(ngtcp2_conn *conn, uint32_t version,
                                   const ngtcp2_cid *client_dcid,
                                   void *user_data) {
  (void)user_data;
  (void)version;
  /* Only QUIC v1 — re-derive initial keys */
  return install_initial_keys(conn, client_dcid,
                               quic_v1_salt, sizeof(quic_v1_salt));
}

/* ------------------------------------------------------------------ */
/*  OpenSSL 3.5 QUIC TLS dispatch callbacks                           */
/* ------------------------------------------------------------------ */

/* Called when TLS has handshake data to send */
static int quic_crypto_send(SSL *ssl, const unsigned char *buf,
                             size_t buf_len, size_t *consumed, void *arg) {
  ServerConn *sc = (ServerConn *)arg;
  (void)ssl;
  if (ngtcp2_conn_submit_crypto_data(sc->qconn, sc->write_level,
                                      buf, buf_len) != 0)
    return 0;
  *consumed = buf_len;
  return 1;
}

/* Pull model: OpenSSL asks for incoming crypto data */
static int quic_crypto_recv_rcd(SSL *ssl, const unsigned char **buf,
                                 size_t *bytes_read, void *arg) {
  ServerConn *sc = (ServerConn *)arg;
  (void)ssl;
  /* Find a level with unconsumed data */
  int i;
  for (i = 0; i < 4; i++) {
    CryptoBuf *cb = &sc->crypto[i];
    if (cb->consumed < cb->len) {
      *buf = cb->buf + cb->consumed;
      *bytes_read = cb->len - cb->consumed;
      return 1;
    }
  }
  *buf = NULL;
  *bytes_read = 0;
  return 1; /* no data — OpenSSL will return SSL_ERROR_WANT_READ */
}

/* Release consumed crypto data */
static int quic_crypto_release_rcd(SSL *ssl, size_t bytes_read, void *arg) {
  ServerConn *sc = (ServerConn *)arg;
  int i;
  (void)ssl;
  for (i = 0; i < 4; i++) {
    CryptoBuf *cb = &sc->crypto[i];
    size_t avail = cb->len - cb->consumed;
    if (avail > 0) {
      if (bytes_read <= avail) {
        cb->consumed += bytes_read;
        /* Compact buffer when fully consumed */
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

/* Called when TLS derives a new traffic secret */
static int quic_yield_secret(SSL *ssl, uint32_t prot_level, int direction,
                              const unsigned char *secret, size_t secret_len,
                              void *arg) {
  ServerConn *sc = (ServerConn *)arg;
  ngtcp2_encryption_level level = prot_to_level(prot_level);
  const EVP_CIPHER *aead;
  const EVP_CIPHER *hp;
  const EVP_MD *md;
  (void)ssl;

  cipher_suite_from_ssl(sc->ssl, &aead, &hp, &md);

  /* Track the current write level for crypto_send */
  if (direction == 1)
    sc->write_level = level;

  /* Set crypto context on first handshake-level secret */
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
    ngtcp2_conn_set_crypto_ctx(sc->qconn, &crypto_ctx);
  }

  return install_key(sc->qconn, level, direction, aead, hp, md,
                      secret, secret_len) == 0 ? 1 : 0;
}

/* Called when peer's transport params arrive */
static int quic_got_transport_params(SSL *ssl, const unsigned char *params,
                                      size_t params_len, void *arg) {
  ServerConn *sc = (ServerConn *)arg;
  (void)ssl;
  return ngtcp2_conn_decode_and_set_remote_transport_params(
           sc->qconn, params, params_len) == 0 ? 1 : 0;
}

/* Called on TLS alert */
static int quic_alert(SSL *ssl, unsigned char alert_code, void *arg) {
  ServerConn *sc = (ServerConn *)arg;
  (void)ssl;
  ngtcp2_conn_set_tls_alert(sc->qconn, alert_code);
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
  ngtcp2_conn_open_uni_stream(sc->qconn, &ctrl, NULL);
  ngtcp2_conn_open_uni_stream(sc->qconn, &qenc, NULL);
  ngtcp2_conn_open_uni_stream(sc->qconn, &qdec, NULL);
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
      nwrite = ngtcp2_conn_writev_stream(sc->qconn, &ps.path, &pi,
                                         buf, sizeof(buf), &ndatalen,
                                         wflags, stream_id,
                                         (ngtcp2_vec *)vec,
                                         (size_t)sveccnt, ts);
    } else {
      nwrite = ngtcp2_conn_write_pkt(sc->qconn, &ps.path, &pi,
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

  /* ngtcp2 callbacks — crypto callbacks are ours, not from ngtcp2_crypto_ossl */
  memset(&q_cb, 0, sizeof(q_cb));
  q_cb.recv_client_initial   = my_recv_client_initial;
  q_cb.recv_crypto_data      = my_recv_crypto_data;
  q_cb.encrypt               = my_encrypt;
  q_cb.decrypt               = my_decrypt;
  q_cb.hp_mask               = my_hp_mask;
  q_cb.update_key            = my_update_key;
  q_cb.delete_crypto_aead_ctx   = my_delete_aead_ctx;
  q_cb.delete_crypto_cipher_ctx = my_delete_cipher_ctx;
  q_cb.get_path_challenge_data  = my_get_path_challenge_data;
  q_cb.version_negotiation      = my_version_negotiation;
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

    rv = ngtcp2_conn_server_new(&sc.qconn, &dcid, &scid, &ps.path,
                                hd.version, &q_cb, &q_settings,
                                &q_params, NULL, &sc);
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_server_new: %s\n",
              ngtcp2_strerror(rv));
      return 1;
    }

    /* Create SSL and register our QUIC TLS dispatch table */
    sc.ssl = SSL_new(ssl_ctx);
    if (!sc.ssl) {
      fprintf(stderr, "SSL_new failed\n");
      return 1;
    }
    SSL_set_accept_state(sc.ssl);
    if (!SSL_set_quic_tls_cbs(sc.ssl, quic_tls_dispatch, &sc)) {
      fprintf(stderr, "SSL_set_quic_tls_cbs failed\n");
      return 1;
    }

    /* Feed the Initial packet */
    memset(&pi, 0, sizeof(pi));
    path = ps.path;
    rv = ngtcp2_conn_read_pkt(sc.qconn, &path, &pi, buf,
                              (size_t)nread, timestamp());
    if (rv != 0) {
      fprintf(stderr, "read_pkt(Initial): %s\n", ngtcp2_strerror(rv));
      ngtcp2_conn_del(sc.qconn);
      SSL_free(sc.ssl);
      sc.qconn = NULL;
      sc.ssl = NULL;
      continue;
    }

    write_to_wire(&sc);
    break;
  }

  if (!sc.qconn) {
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

    expiry = ngtcp2_conn_get_expiry(sc.qconn);
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

        rv = ngtcp2_conn_read_pkt(sc.qconn, &ps.path, &pi, buf,
                                  (size_t)nread, now);
        if (rv != 0) {
          if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING)
            break;
          fprintf(stderr, "read_pkt: %s\n", ngtcp2_strerror(rv));
        }
      }
    }

    rv = ngtcp2_conn_handle_expiry(sc.qconn, now);
    if (rv != 0) {
      fprintf(stderr, "handle_expiry: %s\n", ngtcp2_strerror(rv));
      break;
    }

    if (!sc.h3conn &&
        ngtcp2_conn_get_handshake_completed(sc.qconn)) {
      if (setup_h3(&sc) < 0)
        break;
      printf("Handshake complete, H3 ready\n");
    }

    if (write_to_wire(&sc) < 0)
      break;
  }

  printf("Shutting down\n");
  if (sc.h3conn) nghttp3_conn_del(sc.h3conn);
  if (sc.qconn)  ngtcp2_conn_del(sc.qconn);
  if (sc.ssl)    SSL_free(sc.ssl);
  close(fd);
  SSL_CTX_free(ssl_ctx);
  return 0;
}
