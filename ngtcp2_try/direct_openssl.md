# Integrating `ngtcp2` Directly with OpenSSL (Without `libngtcp2_crypto_ossl`)

This guide explains how to use **`libngtcp2`** (the QUIC transport engine) directly with **OpenSSL 3.5+** while bypassing the helper bridge library (`libngtcp2_crypto_ossl`). The working implementation is in `testngserver.c`.

## Build

```sh
gcc -Wall -Wextra -o testngserver testngserver.c \
  -lnghttp3 \
  -lngtcp2 \
  -lssl -lcrypto
```

No `-lngtcp2_crypto_ossl` required.

---

## 1. Overview

`libngtcp2` is a QUIC state machine with **no built-in cryptographic routines**. It relies on callbacks for:

1. **AEAD Packet Encryption & Decryption** (`encrypt`, `decrypt`)
2. **QUIC Header Protection Masking** (`hp_mask`)
3. **TLS 1.3 Handshake & Secret Derivation** (`recv_crypto_data`)
4. **Key lifecycle** (`delete_crypto_aead_ctx`, `delete_crypto_cipher_ctx`, `update_key`)

The standard helper library `libngtcp2_crypto_ossl` implements these callbacks on top of OpenSSL. This guide shows how to implement them yourself using OpenSSL's EVP APIs and the OpenSSL 3.5 `SSL_set_quic_tls_cbs` OSSL_DISPATCH API.

---

## 2. Architecture & Data Flow

```
  curl (QUIC client)
       |
       | UDP datagrams
       v
  ngtcp2 (QUIC state machine)
       |
       |-- encrypt/decrypt/hp_mask callbacks --> our EVP code
       |-- recv_crypto_data callback ----------> our TLS glue
       |                                            |
       |                                            v
       |                                    OpenSSL SSL object
       |                                    (SSL_set_quic_tls_cbs)
       |                                            |
       |                                            +-- crypto_send -------> ngtcp2_conn_submit_crypto_data
       |                                            +-- crypto_recv_rcd ---> pull from CryptoBuf
       |                                            +-- yield_secret ------> install_key (per level)
       |                                            +-- got_transport_params -> ngtcp2_conn_decode_..._transport_params
       |                                            +-- alert -------------> ngtcp2_conn_set_tls_alert
       |
       +-- stream callbacks --> nghttp3 (HTTP/3)
```

---

## 3. Key Data Structures

### AEAD and HP Key Storage

OpenSSL 3.5's `EVP_CIPHER_CTX` cannot be reused across AEAD or ECB operations — you must create a fresh context per encrypt/decrypt/hp_mask call. Store the key material and create a temporary `EVP_CIPHER_CTX` each time:

```c
typedef struct {
  const EVP_CIPHER *cipher;
  uint8_t key[32];
  size_t keylen;
  int enc;         /* 1 = encrypt, 0 = decrypt */
} AeadKey;         /* stored in ngtcp2_crypto_aead_ctx.native_handle */

typedef struct {
  const EVP_CIPHER *cipher;
  uint8_t key[32];
  size_t keylen;
} HpKey;           /* stored in ngtcp2_crypto_cipher_ctx.native_handle */
```

### Per-Level Crypto Buffer (Pull Model)

OpenSSL 3.5's QUIC TLS API uses a **pull model** for incoming crypto data. The `crypto_recv_rcd` callback is called by OpenSSL to ask for data, not push it. Buffer incoming TLS handshake data per encryption level:

```c
typedef struct {
  uint8_t buf[65536];
  size_t len;
  size_t consumed;
} CryptoBuf;
```

The `ServerConn` holds `CryptoBuf crypto[4]` indexed by `ngtcp2_encryption_level` (INITIAL=0, HANDSHAKE=1, 1RTT=2, 0RTT=3).

---

## 4. OpenSSL 3.5 QUIC TLS Dispatch Callbacks

Register six callbacks via `SSL_set_quic_tls_cbs(ssl, dispatch_table, arg)`:

| OSSL_DISPATCH ID | Callback | Purpose |
|---|---|---|
| `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND` | `crypto_send` | OpenSSL has TLS handshake bytes to send |
| `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD` | `crypto_recv_rcd` | OpenSSL pulls incoming crypto data |
| `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD` | `crypto_release_rcd` | OpenSSL releases consumed crypto data |
| `OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET` | `yield_secret` | New traffic secret derived |
| `OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS` | `got_transport_params` | Peer's transport params received |
| `OSSL_FUNC_SSL_QUIC_TLS_ALERT` | `alert` | TLS alert generated |

### Critical: `crypto_recv_rcd` Return Value

When no data is available, return **1** with `*bytes_read = 0`. Returning **0** is treated as a fatal error by OpenSSL.

```c
static int quic_crypto_recv_rcd(SSL *ssl, const unsigned char **buf,
                                 size_t *bytes_read, void *arg) {
  ServerConn *sc = (ServerConn *)arg;
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
  return 1;  /* NOT 0 — 0 means fatal error */
}
```

### `yield_secret`: Encryption Level Mapping

OpenSSL protection levels differ from ngtcp2 encryption levels:

| OpenSSL `prot_level` | Value | ngtcp2 level | ngtcp2 value |
|---|---|---|---|
| `OSSL_RECORD_PROTECTION_LEVEL_NONE` | 0 | `NGTCP2_ENCRYPTION_LEVEL_INITIAL` | 0 |
| `OSSL_RECORD_PROTECTION_LEVEL_EARLY` | 1 | `NGTCP2_ENCRYPTION_LEVEL_0RTT` | 3 |
| `OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE` | 2 | `NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE` | 1 |
| `OSSL_RECORD_PROTECTION_LEVEL_APPLICATION` | 3 | `NGTCP2_ENCRYPTION_LEVEL_1RTT` | 2 |

The `yield_secret` callback must:
1. Map the protection level to an ngtcp2 encryption level
2. Detect the cipher suite via `SSL_get_current_cipher`
3. Derive packet keys (key, iv, hp) using HKDF-Expand-Label
4. Install the keys into ngtcp2 using **level-specific** functions
5. Track `write_level` (updated when `direction == 1`) for `crypto_send`
6. On the first handshake write secret, call `ngtcp2_conn_set_crypto_ctx`

### `crypto_send`: Write Level Tracking

The `crypto_send` callback must know the current encryption level to pass to `ngtcp2_conn_submit_crypto_data`. Track it via a `write_level` field in your connection state, updated by `yield_secret` when `direction == 1`.

---

## 5. ngtcp2 Crypto Callbacks

### Key Installation per Level

ngtcp2 has **separate** key installation functions per encryption level. Using the wrong function causes assertion failures:

```c
switch (level) {
case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
  if (direction == 0)
    ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, iv, ivlen, &hp_ctx);
  else
    ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, iv, ivlen, &hp_ctx);
  break;
case NGTCP2_ENCRYPTION_LEVEL_1RTT:
  if (direction == 0)
    ngtcp2_conn_install_rx_key(conn, secret, secretlen, &aead_ctx, iv, ivlen, &hp_ctx);
  else
    ngtcp2_conn_install_tx_key(conn, secret, secretlen, &aead_ctx, iv, ivlen, &hp_ctx);
  break;
case NGTCP2_ENCRYPTION_LEVEL_0RTT:
  ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, iv, ivlen, &hp_ctx);
  break;
}
```

Note: `install_rx_key`/`install_tx_key` (1-RTT) also take the raw secret for later key updates.

### AEAD Encrypt/Decrypt

Create a **fresh `EVP_CIPHER_CTX` per operation** — context reuse is broken in OpenSSL 3.5 for AES-GCM:

```c
static int my_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                      const ngtcp2_crypto_aead_ctx *aead_ctx,
                      const uint8_t *plaintext, size_t plaintextlen,
                      const uint8_t *nonce, size_t noncelen,
                      const uint8_t *aad, size_t aadlen) {
  AeadKey *ak = aead_ctx->native_handle;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, rv = -1;
  if (!ctx) return -1;
  if (!EVP_EncryptInit_ex(ctx, ak->cipher, NULL, ak->key, nonce)) goto out;
  if (aadlen > 0 && !EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen)) goto out;
  if (!EVP_EncryptUpdate(ctx, dest, &len, plaintext, (int)plaintextlen)) goto out;
  if (!EVP_EncryptFinal_ex(ctx, dest + len, &len)) goto out;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            (int)aead->max_overhead, dest + plaintextlen)) goto out;
  rv = 0;
out:
  EVP_CIPHER_CTX_free(ctx);
  return rv;
}
```

### Header Protection Mask

Also requires a fresh `EVP_CIPHER_CTX`. Handles both ECB mode (AES) and stream mode (ChaCha20):

```c
static int my_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                      const ngtcp2_crypto_cipher_ctx *hp_ctx,
                      const uint8_t *sample) {
  HpKey *hk = hp_ctx->native_handle;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, rv = -1, mode;
  if (!ctx) return -1;
  mode = EVP_CIPHER_get_mode((const EVP_CIPHER *)hp->native_handle);
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
```

### Context Cleanup

Since `native_handle` points to a heap-allocated `AeadKey`/`HpKey` (not an `EVP_CIPHER_CTX`), use `free()`:

```c
static void my_delete_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *ctx, void *ud) {
  free(ctx->native_handle);
  ctx->native_handle = NULL;
}
```

---

## 6. HKDF Key Derivation

Implement HKDF using `EVP_MAC("HMAC")` (OpenSSL 3.x API):

- **HKDF-Extract**: `HMAC(salt, ikm)` — used for initial secret derivation
- **HKDF-Expand**: iterative HMAC — used for key material expansion
- **HKDF-Expand-Label**: TLS 1.3 label format `"tls13 " + label` with empty context — used for all QUIC key derivation (`"quic key"`, `"quic iv"`, `"quic hp"`, `"quic ku"`)

### Initial Key Derivation (RFC 9001 Section 5.2)

Initial keys use a fixed salt, AES-128-GCM, and SHA-256 regardless of the negotiated cipher suite:

```c
hkdf_extract(initial_secret, md, quic_v1_salt, dcid);
qhkdf_expand(client_secret, 32, md, initial_secret, "client in", 9);
qhkdf_expand(server_secret, 32, md, initial_secret, "server in", 9);
/* Then derive key/iv/hp from each secret */
```

### Cipher Suite Detection

After the handshake starts, use `SSL_get_current_cipher` to determine the negotiated cipher:

| Cipher Suite ID | AEAD | HP | MD |
|---|---|---|---|
| 0x1301 | AES-128-GCM | AES-128-ECB | SHA-256 |
| 0x1302 | AES-256-GCM | AES-256-ECB | SHA-384 |
| 0x1303 | ChaCha20-Poly1305 | ChaCha20 | SHA-256 |

---

## 7. Transport Parameters

### Pitfall: `SSL_set_quic_tls_transport_params` Keeps a Pointer

`SSL_set_quic_tls_transport_params(ssl, buf, len)` does **not** copy the buffer — it stores a pointer. The buffer must remain valid until the EncryptedExtensions are sent. Store it in the connection struct, not on the stack:

```c
typedef struct {
  /* ... */
  uint8_t tp_buf[512];   /* must outlive recv_client_initial */
  size_t tp_len;
} ServerConn;
```

### Pitfall: `initial_scid` and `version_info` Not Set Yet

When `recv_client_initial` is called (during `ngtcp2_conn_read_pkt`), ngtcp2 has not yet populated `initial_scid` or `version_info.chosen_version` in the local transport params. You must add them manually:

```c
const ngtcp2_transport_params *ltp = ngtcp2_conn_get_local_transport_params(conn);
ngtcp2_transport_params tp_copy = *ltp;
ngtcp2_cid scids[1];
ngtcp2_conn_get_scid(conn, scids);
tp_copy.initial_scid = scids[0];
tp_copy.initial_scid_present = 1;
if (tp_copy.version_info.chosen_version == 0)
  tp_copy.version_info.chosen_version = 1;  /* QUIC v1 */
ngtcp2_transport_params_encode(sc->tp_buf, sizeof(sc->tp_buf), &tp_copy);
```

Without `initial_scid`, the client sends `TRANSPORT_PARAMETER_ERROR` (error code 0x08).

---

## 8. SSL Setup

Use `TLS_server_method()` (not a QUIC-specific method). The QUIC TLS callbacks handle the QUIC integration:

```c
SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
SSL_CTX_use_certificate_chain_file(ctx, cert_file);
SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

SSL *ssl = SSL_new(ctx);
SSL_set_accept_state(ssl);
SSL_set_quic_tls_cbs(ssl, quic_tls_dispatch, &server_conn);
```

---

## 9. Handshake Completion

In `recv_crypto_data`, after each `SSL_do_handshake` call, check if the handshake is finished:

```c
if (SSL_is_init_finished(sc->ssl)) {
  sc->handshake_completed = 1;
  ngtcp2_conn_tls_handshake_completed(conn);
}
```

Then in the event loop, set up HTTP/3 once `ngtcp2_conn_get_handshake_completed` returns true.

