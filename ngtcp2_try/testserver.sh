gcc -o testserver testserver.c \
  -lnghttp3 \
  -lngtcp2 \
  -lngtcp2_crypto_ossl \
  -lssl -lcrypto
