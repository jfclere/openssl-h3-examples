gcc -Wall -Wextra -o testngserver testngserver.c ngopenssl.c \
  -lnghttp3 \
  -lngtcp2 \
  -lssl -lcrypto
