gcc -Wall -Wextra -o testngserver testngserver.c \
  -lnghttp3 \
  -lngtcp2 \
  -lssl -lcrypto
