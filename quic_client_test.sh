make quic_client_test
unset LD_LIBRARY_PATH
export LD_LIBRARY_PATH=${HOME}/OPENSSL/lib64:${HOME}/NGHTTP3/lib
#./quic_client_test nghttp2.org 4433
./quic_client_test www.google.com 443
# WORKING ./quic_client_test quic.rocks 4433
#./quic_client_test quic.rocks 4433
# ./quic-client-block quic.rocks 4433
# ./quic_client_test nghttp2.org 4433
# SERVER BROKEN ./quic_client_test quic.aiortc.org 4433
# WORKING ./quic_client_test quic.tech 4433
#gdb ./quic_client_test
#gdb --args ./quic_client_test quic.rocks 4433
#./quic_client_test localhost 4433
#./quic_client_test jfclere.myddns.me 4433
#./quic_client_test localhost 4433
