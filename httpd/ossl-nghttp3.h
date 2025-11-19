
/*
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <nghttp3/nghttp3.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"
#endif
#include "scoreboard.h"
#include "mpm_common.h"

#include "apr_strings.h"


struct h3_conn_ctx_t {
    ap_bucket_response *resp; /* Header part of the response */
    apr_bucket *otherpart;    /* file bucket or something the like */
    apr_pool_t *p;            /* a pool */
    server_rec *s;            /* mostly for log */
};
typedef struct h3_conn_ctx_t h3_conn_ctx_t;

struct h3_nvs_t {
    nghttp3_nv *resp;
    size_t cur_nv;
    size_t max_nv;
    apr_pool_t *p;
    server_rec *s;
};
typedef struct h3_nvs_t h3_nvs_t;

/* run a h3 server logic using openssl calls */
int server(apr_pool_t *p, server_rec *s, unsigned long port, const char *cert_path, const char *key_path);
/* process a request, using a internal connection */
apr_status_t process_connection(apr_pool_t *p, server_rec *s, h3_conn_ctx_t *ctx);
