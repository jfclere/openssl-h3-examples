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

#include <stdio.h>

static ap_filter_rec_t *h3_net_out_filter_handle;
static ap_filter_rec_t *h3_net_in_filter_handle;
static ap_filter_rec_t *h3_proto_out_filter_handle;

static int h3_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    (void)plog;
    (void)ptemp;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "JFC: %d", getpid());
    return OK;
}

static int h3_hook_process_connection(conn_rec* c)
{
    request_rec *r = NULL;
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "h3_hook_process_connection");
    r = ap_create_request(c);
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "h3_hook_process_connection after ap_create_request()");

    /* populate r with the data we have. */
    r->uri             = "/";
    r->method = "GET";
    r->method_number = M_GET;
    r->header_only = 0;
    r->protocol = "HTTP/1.1";
    r->proto_num = HTTP_VERSION(1, 1);
    r->hostname = NULL;

    /* some headers to try */
    apr_table_setn(r->headers_in, "Host", "localhost"); 
    apr_table_setn(r->headers_in, "User-Agent", "curl/8.11.1"); 
    apr_table_setn(r->headers_in, "Accept", "*/*"); 

    /* Add the filter for the response here */
    ap_add_output_filter_handle(h3_proto_out_filter_handle, NULL, r, r->connection);

    ap_process_request(r);
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "h3_hook_process_connection after ap_process_request()");
    return OK;
}

static int h3_hook_pre_connection(conn_rec *c, void *csd)
{
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "h3_hook_pre_connection");
    ap_add_input_filter_handle(h3_net_in_filter_handle, NULL, NULL, c);
    ap_add_output_filter_handle(h3_net_out_filter_handle, NULL, NULL, c);
    return OK;
}
static int h3_hook_post_read_request(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_hook_ap_hook_post_read_request");
    return OK;
}
static void h3_hook_pre_read_request(request_rec *r, conn_rec *c)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_hook_ap_hook_pre_read_request");
    ap_add_output_filter_handle(h3_proto_out_filter_handle, NULL, r, r->connection);
}
static int h3_hook_fixups(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_hook_fixups");
    return DECLINED;
}

static apr_status_t h3_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    int rv;
    char buff[2048];
    apr_size_t bufsiz = sizeof(buff);

    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out");
    rv = apr_brigade_flatten(bb, buff, &bufsiz);
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out: read %d", bufsiz);
    if (bufsiz != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out: read %.*s", bufsiz, buff);
    }
    return rv;
}

static int print_table_entry(void *rec, const char *key, const char *value)
{
    const conn_rec *c = (conn_rec *) rec;
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "print_table_entry %s %s", key, value);
}

static apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket *b;
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto");
    
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b)) {
        if (AP_BUCKET_IS_RESPONSE(b)) {
            ap_bucket_response *resp = b->data;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE");
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto %d", resp->status);
            if (resp->reason != NULL) {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto %s", resp->reason);
            }
            if (resp->headers != NULL) {
                apr_table_do(print_table_entry, (void *) f->c, resp->headers, NULL);
            }
            if (resp->notes != NULL) {
                apr_table_do(print_table_entry, (void *) f->c, resp->notes, NULL);
            }
        } 
    }
    return ap_pass_brigade(f->next, bb);
}

static apr_status_t h3_filter_in(ap_filter_t *f,
                                     apr_bucket_brigade *bb,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in mode %d", mode);
    if (mode == AP_MODE_READBYTES) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in AP_MODE_READBYTES");
        ap_remove_input_filter(f);
    }
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(h3_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(h3_hook_pre_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_process_connection(h3_hook_process_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_pre_read_request(h3_hook_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(h3_hook_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(h3_hook_fixups, NULL, NULL, APR_HOOK_LAST);
    h3_net_out_filter_handle =
        ap_register_output_filter("H3_NET_OUT", h3_filter_out,
                                  NULL, AP_FTYPE_NETWORK);
    h3_net_in_filter_handle =
        ap_register_input_filter("H3_NET_IN", h3_filter_in,
                                  NULL, AP_FTYPE_NETWORK);
    h3_proto_out_filter_handle =
    ap_register_output_filter("H3_NET_OUT_PROTO", h3_filter_out_proto,
                               NULL, AP_FTYPE_PROTOCOL);
#ifdef AP_HAS_RESPONSE_BUCKETS
#error Not supported for the moment.
#endif

}

AP_DECLARE_MODULE(h3) = {
    STANDARD20_MODULE_STUFF,
    NULL,               /* create per-directory config structure */
    NULL,               /* merge per-directory config structures */
    NULL,               /* create per-server config structure */
    NULL,               /* merge per-server config structures */
    NULL,               /* command apr_table_t */
    register_hooks,     /* register hooks */
    AP_MODULE_FLAG_NONE /* flags */
};
