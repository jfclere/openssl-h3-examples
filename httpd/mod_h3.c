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

#include "ossl-nghttp3.h"

module AP_MODULE_DECLARE_DATA http3_module;

static ap_filter_rec_t *h3_net_out_filter_handle;
static ap_filter_rec_t *h3_net_in_filter_handle;
static ap_filter_rec_t *h3_proto_out_filter_handle;
static ap_filter_rec_t *h3_proto_in_filter_handle;

static apr_socket_t *dummy_socket;

static int h3_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    (void)plog;
    (void)ptemp;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "h3_post_config: %d", getpid());
    return OK;
}

/* WE DON'T NEED THAT ONE */
static int h3_hook_process_connection(conn_rec* c)
{
    return OK;
}

static int h3_hook_pre_connection(conn_rec *c, void *csd)
{
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "h3_hook_pre_connection");
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
}
static int h3_hook_fixups(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_hook_fixups");
    return DECLINED;
}

static apr_status_t h3_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket *b;
    apr_status_t rv;
    char buff[2048];
    apr_size_t bufsiz = sizeof(buff);

    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out");
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_METADATA(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_METADATA");
        }
        if (APR_BUCKET_IS_FLUSH(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_EOS(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_EOS");
        }
        if (AP_BUCKET_IS_ERROR(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out AP_BUCKET_IS_ERROR");
        }
        if (AP_BUCKET_IS_EOC(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out AP_BUCKET_IS_EOC");
        }
        if (APR_BUCKET_IS_FILE(b)) {
            h3_conn_ctx_t *ctx = (h3_conn_ctx_t*)ap_get_module_config((f->c)->conn_config, &http3_module);
            if (ctx != NULL) {
                ctx->otherpart = b->data;
                abort();
            } else {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_FILE NO CTX");
            }
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_FILE");
        }
        if (AP_BUCKET_IS_HEADERS(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out AP_BUCKET_IS_HEADERS");
        }
        if (APR_BUCKET_IS_FLUSH(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_IMMORTAL(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out APR_BUCKET_IS_IMMORTAL");
        }
        if (AP_BUCKET_IS_EOR(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out AP_BUCKET_IS_EOR");
        }
        if (AP_BUCKET_IS_RESPONSE(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out AP_BUCKET_IS_RESPONSE");
        } else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out NOT AP_BUCKET_IS_RESPONSE");
        }
    }

    rv = apr_brigade_flatten(bb, buff, &bufsiz);
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out: read %d", bufsiz);
    if (bufsiz != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out: read %.*s", bufsiz, buff);
    } else {
        /* Why I am here??? */
        // abort();
    }
    return rv;
}

static int print_table_entry(void *rec, const char *key, const char *value)
{
    const conn_rec *c = (conn_rec *) rec;
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "h3_filter_out_proto print_table_entry %s %s", key, value);
}

static apr_status_t h3_filter_out_proto(ap_filter_t* f, apr_bucket_brigade* bb)
{
    apr_bucket *b;
    apr_status_t rv;
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto %d", f->r->status);
    
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_METADATA(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_METADATA");
        }
        if (APR_BUCKET_IS_FLUSH(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FLUSH");
        }
        if (APR_BUCKET_IS_EOS(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_EOS");
        }
        if (AP_BUCKET_IS_ERROR(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_ERROR");
        }
        if (AP_BUCKET_IS_EOC(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_EOC");
        }
        if (APR_BUCKET_IS_FILE(b)) {
            h3_conn_ctx_t *ctx = (h3_conn_ctx_t*)ap_get_module_config((f->c)->conn_config, &http3_module);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE %d * %d *", ctx, b);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE %d * %d *", ctx, ctx->otherpart);
            if (ctx != NULL) {
                apr_bucket_setaside(b, ctx->p); // Otherwise the file will be closed.
                ctx->otherpart = b;
            } else {
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE NO CTX");
            }
            /* we will need to read the file and send it */
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto APR_BUCKET_IS_FILE %d * %d *", ctx->otherpart, b);
        }
        if (AP_BUCKET_IS_HEADERS(b)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_HEADERS");
        }
        if (AP_BUCKET_IS_RESPONSE(b)) {
            ap_bucket_response *resp = b->data;
            h3_conn_ctx_t *ctx = (h3_conn_ctx_t*)ap_get_module_config((f->c)->conn_config, &http3_module);
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE");
            if (ctx != NULL)
                ctx->resp = resp;
            else
                ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto AP_BUCKET_IS_RESPONSE NO CTX!!!!");
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
        } else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto NOT AP_BUCKET_IS_RESPONSE");
        }
    }
    rv = ap_pass_brigade(f->next, bb);
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_out_proto %d %d", rv, f->r->status);
    
    // return rv;
    return OK;
}

static apr_status_t h3_filter_in_proto(ap_filter_t* f,
                                     apr_bucket_brigade* bb,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes)
{
    apr_status_t rv;
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto let's do nothing!");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    ap_remove_input_filter(f);
    if (mode == AP_MODE_READBYTES) {
        /* we have nothing to read in fact */
         ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto AP_MODE_READBYTES status %d", f->r->status);
         if (APR_BRIGADE_EMPTY(bb)) {
             apr_bucket *eos;
             eos = apr_bucket_eos_create(f->c->bucket_alloc);
             APR_BRIGADE_INSERT_TAIL(bb, eos);
         }
         // return APR_SUCCESS;
    }
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto OTHER status %d", f->r->status);
    rv = ap_pass_brigade(f->next, bb);
    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto %d %d %d", rv, mode, AP_MODE_READBYTES);
    // ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c, "h3_filter_in_proto");
    return APR_SUCCESS;
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
        if (f->ctx == NULL) {
            apr_bucket *e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            f->ctx = (void *)1;
            return APR_EOF;
        }
        ap_remove_input_filter(f);
    }
    return OK;
}
struct h3_stuff {
    apr_pool_t *pchild;
    server_rec *s;
};

/* Create a connection */
conn_rec *create_connection(apr_pool_t *p, server_rec *s, h3_conn_ctx_t *ctx)
{
    conn_rec *c3;
    apr_pool_t *pool;
    apr_sockaddr_t *fake_from;
    apr_sockaddr_t *fake_local;
    apr_pool_create(&pool, p);
    ctx->p = pool;
    c3 = (conn_rec *) apr_palloc(pool, sizeof(conn_rec));
    //   c2->master                 = c1;
    c3->pool                   = pool;
    c3->base_server            = s;
    c3->master                 = c3; /* We don't have a master! */
    c3->conn_config            = ap_create_conn_config(pool);
    c3->notes                  = apr_table_make(pool, 5);
    c3->input_filters          = NULL;
    c3->output_filters         = NULL;
    c3->keepalives             = 0;
    c3->filter_conn_ctx        = NULL;
    c3->bucket_alloc           = apr_bucket_alloc_create(pool);
    /* prevent mpm_event from making wrong assumptions about this connection,
     * like e.g. using its socket for an async read check. */
    c3->clogging_input_filters = 1;
    c3->log                    = NULL;
    c3->aborted                = 0;

    /* We use the ctx to store the response */
    ap_set_module_config(c3->conn_config, &http3_module, ctx);

    /* We cannot install the master connection socket on the secondary, as
     * modules mess with timeouts/blocking of the socket, with
     * unwanted side effects to the master connection processing.
     * Fortunately, since we never use the secondary socket, we can just install
     * a single, process-wide dummy and everyone is happy.
     */
    // ap_set_module_config(c3->conn_config, &http3_module, dummy_socket);
    /* TODO: these should be unique to this thread */
    // c3->sbh = NULL; /*c1->sbh;*/
    /* Use a fake local_addr and client_addr for the moment */
    apr_sockaddr_info_get(&fake_from, "127.0.0.1", APR_INET, 4242, 0, pool);
    apr_sockaddr_info_get(&fake_local, "127.0.0.1", APR_INET, 4242, 0, pool);
    c3->local_addr = fake_local;
    c3->client_addr = fake_from;


    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c3,
                  "c3 created");
    return c3;
}

/* Process a connection */
/* the create_connection has been called in ossl-nghttp3.c */
apr_status_t process_connection(apr_pool_t *p, server_rec *s, conn_rec *c)
{

    /* We need to process the connection we have created */
    ap_run_process_connection(c);

    return APR_SUCCESS;
}
/* Process a request */
/* the request has been created in ossl-nghttp3.c */
apr_status_t process_request(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "process_request before ap_process_request()");
    ap_process_request(r);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "process_request after ap_process_request()");
    return OK;
}

static void * APR_THREAD_FUNC worker_thread_main(apr_thread_t *thread, void *data)
{
    struct h3_stuff *h3 = (struct h3_stuff *)data;
    apr_pool_t *p = h3->pchild;
    server_rec *s = h3->s;
    unsigned long port = 4433;
    const char *cert_path = "/home/jfclere/CERTS/localhost/newcert.pem";
    const char *key_path = "/home/jfclere/CERTS/localhost/newkey.txt.pem";
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "worker_thread_main");
    server(p, s, port, cert_path, key_path);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "worker_thread_main exited!");
}

/* The child creates a thread that waits on the udp socket and create another thread to process a request */ 
static void h3_child_init(apr_pool_t *pchild, server_rec *s)
{
    apr_status_t rv;
    apr_thread_t *worker_thread;
    struct h3_stuff *h3;

    h3  = apr_palloc(pchild, sizeof(struct h3_stuff));
    h3->pchild = pchild;
    h3->s = s;
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "h3_child_init");
    rv = apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM, APR_PROTO_TCP, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, 
                     "h3_child_init: Failed to create dummy socket: %d", rv);
    }
    rv = ap_thread_create(&worker_thread, NULL, worker_thread_main, (void *)h3, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, 
                     "h3_child_init: Failed to create worker thread: %d", rv);
    }
       
}
static void h3_c1_child_stopping(apr_pool_t *pool, int graceful) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "h3_c1_child_stopping %d", graceful);
}
static int h3_hook_http_create_request(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_hook_http_create_request %d", r->status);
    if (r->main != NULL) {
        return DECLINED;
    }


    /* Add the filter for the response here */
    ap_add_output_filter_handle(h3_proto_out_filter_handle, NULL, r, r->connection);
    ap_add_input_filter_handle(h3_proto_in_filter_handle, NULL, r, r->connection);
    ap_add_input_filter_handle(h3_net_in_filter_handle, NULL, NULL, r->connection);
    ap_add_output_filter_handle(h3_net_out_filter_handle, NULL, NULL, r->connection);

    // return DECLINED;
    return OK;
}
static void h3_filter_last(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_filter_last");
    ap_add_output_filter_handle(h3_proto_out_filter_handle, NULL, r, r->connection); /* HACKING */
}
static void h3_filter_first(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "h3_filter_first");
    ap_add_input_filter_handle(h3_net_in_filter_handle, NULL, r, r->connection); /* HACKING */
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(h3_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(h3_hook_pre_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_process_connection(h3_hook_process_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_create_request(h3_hook_http_create_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_pre_read_request(h3_hook_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(h3_hook_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    // ap_hook_fixups(h3_hook_fixups, NULL, NULL, APR_HOOK_LAST);
    h3_net_out_filter_handle =
        ap_register_output_filter("H3_NET_OUT", h3_filter_out,
                                  NULL, AP_FTYPE_NETWORK);
    h3_net_in_filter_handle =
        ap_register_input_filter("H3_NET_IN", h3_filter_in,
                                  NULL, AP_FTYPE_NETWORK);
    /* trying it was run too late before */
    /* ap_hook_insert_filter(h3_filter_first, NULL, NULL, APR_HOOK_FIRST); */

    h3_proto_out_filter_handle =
    ap_register_output_filter("H3_NET_OUT_PROTO", h3_filter_out_proto,
                               NULL, AP_FTYPE_PROTOCOL);

    h3_proto_in_filter_handle =
    ap_register_input_filter("H3_NET_IN_PROTO", h3_filter_in_proto,
                               NULL, AP_FTYPE_PROTOCOL);
    /* trying it was run too early before */
    ap_hook_insert_filter(h3_filter_last, NULL, NULL, APR_HOOK_LAST);


    ap_hook_child_init(h3_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_stopping(h3_c1_child_stopping, NULL, NULL, APR_HOOK_MIDDLE);
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
