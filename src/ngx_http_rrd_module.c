/*
 * ngx_http_rrd_module.c
 *
 *  Created on: Feb 10, 2011
 *      Author: abonavita
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* The following could be in a header but there is no point in
 * exporting anything. So we keep it and at the beginning to avoid
 * compiler complaints about things being used without being
 * declared.
 */
static char *ngx_http_rrd_post_command(ngx_conf_t *cf, void *data, void *conf);
static ngx_int_t ngx_http_rrd_handler(ngx_http_request_t *r);
static void *ngx_http_rrd_create_loc_conf(ngx_conf_t *conf);
static ngx_int_t ngx_http_rrd_update_database(ngx_http_request_t *r);
static ngx_int_t ngx_http_rrd_show_graph(ngx_http_request_t *r);

/* Module declaration */
static ngx_http_module_t  ngx_http_rrd_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_rrd_create_loc_conf,  /* create location configuration */
    NULL                           /* merge location configuration */
};



/* Structure storing configuration specific to this module. */
typedef struct {
    ngx_str_t db_name; /* Name of rrd database. */
} ngx_http_rrd_module_conf_t;
/* The module configuration creation function. */
static void *ngx_http_rrd_create_loc_conf(ngx_conf_t *conf)
{
    ngx_http_rrd_module_conf_t  *rrd_conf;

    rrd_conf = ngx_pcalloc(conf->pool, sizeof(ngx_http_rrd_module_conf_t));
    if (rrd_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    /*ngx_str_null(&(rrd_conf->db_name));*/
    return rrd_conf;
}

/* Commands offered by this module. */
static ngx_conf_post_t ngx_http_rrd_post = {
        ngx_http_rrd_post_command
};
static ngx_command_t  ngx_http_rrd_commands[] = {

    { ngx_string("rrd"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rrd_module_conf_t, db_name),
      &ngx_http_rrd_post},

      ngx_null_command
};

ngx_module_t  ngx_http_rrd_module = {
    NGX_MODULE_V1,
    &ngx_http_rrd_module_ctx,      /* module context */
    ngx_http_rrd_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/*  Called as post processing the command "rrd". The argument
 * of this command is handled by ngx_conf_set_str_slot, then this
 * function is called. */
static char*
ngx_http_rrd_post_command(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_core_loc_conf_t  *core_loc_conf;

    core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    core_loc_conf->handler = ngx_http_rrd_handler;

    return NGX_CONF_OK;
}

/* The messages (OK, errors) that can be sent by this module. Note that
 * the important thing returned is the status (this is a REST-like API).
 */
static ngx_str_t OK_MSG =
        ngx_string("You make the rock-n-roll go round, Robin.");
#define ERR_BAD_METHOD_MSG_CSTR "rrd module supports only GET and POST verbs."
static ngx_str_t ERR_BAD_METHOD_MSG =
        ngx_string(ERR_BAD_METHOD_MSG_CSTR);
static ngx_str_t ERR_BAD_CONTENT_TYPE_MSG =
        ngx_string("rrd module supports only application/x-www-form-urlencoded \
                content type for now.");
static ngx_str_t IMAGE_PNG = ngx_string("image/png");
static ngx_str_t TEXT_PLAIN = ngx_string("text/plain");
static ngx_str_t WWW_FORM_URLENCODED =
        ngx_string("application/x-www-form-urlencoded");

/*
 * Helper function to create a chain from an array of ngx_str.
 */
ngx_chain_t *ngx_http_rrd_create_chain(ngx_pool_t *pool,
                                  ngx_uint_t sarray_len, ngx_str_t **sarray)
{
    /* Allocate sarray_len chain links */
    ngx_chain_t *out_chain = ngx_pcalloc(pool, sarray_len * sizeof(ngx_chain_t));
    if (NULL == out_chain) {
        return NULL;
    }
    /* Allocate sarray_len buffers */
    ngx_buf_t *buf = ngx_pcalloc(pool, sarray_len * sizeof(ngx_buf_t));
    if (NULL == buf) {
        /* Don't try to free memory, nginx will do it when throwing away the
         * pool.
         */
        return NULL;
    }

    ngx_uint_t i;
    for (i = 0; i<sarray_len - 1; i++){
        out_chain[i].buf = &(buf[i]);
        out_chain[i].next = &out_chain[i+1];
        buf[i].start = buf[i].pos = sarray[i]->data;
        buf[i].end = buf[i].last = sarray[i]->data + sarray[i]->len;
        buf[i].memory = 1;
    }
    /* Last one is slightly different. */
    out_chain[i].buf = &(buf[i]);
    out_chain[i].next = NULL; /* diff */
    buf[i].start = buf[i].pos = sarray[i]->data;
    buf[i].end = buf[i].last = sarray[i]->data + sarray[i]->len;
    buf[i].memory = 1;
    buf[i].last_in_chain = 1;
    buf[i].last_buf = 1;
    return out_chain;
}
/*
 * Helper function to send an array of ngx_str as response to a request.
 */
ngx_uint_t ngx_http_rrd_output_200(ngx_http_request_t *r,
                                  ngx_uint_t sarray_len, ngx_str_t **sarray)
{
	ngx_log_t *log = r->connection->log;
    ngx_chain_t *out_chain = ngx_http_rrd_create_chain(r->pool,
                                                       sarray_len, sarray);
    if (NULL == out_chain) {
        /* nothing else I can do... */
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "memory alloc pb @ngx_http_rrd_body_received");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_uint_t rc;
    r->headers_out.status = NGX_HTTP_OK;
    rc = ngx_http_send_header(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "pb sending header @ngx_http_rrd_body_received");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_output_filter(r, out_chain);
}
/* The actual handler that will process requests. */
ngx_int_t
ngx_http_rrd_handler(ngx_http_request_t *r)
{
    ngx_log_t                 *log;
    log = r->connection->log;


    if (NGX_HTTP_GET == r->method) {
        return ngx_http_rrd_show_graph(r);
    } else if (NGX_HTTP_POST == r->method) {
        return ngx_http_rrd_update_database(r);
    } else if (NGX_HTTP_HEAD == r->method) {
        /*  HEAD is supposed to give you the headers the GET would give you.
         * So, we're providing the content-type.
         */
        r->headers_out.status = NGX_HTTP_OK;
        r->header_only = 1;
        r->headers_out.content_type.data = IMAGE_PNG.data;
        r->headers_out.content_type.len = IMAGE_PNG.len;
        return ngx_http_send_header(r);
    } else {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              ERR_BAD_METHOD_MSG_CSTR);
        ngx_http_complex_value_t cv = {ERR_BAD_METHOD_MSG, NULL, NULL, NULL};

        return ngx_http_send_response(r, NGX_HTTP_NOT_ALLOWED,
                                      &TEXT_PLAIN, &cv);
    }
}
/*
 *  The handler for POST requests (that update the RRD database). The
 * thing here is to remember that when this is called, the body might
 * not be available. So, you need to register an extra callback that
 * will be called when the body is available.
 */
void ngx_http_rrd_body_received(ngx_http_request_t *r);
ngx_int_t ngx_http_rrd_update_database(ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;
    ngx_int_t rc;

    if (r->headers_in.content_type == NULL
            || r->headers_in.content_type->value.data == NULL
            || r->headers_in.content_type->value.len != WWW_FORM_URLENCODED.len
            || ngx_strncasecmp(r->headers_in.content_type->value.data,
                    (u_char *) WWW_FORM_URLENCODED.data,
                    WWW_FORM_URLENCODED.len) != 0)
    {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              (char *) ERR_BAD_CONTENT_TYPE_MSG.data);
        ngx_http_complex_value_t cv = {ERR_BAD_CONTENT_TYPE_MSG, NULL, NULL, NULL};

        return ngx_http_send_response(r, NGX_HTTP_NOT_ALLOWED,
                                      &TEXT_PLAIN, &cv);
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                          "rrd module: Content-type is OK. Proceeding.");

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                   "rrd module: start reading client request body");

    rc = ngx_http_read_client_request_body(r, ngx_http_rrd_body_received);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        /* Don't call me again, but call the body_received. */
        return NGX_DONE;
    }
    if (NGX_OK == rc) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                      "rrd module: client request body already read");
        return rc;
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0,
                   "rrd module: unexpected response code from"
                   "ngx_http_read_client_request_body : %u", rc);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
/*
 *  Called when the full body has been received. Even if the body is sent in
 *  multiple chinks, this will be called only once when everything has
 *  been received.
 */
void ngx_http_rrd_body_received(ngx_http_request_t *r)
{
    ngx_chain_t *body_chain = r->request_body->bufs;
    /* Use the content length as a mw for our value. */
    u_char* copy_idx;
    u_char* rrd_value = copy_idx =
            ngx_palloc(r->pool, r->headers_in.content_length_n);
    u_char* p;
    ngx_int_t looking_for_eq = 1;
    do {
        p = body_chain->buf->start;
        while (p!=body_chain->buf->end && looking_for_eq) {
            if ('=' == *(p++)) {
                looking_for_eq = 0;
            }
        }
        ngx_memcpy(rrd_value, p, body_chain->buf->end - p);
        body_chain = body_chain->next;
    } while (NULL != body_chain);


    ngx_http_rrd_module_conf_t *rrd_conf;
    rrd_conf = ngx_http_get_module_loc_conf(r, ngx_http_rrd_module);

    ngx_str_t* out_str[] = {&OK_MSG, &(rrd_conf->db_name)};
    ngx_http_rrd_output_200(r, 2, out_str);
}

static ngx_int_t ngx_http_rrd_show_graph(ngx_http_request_t *r)
{
    ngx_http_rrd_module_conf_t *rrd_conf;
    rrd_conf = ngx_http_get_module_loc_conf(r, ngx_http_rrd_module);

    ngx_str_t* out_str[] = {&OK_MSG, &(rrd_conf->db_name)};
    return ngx_http_rrd_output_200(r, 2, out_str);
}

